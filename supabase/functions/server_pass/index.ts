import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { accountTag, signPass } from "./pass.ts";

// As `publish_server`: the secret key first, the legacy JWT after it.
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  (Deno.env.get("RIFT_SECRET_KEY") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))!,
);

/** How long a pass is good for: one join, started now. */
const PASS_SECONDS = 300;

/**
 * Vouch for a Rift account to one self-hosted server.
 *
 * A server's admin can make a link that needs a Rift account (030 there), so
 * a ban holds against the account rather than one identity, which costs
 * nothing to make again. The server cannot tell an account from an identity,
 * and never sees anybody's email. So the app asks here, signed in, and gets a
 * pass for that server and the one identity that will join: a tag that is
 * the same for this inbox on that server and different on every other, five
 * minutes of life, and central's Ed25519 signature. The server checks it with
 * central's public key (`_shared/server_pass.ts` in rift-self-host).
 *
 * Nothing is written down: no table, and nothing about the request in the
 * log. Central still sees the request, which is why the app asks only for a
 * link that needs it and its join screen says so.
 *
 * Secrets: `SERVER_PASS_SIGNING_KEY` (Ed25519, PKCS8, base64) and
 * `SERVER_PASS_TAG_SECRET` (base64, 32 bytes or more). Changing the tag
 * secret changes every tag, which lifts every ban made by tag.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  try {
    const user = await caller(req);
    if (!user) return fail("not_authenticated", 401);
    if (!user.email || !user.email_confirmed_at) return fail("email_unconfirmed", 400);

    const body = await req.json().catch(() => ({}));
    const supabaseUrl = String(body.supabase_url ?? "");
    const serverId = String(body.server_id ?? "");
    const publicKey = String(body.public_key ?? "");
    if (!supabaseUrl || !serverId || !publicKey) return fail("missing_fields", 400);
    if (!validFields(supabaseUrl, serverId, publicKey)) return fail("bad_fields", 400);

    const signingKey = await crypto.subtle.importKey(
      "pkcs8",
      fromB64(Deno.env.get("SERVER_PASS_SIGNING_KEY")!),
      "Ed25519",
      false,
      ["sign"],
    );
    const tag = await accountTag(
      fromB64(Deno.env.get("SERVER_PASS_TAG_SECRET")!),
      user.email,
      supabaseUrl,
      serverId,
    );
    const pass = await signPass(signingKey, {
      serverId,
      supabaseUrl,
      publicKey,
      tag,
      exp: Math.floor(Date.now() / 1000) + PASS_SECONDS,
    });
    return json({ pass }, 200);
  } catch (err) {
    // The error only: the request names a server, which is not for the log.
    console.error("[server_pass]", err instanceof Error ? err.name : "error");
    return fail("unexpected_error", 500);
  }
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validFields(supabaseUrl: string, serverId: string, publicKey: string): boolean {
  if (!UUID.test(serverId)) return false;
  try {
    const url = new URL(supabaseUrl);
    // https only, as a listing is: a server is known by its origin, so a pass
    // for an http one is for a server that does not exist.
    if (url.protocol !== "https:") return false;
    return fromB64(publicKey).length === 32;
  } catch {
    return false;
  }
}

function fromB64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** The caller's account, from their verified JWT. */
async function caller(
  req: Request,
): Promise<{ email?: string; email_confirmed_at?: string } | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  return error || !data.user ? null : data.user;
}

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

function fail(message: string, status: number): Response {
  return json({ error: message }, status);
}

import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { safePost } from "./safe_fetch.ts";

// `RIFT_SECRET_KEY` first, the legacy JWT after it. The platform stops
// injecting `SUPABASE_SERVICE_ROLE_KEY` once a project disables its legacy
// API keys, and that key is an HS256 token signed with the project's old JWT
// secret — a secret the dashboard hands out on request. See the README's
// "Bringing up a project from nothing".
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  (Deno.env.get("RIFT_SECRET_KEY") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))!,
);

/**
 * List a self-hosted server in the public directory — once its own server has
 * confirmed that an admin asked.
 *
 * This exists because the RPC it wraps could not answer the only question that
 * matters. Central has never heard of the database being listed and shares no
 * identity with it, so `publish_server` checked that the caller was signed in
 * *here* and nothing more. Every member of a server holds its URL, its id and
 * an invite code, so every member could list it — publicly, with a working
 * join link, under a description of their choosing, and permanently, because
 * the listing is unique per server and the first claimant keeps it.
 *
 * The proof is a round trip. An admin asks their own server for a one-time
 * token (`listing_token` there); this function redeems it against that
 * server's own domain (`verify_listing_token` there) before writing anything.
 * What that establishes is domain control plus administration — which is
 * precisely what a directory entry claims, and the only thing central is in a
 * position to check.
 *
 * The outbound call is the one place central fetches an address a caller
 * chose. Everything that makes that safe is in `safe_fetch.ts`.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  try {
    const body = await req.json();

    // The owner comes from the verified session, never from the body. It is
    // the one argument `publish_server_as` cannot read for itself, and the one
    // a caller must not be able to choose.
    const owner = await callerId(req);
    if (!owner) return fail("not_authenticated", 401);

    const supabaseUrl = String(body.supabase_url ?? "");
    const serverId = String(body.server_id ?? "");
    const token = String(body.listing_token ?? "");

    if (!supabaseUrl || !serverId || !token) {
      return fail("missing_fields", 400);
    }

    // Ask the server itself. A refusal here is the whole gate.
    const verified = await verifyWithServer(supabaseUrl, serverId, token);
    if (verified !== "ok") return fail(verified, 400);

    const { data, error } = await supabase.rpc("publish_server_as", {
      p_owner: owner,
      p_supabase_url: supabaseUrl,
      p_server_id: serverId,
      p_invite_code: body.invite_code,
      p_name: body.name,
      p_description: body.description ?? null,
      p_icon_url: body.icon_url ?? null,
      p_tags: body.tags ?? [],
      p_member_count: body.member_count ?? 0,
      p_is_listed: body.is_listed ?? true,
    });

    // The RPC raises bare identifiers the client already knows how to read.
    if (error) return fail(error.message, 400);
    return json(data, 200);
  } catch (err) {
    console.error("[publish_server]", err);
    return fail("unexpected_error", 500);
  }
});

/**
 * Redeem [token] against the server at [supabaseUrl].
 *
 * Returns `"ok"` or the identifier to refuse with. The server is asked over
 * its *own* domain, which is what ties the listing to whoever controls that
 * name — and the reply is only believed if it names the same server the
 * listing does, so a cooperative third-party server cannot vouch for someone
 * else's id.
 */
async function verifyWithServer(
  supabaseUrl: string,
  serverId: string,
  token: string,
): Promise<string> {
  const result = await safePost(
    supabaseUrl,
    "/functions/v1/verify_listing_token",
    { token },
  );

  if (!result.ok) {
    // Two different refusals, because they mean different things to the
    // person who sees them: one is "that address is not somewhere we will
    // ask", the other is "your server did not answer, try again when it is
    // up". Neither says anything about what is at the address.
    return result.reason === "blocked" ? "server_url_not_allowed" : "server_unreachable";
  }

  try {
    const answer = JSON.parse(result.body);
    if (answer?.success !== true || answer?.data?.verified !== true) {
      return "listing_not_authorised";
    }
    // The server names which server the token was for. If that is not the one
    // being listed, the token was real and for something else.
    if (String(answer.data.server_id) !== serverId) return "listing_not_authorised";
    return "ok";
  } catch {
    return "listing_not_authorised";
  }
}

/** The caller's central account id, from their verified JWT. */
async function callerId(req: Request): Promise<string | null> {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;

  const { data, error } = await supabase.auth.getUser(token);
  return error || !data.user ? null : data.user.id;
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

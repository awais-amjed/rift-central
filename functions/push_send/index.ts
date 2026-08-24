import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

/**
 * The push relay: the one place that holds FCM credentials.
 *
 * FCM registration tokens are scoped to the Firebase project an app was built
 * against, so only the holder of Rift's credentials can wake a Rift install.
 * Self-hosted servers are run by other people and cannot be given those keys,
 * which leaves them unable to reach their own members' phones — so they ask
 * here instead, and this forwards.
 *
 * Two callers, two credentials. Central's own `dm_messages` trigger presents
 * the deployment secret and names a *recipient*, whose devices are looked up
 * here. A self-hosted server presents a relay credential its admin enrolled
 * (migration 010) and supplies the *tokens* it already holds for its own
 * member — central has no idea who that is, and keeps it that way by not
 * asking.
 *
 * What it learns is the point of the design: a device token and a moment. Not
 * who sent the message, not what it said, not which server or channel it was
 * in. The payload is empty — a doorbell, sent as `data` rather than
 * `notification` so it wakes the app's handler instead of being drawn by the
 * system, which is what lets the phone decrypt the message itself and say
 * something true about it.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const PUSH_SECRET = Deno.env.get("PUSH_SECRET")!;
const SERVICE_ACCOUNT = JSON.parse(Deno.env.get("FCM_SERVICE_ACCOUNT")!);
const FCM_URL =
  `https://fcm.googleapis.com/v1/projects/${SERVICE_ACCOUNT.project_id}/messages:send`;

/** Cached until shortly before it expires — one mint per hour, not per push. */
let accessToken: { value: string; expiresAt: number } | null = null;

function b64url(bytes: Uint8Array | string): string {
  const raw = typeof bytes === "string" ? bytes : String.fromCharCode(...bytes);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToPkcs8(pem: string): Uint8Array {
  const body = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

/** Google's service-account flow: a self-signed JWT traded for an access token. */
async function googleAccessToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (accessToken && accessToken.expiresAt > now + 60) return accessToken.value;

  const claims = {
    iss: SERVICE_ACCOUNT.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const input = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${
    b64url(JSON.stringify(claims))
  }`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToPkcs8(SERVICE_ACCOUNT.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(input)),
  );

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${input}.${b64url(signature)}`,
    }),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${await res.text()}`);

  const json = await res.json();
  accessToken = { value: json.access_token, expiresAt: now + json.expires_in };
  return accessToken.value;
}

/** Ring one device. Returns false if FCM says the token is dead. */
async function ring(token: string, bearer: string): Promise<boolean> {
  const res = await fetch(FCM_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${bearer}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: {
        token,
        // `data` only. A `notification` block would be drawn by the system
        // before the app ever saw it, which would mean putting the sender and
        // the message into a payload Google can read — and would leave the
        // notification saying only what the relay was told.
        data: { kind: "wake" },
        android: { priority: "HIGH" },
      },
    }),
  });
  if (res.ok) return true;

  const body = await res.text();
  // Uninstalled, or the token was replaced. Anything else — a network blip, a
  // quota — is not the token's fault and must not delete it.
  return !(res.status === 404 || body.includes("UNREGISTERED") ||
    body.includes("INVALID_ARGUMENT"));
}

/** How many devices one request may ring. A community server, not a fleet. */
const MAX_TOKENS = 1000;

Deno.serve(async (req) => {
  try {
    const secret = req.headers.get("x-push-secret") ?? "";
    const { recipient, relay_id: relayId, tokens: given } = await req.json();

    let tokens: string[] = Array.isArray(given) ? given.filter((t) => typeof t === "string") : [];

    if (relayId) {
      // A self-hosted server forwarding for one of its own members. Verifying
      // and metering the credential is one statement, so two requests that
      // each see room under the day's ceiling cannot both be let through.
      if (tokens.length === 0) return Response.json({ rang: 0 });
      if (tokens.length > MAX_TOKENS) tokens = tokens.slice(0, MAX_TOKENS);
      const { data: allowed, error } = await supabase.rpc("claim_relay_push", {
        p_relay_id: relayId,
        p_secret: secret,
        p_count: tokens.length,
      });
      if (error) return new Response(`db: ${error.message}`, { status: 500 });
      if (allowed !== true) return new Response("forbidden", { status: 403 });
    } else {
      // Central's own trigger, which names an account rather than a device.
      if (secret !== PUSH_SECRET) return new Response("forbidden", { status: 403 });
      if (!recipient) return Response.json({ rang: 0 });
      const { data, error } = await supabase
        .from("device_tokens")
        .select("token")
        .eq("user_id", recipient);
      if (error) return new Response(`db: ${error.message}`, { status: 500 });
      tokens = (data ?? []).map((r: Record<string, string>) => r.token);
    }

    if (tokens.length === 0) return Response.json({ rang: 0 });

    const bearer = await googleAccessToken();
    const results = await Promise.all(tokens.map((t) => ring(t, bearer)));

    const dead = tokens.filter((_, i) => !results[i]);
    // Only central's own registry is ours to clean. A relayed token lives in a
    // database we have no credentials for, and the dead ones there are swept
    // on staleness instead (self-hosted migration 010) — reporting them back
    // would tell us which of a server's members had uninstalled the app.
    if (dead.length > 0 && !relayId) {
      await supabase.from("device_tokens").delete().in("token", dead);
    }
    return Response.json({ rang: tokens.length - dead.length, pruned: dead.length });
  } catch (err) {
    return new Response(`error: ${err}`, { status: 500 });
  }
});

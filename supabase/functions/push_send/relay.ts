/**
 * The push relay, as portable code.
 *
 * This file has **no imports**. Everything it uses — `fetch`, `crypto.subtle`,
 * `btoa`, `Response` — exists in Deno, Node 18+ and Cloudflare Workers alike,
 * so the same source runs on Supabase Edge Functions today and on a VPS,
 * Fly.io or a Worker tomorrow without being rewritten. Only the few lines that
 * read configuration and start a server differ, and those live in the host's
 * own entry point beside it.
 *
 * That is deliberate. The relay's address is written into every self-hosted
 * server's `push_config`, so moving it is not a private decision — it costs
 * every operator a re-enable unless the address is stable. Keeping the *code*
 * portable and the *address* fixed is what makes the hosting choice reversible
 * rather than permanent. See `relay/README.md`.
 *
 * Database access is plain PostgREST over `fetch` rather than the Supabase
 * client, for the same reason: one less dependency to install, bundle and
 * patch on whichever host this lands on.
 */

export interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
}

export interface RelayConfig {
  /** Central's Supabase URL — where the credential and token tables live. */
  supabaseUrl: string;
  /** Service role key. Reaches `push_relays` and `device_tokens`, which no session can. */
  serviceRoleKey: string;
  /** The secret central's own `dm_messages` trigger presents. */
  pushSecret: string;
  /** Google service account holding the FCM credentials. */
  serviceAccount: ServiceAccount;
}

/** How many devices one request may ring. A community server, not a fleet. */
const MAX_TOKENS = 1000;

function b64url(bytes: Uint8Array | string): string {
  const raw = typeof bytes === "string" ? bytes : String.fromCharCode(...bytes);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToPkcs8(pem: string): Uint8Array {
  const body = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

export function createRelay(config: RelayConfig) {
  const fcmUrl =
    `https://fcm.googleapis.com/v1/projects/${config.serviceAccount.project_id}/messages:send`;
  const rest = `${config.supabaseUrl}/rest/v1`;
  const dbHeaders = {
    apikey: config.serviceRoleKey,
    Authorization: `Bearer ${config.serviceRoleKey}`,
    "Content-Type": "application/json",
  };

  /** Cached until shortly before it expires — one mint per hour, not per push. */
  let accessToken: { value: string; expiresAt: number } | null = null;

  /** Google's service-account flow: a self-signed JWT traded for an access token. */
  async function googleAccessToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (accessToken && accessToken.expiresAt > now + 60) return accessToken.value;

    const claims = {
      iss: config.serviceAccount.client_email,
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
      pemToPkcs8(config.serviceAccount.private_key),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        key,
        new TextEncoder().encode(input),
      ),
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
    const res = await fetch(fcmUrl, {
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

  /** Every device registered to one account on this deployment. */
  async function tokensFor(recipient: string): Promise<string[]> {
    const res = await fetch(
      `${rest}/device_tokens?select=token&user_id=eq.${encodeURIComponent(recipient)}`,
      { headers: dbHeaders },
    );
    if (!res.ok) throw new Error(`db: ${await res.text()}`);
    return (await res.json()).map((row: { token: string }) => row.token);
  }

  /** Verify, meter and spend a relay credential — one statement, so two
   *  forwards that each see room under the day's ceiling cannot both pass. */
  async function claim(relayId: string, secret: string, count: number): Promise<boolean> {
    const res = await fetch(`${rest}/rpc/claim_relay_push`, {
      method: "POST",
      headers: dbHeaders,
      body: JSON.stringify({ p_relay_id: relayId, p_secret: secret, p_count: count }),
    });
    if (!res.ok) throw new Error(`db: ${await res.text()}`);
    return await res.json() === true;
  }

  async function forget(tokens: string[]): Promise<void> {
    // One at a time rather than an `in.(…)` filter: dead tokens arrive a few at
    // a time, and an FCM token is full of characters a URL filter would have to
    // be careful with. Clarity is worth more than the round trips here.
    await Promise.all(tokens.map((token) =>
      fetch(`${rest}/device_tokens?token=eq.${encodeURIComponent(token)}`, {
        method: "DELETE",
        headers: dbHeaders,
      })
    ));
  }

  /**
   * Handle one forward request. Web-standard in and out, so every host's entry
   * point is a few lines of adapter around this.
   */
  return async function handle(req: Request): Promise<Response> {
    // A liveness answer, on every host. It is what lets an admin's client
    // check the relay is actually reachable *before* turning push on — the
    // address is compiled into the app, and a DNS record that has not been
    // made yet would otherwise fail silently, one undelivered push at a time.
    if (req.method === "GET") {
      return new Response("ok", {
        headers: { "Content-Type": "text/plain" },
      });
    }
    try {
      const secret = req.headers.get("x-push-secret") ?? "";
      const { recipient, relay_id: relayId, tokens: given } = await req.json();

      let tokens: string[] = Array.isArray(given)
        ? given.filter((t: unknown) => typeof t === "string")
        : [];

      if (relayId) {
        // A self-hosted server forwarding for one of its own members.
        if (tokens.length === 0) return Response.json({ rang: 0 });
        if (tokens.length > MAX_TOKENS) tokens = tokens.slice(0, MAX_TOKENS);
        if (!await claim(relayId, secret, tokens.length)) {
          return new Response("forbidden", { status: 403 });
        }
      } else {
        // Central's own trigger, which names an account rather than a device.
        if (!await sameSecret(secret, config.pushSecret)) {
          return new Response("forbidden", { status: 403 });
        }
        if (!recipient) return Response.json({ rang: 0 });
        tokens = await tokensFor(recipient);
      }

      if (tokens.length === 0) return Response.json({ rang: 0 });

      const bearer = await googleAccessToken();
      const results = await Promise.all(tokens.map((t) => ring(t, bearer)));

      const dead = tokens.filter((_, i) => !results[i]);
      // Only central's own registry is ours to clean. A relayed token lives in
      // a database we have no credentials for, and the dead ones there are
      // swept on staleness instead (self-hosted migration 010) — reporting
      // them back would tell us which of a server's members had uninstalled.
      if (dead.length > 0 && !relayId) await forget(dead);

      return Response.json({
        rang: tokens.length - dead.length,
        pruned: dead.length,
      });
    } catch (err) {
      return new Response(`error: ${err}`, { status: 500 });
    }
  };
}

/**
 * Compare two secrets in time that does not depend on where they differ.
 *
 * The same shape `sweep_dm_attachments` and `create_server` use, and for the
 * same reason — this one was a plain `!==`, which is the one secret comparison
 * in either repository that told you how much of it you had right. Digesting
 * first means the loop runs over a fixed 32 bytes whatever lengths went in, so
 * the length does not leak either.
 *
 * No imports, like the rest of this file: `crypto.subtle` is in Deno, Node 18+
 * and Workers alike.
 */
async function sameSecret(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  const left = new Uint8Array(x);
  const right = new Uint8Array(y);
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

/**
 * Configuration from the environment, spelled once for every host.
 *
 * Deno, Node and Workers each expose the environment differently; this reads
 * whichever is present so an entry point never has to care.
 */
export function relayConfigFromEnv(
  env: Record<string, string | undefined> = {},
): RelayConfig {
  const globals = globalThis as {
    Deno?: { env: { get(k: string): string | undefined } };
    process?: { env: Record<string, string | undefined> };
  };
  const read = (key: string): string => {
    const value = env[key] ?? globals.Deno?.env.get(key) ??
      globals.process?.env[key];
    if (!value) throw new Error(`missing configuration: ${key}`);
    return value;
  };
  return {
    supabaseUrl: read("SUPABASE_URL"),
    serviceRoleKey: read("SUPABASE_SERVICE_ROLE_KEY"),
    pushSecret: read("PUSH_SECRET"),
    serviceAccount: JSON.parse(read("FCM_SERVICE_ACCOUNT")),
  };
}

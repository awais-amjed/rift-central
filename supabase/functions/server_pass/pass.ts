/**
 * What `server_pass` signs: see `index.ts` for why it exists.
 *
 * The format is shared with rift-self-host's `_shared/server_pass.ts`, which
 * checks it: `b64url(payload).b64url(signature)`, the payload UTF-8 JSON,
 * the Ed25519 signature over exactly those bytes.
 */

const GMAIL = new Set(["gmail.com", "googlemail.com"]);

/**
 * One inbox, one address: lower-cased, a `+suffix` dropped on every domain,
 * and Gmail's dots dropped (Gmail ignores them, and `googlemail.com` is the
 * same mailbox). Without it one Gmail inbox could make endless accounts, each
 * with a fresh tag, and a ban would hold against none of them.
 */
export function normaliseEmail(email: string): string {
  const trimmed = email.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at < 0) return trimmed;
  let local = trimmed.slice(0, at);
  let domain = trimmed.slice(at + 1);
  const plus = local.indexOf("+");
  if (plus >= 0) local = local.slice(0, plus);
  if (GMAIL.has(domain)) {
    local = local.replace(/\./g, "");
    domain = "gmail.com";
  }
  return `${local}@${domain}`;
}

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_")
    .replace(/=+$/, "");

/**
 * The account's tag on one server: the same every time that inbox joins that
 * server, different on every other server, and no way back to the email
 * without [secret]. The server is its origin and its id — both, so two
 * servers that share an id (one copied the other's on purpose) still see
 * different tags.
 */
export async function accountTag(
  secret: Uint8Array<ArrayBuffer>,
  email: string,
  supabaseUrl: string,
  serverId: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = `${normaliseEmail(email)}\n${new URL(supabaseUrl).origin}\n${serverId}`;
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64url(new Uint8Array(mac));
}

/** The pass for one identity joining one server. */
export async function signPass(
  key: CryptoKey,
  p: { serverId: string; supabaseUrl: string; publicKey: string; tag: string; exp: number },
): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify({
    v: 1,
    server_id: p.serverId,
    supabase_url: p.supabaseUrl,
    public_key: p.publicKey,
    tag: p.tag,
    exp: p.exp,
  }));
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key, payload));
  return `${b64url(payload)}.${b64url(signature)}`;
}

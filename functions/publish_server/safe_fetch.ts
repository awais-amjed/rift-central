/**
 * Fetching a URL somebody else chose, without becoming their proxy.
 *
 * This is the only place in Rift where central makes a request to an address a
 * caller supplied, and that is exactly the shape of a server-side request
 * forgery. Central runs inside a cloud network: an unguarded fetch of
 * `http://169.254.169.254/` hands back the instance's IAM credentials, and one
 * of `http://10.0.0.5:6379` reaches something that is only unexposed because
 * nothing outside was supposed to be able to ask.
 *
 * Six rules, and each closes a specific way in:
 *
 *   1. **https only.** Plain http to a link-local address is the whole
 *      metadata attack, and a self-hosted Rift server must be on https anyway
 *      — Android refuses cleartext, so an http server has no phone clients.
 *   2. **We own the path.** The caller names a host; the path is ours. There
 *      is no way to point this at an arbitrary endpoint.
 *   3. **Resolve first, then check the address.** A hostname is not a
 *      destination — `evil.test` can resolve to 127.0.0.1. Every resolved
 *      address is checked against the private ranges before anything connects.
 *   4. **Connect to the address we checked.** Resolving twice invites a DNS
 *      rebind: pass on the first answer, and the check applies to the request
 *      actually made.
 *   5. **No redirects.** A 302 to the metadata service defeats every rule
 *      above it.
 *   6. **One flat error.** Timing and error text are an oracle for what is
 *      listening on a network the caller cannot otherwise see.
 */

/** What a guarded fetch can come back with. */
export type SafeFetchResult =
  | { ok: true; status: number; body: string }
  | { ok: false; reason: "blocked" | "unreachable" };

/** How long to wait. Short: this is a health-check-sized question. */
const TIMEOUT_MS = 5000;

/** How much of a response to read. A listing answer is a few dozen bytes. */
const MAX_BYTES = 16 * 1024;

/**
 * Address ranges that must never be a destination.
 *
 * Loopback and link-local are the dangerous ones — link-local is where cloud
 * metadata lives. The private ranges are here because central has no business
 * reaching anything inside its own network on a caller's say-so.
 */
function isBlockedIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return true; // unparseable is not something to connect to
  }
  const [a, b] = parts;

  return (
    a === 0 || // "this network"
    a === 10 || // private
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local — cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) || // private
    (a === 192 && b === 0) || // IETF protocol assignments
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast and reserved
  );
}

/** The same question for IPv6, including the mapped-IPv4 form. */
function isBlockedIPv6(address: string): boolean {
  const lower = address.toLowerCase();

  // ::ffff:127.0.0.1 and friends are IPv4 wearing a hat.
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIPv4(mapped[1]);

  return (
    lower === "::" ||
    lower === "::1" || // loopback
    lower.startsWith("fe80") || // link-local
    lower.startsWith("fc") || lower.startsWith("fd") || // unique local
    lower.startsWith("ff") // multicast
  );
}

/** True if [address] is somewhere central must not be pointed. */
export function isBlockedAddress(address: string): boolean {
  return address.includes(":") ? isBlockedIPv6(address) : isBlockedIPv4(address);
}

/**
 * Whether [url] is a shape we will consider at all.
 *
 * Separate from the address check because it can be answered without a
 * network, which makes it testable and makes the common refusal instant.
 */
export function parseTarget(url: string): URL | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  if (parsed.protocol !== "https:") return null;
  // Credentials in a URL are a redirect trick and never legitimate here.
  if (parsed.username || parsed.password) return null;
  // A bare IP is not a domain, and the whole point is binding to a domain.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) return null;
  if (parsed.hostname.startsWith("[")) return null; // literal IPv6

  return parsed;
}

/**
 * POST [body] to [path] on [baseUrl], with every rule above applied.
 *
 * [resolve] is injectable so the rules can be tested without DNS.
 */
export async function safePost(
  baseUrl: string,
  path: string,
  body: unknown,
  options: {
    resolve?: (hostname: string) => Promise<string[]>;
    timeoutMs?: number;
  } = {},
): Promise<SafeFetchResult> {
  const target = parseTarget(baseUrl);
  if (target === null) return { ok: false, reason: "blocked" };

  const resolve = options.resolve ?? defaultResolve;
  let addresses: string[];
  try {
    addresses = await resolve(target.hostname);
  } catch {
    return { ok: false, reason: "unreachable" };
  }

  // Every answer, not just the first: a host that resolves to one public and
  // one private address is a rebind waiting to happen.
  if (addresses.length === 0 || addresses.some(isBlockedAddress)) {
    return { ok: false, reason: "blocked" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? TIMEOUT_MS);

  try {
    const response = await fetch(new URL(path, target).toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: controller.signal,
    });

    const text = (await response.text()).slice(0, MAX_BYTES);
    return { ok: true, status: response.status, body: text };
  } catch {
    return { ok: false, reason: "unreachable" };
  } finally {
    clearTimeout(timer);
  }
}

/** Deno's resolver, reduced to the addresses. */
async function defaultResolve(hostname: string): Promise<string[]> {
  const [v4, v6] = await Promise.allSettled([
    Deno.resolveDns(hostname, "A"),
    Deno.resolveDns(hostname, "AAAA"),
  ]);
  return [
    ...(v4.status === "fulfilled" ? v4.value : []),
    ...(v6.status === "fulfilled" ? v6.value : []),
  ];
}

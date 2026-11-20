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
 *      actually made. So no `fetch`, which looks the name up again: a socket
 *      to the checked address (`Deno.connect`), TLS on it for the hostname
 *      (`Deno.startTls`, which checks the certificate against the name), and
 *      one HTTP/1.1 request written by hand.
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

/**
 * How much of a response body to keep. A listing answer is a few dozen bytes.
 * Read as it arrives and no further, so a server that sends forever, or a
 * compressed bomb, costs this much and no more; and nothing is decompressed,
 * since the request asks for none.
 */
const MAX_BYTES = 16 * 1024;

/** The status line and headers, which come before the body. */
const MAX_HEAD_BYTES = 8 * 1024;

/** A byte stream to the address that was checked, speaking TLS for [hostname]. */
export interface Conn {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  close(): void;
}

export type Connect = (address: string, port: number, hostname: string) => Promise<Conn>;

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
    connect?: Connect;
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

  const url = new URL(path, target);
  const port = Number(target.port) || 443;
  const payload = new TextEncoder().encode(JSON.stringify(body));
  const head = new TextEncoder().encode(
    `POST ${url.pathname}${url.search} HTTP/1.1\r\n` +
      `Host: ${target.host}\r\n` +
      "Content-Type: application/json\r\n" +
      `Content-Length: ${payload.length}\r\n` +
      "Accept-Encoding: identity\r\n" +
      "Connection: close\r\n\r\n",
  );

  let conn: Conn | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  // A socket cannot be aborted like a fetch. The deadline wins the race
  // whatever the socket is doing, and closing it ends any read still waiting.
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timed out")), options.timeoutMs ?? TIMEOUT_MS);
  });
  const exchange = async () => {
    conn = await (options.connect ?? defaultConnect)(addresses[0], port, target.hostname);
    const writer = conn.writable.getWriter();
    await writer.write(concat([head, payload]));
    writer.releaseLock();
    // Not followed, whatever it says: a 3xx comes back as its status (rule 5).
    return await readResponse(conn.readable);
  };

  try {
    const response = await Promise.race([exchange(), deadline]);
    return { ok: true, status: response.status, body: response.body };
  } catch {
    return { ok: false, reason: "unreachable" };
  } finally {
    clearTimeout(timer);
    try {
      (conn as Conn | null)?.close();
    } catch { /* already closed */ }
  }
}

/** A TCP socket to [address], with TLS for [hostname] on it. */
async function defaultConnect(address: string, port: number, hostname: string): Promise<Conn> {
  const tcp = await Deno.connect({ hostname: address, port });
  try {
    return await Deno.startTls(tcp, { hostname });
  } catch (err) {
    tcp.close();
    throw err;
  }
}

/**
 * One HTTP/1.1 response from [readable]: its status and up to [MAX_BYTES] of
 * its body, de-chunked. Stops reading at the end of the body, at the end of
 * the stream, or once it has as much as it will keep.
 */
export async function readResponse(
  readable: ReadableStream<Uint8Array>,
): Promise<{ status: number; body: string }> {
  const reader = readable.getReader();
  let buffer: Uint8Array = new Uint8Array(0);
  let headEnd = -1;
  let status = 0;
  let length: number | null = null;
  let chunked = false;

  try {
    while (true) {
      if (headEnd < 0) {
        headEnd = indexOf(buffer, CRLFCRLF);
        if (headEnd < 0 && buffer.length > MAX_HEAD_BYTES) throw new Error("head too long");
        if (headEnd >= 0) {
          const lines = new TextDecoder().decode(buffer.subarray(0, headEnd)).split("\r\n");
          const statusLine = lines[0].match(/^HTTP\/1\.[01] (\d{3})/);
          if (!statusLine) throw new Error("not HTTP");
          status = Number(statusLine[1]);
          for (const line of lines.slice(1)) {
            const colon = line.indexOf(":");
            if (colon < 0) continue;
            const name = line.slice(0, colon).trim().toLowerCase();
            const value = line.slice(colon + 1).trim().toLowerCase();
            if (name === "transfer-encoding") chunked = value.includes("chunked");
            if (name === "content-length" && /^\d+$/.test(value)) length = Number(value);
          }
        }
      }
      if (headEnd >= 0) {
        const raw = buffer.subarray(headEnd + 4);
        if (chunked) {
          const decoded = dechunk(raw);
          if (decoded.done || decoded.body.length >= MAX_BYTES) return finish(status, decoded.body);
        } else if (length !== null) {
          if (raw.length >= Math.min(length, MAX_BYTES)) return finish(status, raw.subarray(0, length));
        } else if (raw.length >= MAX_BYTES) {
          return finish(status, raw);
        }
      }

      const { value, done } = await reader.read();
      if (done) {
        if (headEnd < 0) throw new Error("no response");
        const raw = buffer.subarray(headEnd + 4);
        return finish(status, chunked ? dechunk(raw).body : raw);
      }
      buffer = concat([buffer, value]);
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

const CRLFCRLF = new Uint8Array([13, 10, 13, 10]);

function finish(status: number, body: Uint8Array): { status: number; body: string } {
  return { status, body: new TextDecoder().decode(body.subarray(0, MAX_BYTES)) };
}

/** As much of a chunked body as has arrived, and whether its last chunk has. */
function dechunk(raw: Uint8Array): { body: Uint8Array; done: boolean } {
  const parts: Uint8Array[] = [];
  let at = 0;
  let size = 0;
  while (at < raw.length) {
    const lineEnd = indexOf(raw.subarray(at), new Uint8Array([13, 10]));
    if (lineEnd < 0) break;
    const sizeText = new TextDecoder().decode(raw.subarray(at, at + lineEnd)).split(";")[0].trim();
    if (!/^[0-9a-fA-F]+$/.test(sizeText)) break;
    const chunk = parseInt(sizeText, 16);
    if (chunk === 0) return { body: concat(parts), done: true };
    const from = at + lineEnd + 2;
    parts.push(raw.subarray(from, Math.min(from + chunk, raw.length)));
    size += chunk;
    if (from + chunk + 2 > raw.length || size >= MAX_BYTES) break;
    at = from + chunk + 2;
  }
  return { body: concat(parts), done: false };
}

function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
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

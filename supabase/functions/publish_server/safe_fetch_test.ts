import { assert, assertEquals } from "jsr:@std/assert@1";
import { type Conn, isBlockedAddress, parseTarget, safePost } from "./safe_fetch.ts";

/**
 * The guard on the one request central makes to an address a caller chose.
 *
 * Every case here is a way to turn central into somebody's proxy, and the
 * expensive one is the cloud metadata service: an unguarded fetch of
 * 169.254.169.254 returns the instance's IAM credentials to whoever asked for
 * it.
 */

Deno.test("the metadata address is refused", () => {
  // The one that matters most. 169.254.0.0/16 is link-local, and on AWS and
  // GCP it serves credentials to anything inside the instance.
  assert(isBlockedAddress("169.254.169.254"));
  assert(isBlockedAddress("169.254.0.1"));
});

Deno.test("loopback and private ranges are refused", () => {
  for (const address of [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.5",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "0.0.0.0",
    "100.64.0.1", // CGNAT
    "224.0.0.1", // multicast
  ]) {
    assert(isBlockedAddress(address), `$${address} should be blocked`);
  }
});

Deno.test("ordinary public addresses are allowed", () => {
  for (const address of ["1.1.1.1", "8.8.8.8", "172.15.0.1", "172.32.0.1", "93.184.216.34"]) {
    assertEquals(isBlockedAddress(address), false, `${address} should be allowed`);
  }
});

Deno.test("IPv6 loopback and link-local are refused", () => {
  for (const address of ["::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1"]) {
    assert(isBlockedAddress(address), `${address} should be blocked`);
  }
  assertEquals(isBlockedAddress("2606:4700:4700::1111"), false);
});

Deno.test("IPv4 wearing an IPv6 hat is still IPv4", () => {
  // ::ffff:127.0.0.1 reaches loopback. Checking the textual form only would
  // wave it straight through.
  assert(isBlockedAddress("::ffff:127.0.0.1"));
  assert(isBlockedAddress("::ffff:169.254.169.254"));
  assertEquals(isBlockedAddress("::ffff:8.8.8.8"), false);
});

Deno.test("anything unparseable is treated as blocked", () => {
  // Failing open on an address we could not read would be the one mistake
  // worth making twice.
  assert(isBlockedAddress("not-an-address"));
  assert(isBlockedAddress("999.1.1.1"));
  assert(isBlockedAddress(""));
});

Deno.test("only https is a target", () => {
  assertEquals(parseTarget("http://chat.example.com"), null);
  assertEquals(parseTarget("file:///etc/passwd"), null);
  assertEquals(parseTarget("gopher://chat.example.com"), null);
  assert(parseTarget("https://chat.example.com") !== null);
});

Deno.test("a bare IP is not a domain", () => {
  // The point of the round trip is binding a listing to a *name* somebody
  // controls, and an address bypasses the DNS check entirely.
  assertEquals(parseTarget("https://93.184.216.34"), null);
  assertEquals(parseTarget("https://[::1]"), null);
});

Deno.test("credentials in a URL are refused", () => {
  assertEquals(parseTarget("https://user:pass@chat.example.com"), null);
});

Deno.test("nonsense is refused rather than thrown over", () => {
  assertEquals(parseTarget(""), null);
  assertEquals(parseTarget("chat.example.com"), null);
});

Deno.test("a host resolving to a private address is refused", async () => {
  // DNS is the hole that a URL check alone does not close: the name looks
  // ordinary and the answer is loopback.
  const result = await safePost("https://evil.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["127.0.0.1"]),
  });
  assertEquals(result, { ok: false, reason: "blocked" });
});

Deno.test("one private answer among public ones is still refused", async () => {
  // A rebind candidate: return both, and whichever the connection picks may
  // not be the one that was checked.
  const result = await safePost("https://evil.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34", "169.254.169.254"]),
  });
  assertEquals(result, { ok: false, reason: "blocked" });
});

Deno.test("a name that resolves to nothing is refused", async () => {
  const result = await safePost("https://nowhere.example.com", "/x", {}, {
    resolve: () => Promise.resolve([]),
  });
  assertEquals(result, { ok: false, reason: "blocked" });
});

Deno.test("a resolver that fails reads as unreachable, not as allowed", async () => {
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.reject(new Error("SERVFAIL")),
  });
  assertEquals(result, { ok: false, reason: "unreachable" });
});

Deno.test("an http URL never reaches the resolver at all", async () => {
  let asked = false;
  const result = await safePost("http://chat.example.com", "/x", {}, {
    resolve: () => {
      asked = true;
      return Promise.resolve(["93.184.216.34"]);
    },
  });
  assertEquals(result, { ok: false, reason: "blocked" });
  assertEquals(asked, false, "the scheme is refused before anything is resolved");
});

// ── The connection itself ───────────────────────────────────
// A stand-in socket: records what was written and answers with [chunks],
// then with [forever] bytes for as long as anybody reads.

function fakeConn(chunks: string[], forever = 0) {
  const written: Uint8Array[] = [];
  let reads = 0;
  const encoder = new TextEncoder();
  const conn: Conn & { written: () => string; reads: () => number } = {
    readable: new ReadableStream<Uint8Array>({
      pull(controller) {
        reads++;
        const next = chunks.shift();
        if (next !== undefined) controller.enqueue(encoder.encode(next));
        else if (forever > 0) controller.enqueue(new Uint8Array(forever).fill(65));
        else controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>({ write: (chunk) => void written.push(chunk) }),
    close() {},
    written: () => written.map((c) => new TextDecoder().decode(c)).join(""),
    reads: () => reads,
  };
  return conn;
}

Deno.test("the connection goes to the address that was checked, TLS for the name", async () => {
  const conn = fakeConn(['HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}']);
  let to: [string, number, string] | null = null;
  const result = await safePost("https://chat.example.com", "/functions/v1/x?a=1", { t: 1 }, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: (address, port, hostname) => {
      to = [address, port, hostname];
      return Promise.resolve(conn);
    },
  });
  assertEquals(to, ["93.184.216.34", 443, "chat.example.com"]);
  assertEquals(result, { ok: true, status: 200, body: "{}" });
  const request = conn.written();
  assert(request.startsWith("POST /functions/v1/x?a=1 HTTP/1.1\r\n"), request);
  assert(request.includes("\r\nHost: chat.example.com\r\n"), request);
  assert(request.endsWith('\r\n\r\n{"t":1}'), request);
});

Deno.test("a chunked answer is put back together", async () => {
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () =>
      Promise.resolve(fakeConn([
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        '5\r\n{"suc\r\n',
        'b\r\ncess":true}\r\n0\r\n\r\n',
      ])),
  });
  assertEquals(result, { ok: true, status: 200, body: '{"success":true}' });
});

Deno.test("a redirect is an answer, not somewhere to go", async () => {
  let connects = 0;
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () => {
      connects++;
      return Promise.resolve(fakeConn([
        "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n",
      ]));
    },
  });
  assertEquals(result, { ok: true, status: 302, body: "" });
  assertEquals(connects, 1);
});

Deno.test("an endless answer is read only as far as it is kept", async () => {
  const conn = fakeConn(["HTTP/1.1 200 OK\r\n\r\n"], 4096);
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () => Promise.resolve(conn),
  });
  assert(result.ok);
  assertEquals(result.ok && result.body.length, 16 * 1024);
  assert(conn.reads() < 10, `read ${conn.reads()} times`);
});

Deno.test("an answer that is not HTTP reads as unreachable", async () => {
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () => Promise.resolve(fakeConn(["SSH-2.0-OpenSSH_9.6\r\n\r\n"])),
  });
  assertEquals(result, { ok: false, reason: "unreachable" });
});

Deno.test("a server that never answers is given up on", async () => {
  const silent: Conn = {
    readable: new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) }),
    writable: new WritableStream<Uint8Array>(),
    close() {},
  };
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () => Promise.resolve(silent),
    timeoutMs: 50,
  });
  assertEquals(result, { ok: false, reason: "unreachable" });
});

// ── The Nov 27 review ───────────────────────────────────────

Deno.test("IPv6 ranges are matched by number, not by the text's start", () => {
  for (const address of ["febf::1", "fe90::1", "fec0::1", "fdff::1", "ff05::2"]) {
    assert(isBlockedAddress(address), `${address} should be blocked`);
  }
  // 0fc1:: and 0fe8:: are public, whatever their first letters.
  for (const address of ["fc1::1", "fe8::1", "2001:db8::1"]) {
    assertEquals(isBlockedAddress(address), false, `${address} should be allowed`);
  }
});

Deno.test("a resolver that never answers is cut off by the deadline", async () => {
  const started = Date.now();
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => new Promise<string[]>(() => {}),
    timeoutMs: 100,
  });
  assertEquals(result, { ok: false, reason: "unreachable" });
  assert(Date.now() - started < 2000, "the lookup waited past the deadline");
});

Deno.test("a chunked reply that never frames a chunk is not read forever", async () => {
  const conn = fakeConn(["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz"], 4096);
  const result = await safePost("https://chat.example.com", "/x", {}, {
    resolve: () => Promise.resolve(["93.184.216.34"]),
    connect: () => Promise.resolve(conn),
    timeoutMs: 5000,
  });
  assertEquals(result, { ok: false, reason: "unreachable" });
  assert(conn.reads() < 100, `read ${conn.reads()} times`);
});

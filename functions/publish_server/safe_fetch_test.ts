import { assert, assertEquals } from "jsr:@std/assert@1";
import { isBlockedAddress, parseTarget, safePost } from "./safe_fetch.ts";

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

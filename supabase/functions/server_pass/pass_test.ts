import { assertEquals, assertNotEquals } from "jsr:@std/assert@1";
import { accountTag, normaliseEmail, signPass } from "./pass.ts";

const secret = new Uint8Array(32).fill(3);
const server = "cccc0000-0000-4000-8000-000000000001";
const url = "https://rift.example";

Deno.test("an email is lower-cased, and its +suffix dropped anywhere", () => {
  assertEquals(normaliseEmail("A.B+c@Example.com"), "a.b@example.com");
});

Deno.test("Gmail's dots and googlemail.com are the same inbox", () => {
  assertEquals(normaliseEmail("J.Doe+x@GoogleMail.com"), "jdoe@gmail.com");
  assertEquals(normaliseEmail(" jdoe@gmail.com "), "jdoe@gmail.com");
});

Deno.test("aliases of one Gmail inbox get one tag", async () => {
  assertEquals(
    await accountTag(secret, "name+1@gmail.com", url, server),
    await accountTag(secret, "n.ame@gmail.com", url, server),
  );
});

Deno.test("a tag differs on another server and at another address", async () => {
  const tag = await accountTag(secret, "name@gmail.com", url, server);
  assertNotEquals(tag, await accountTag(secret, "name@gmail.com", url, "dddd0000-0000-4000-8000-000000000001"));
  assertNotEquals(tag, await accountTag(secret, "name@gmail.com", "https://other.example", server));
  assertNotEquals(tag, await accountTag(secret, "other@gmail.com", url, server));
});

Deno.test("an address is its origin: case and a trailing slash do not matter", async () => {
  assertEquals(
    await accountTag(secret, "name@gmail.com", "https://Rift.Example/", server),
    await accountTag(secret, "name@gmail.com", url, server),
  );
});

Deno.test("a signed pass verifies with central's public key and carries its fields", async () => {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  const fields = {
    serverId: server,
    supabaseUrl: url,
    publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    tag: "tag-1",
    exp: 1_800_000_300,
  };
  const pass = await signPass(keys.privateKey, fields);
  const [payloadPart, sigPart] = pass.split(".");
  const unb64url = (s: string) => {
    let t = s.replace(/-/g, "+").replace(/_/g, "/");
    while (t.length % 4) t += "=";
    return Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  };
  const payload = unb64url(payloadPart);
  assertEquals(
    await crypto.subtle.verify("Ed25519", keys.publicKey, unb64url(sigPart), payload),
    true,
  );
  assertEquals(JSON.parse(new TextDecoder().decode(payload)), {
    v: 1,
    server_id: server,
    supabase_url: url,
    public_key: fields.publicKey,
    tag: "tag-1",
    exp: 1_800_000_300,
  });
});

import { assertEquals } from "jsr:@std/assert@1";
import { createRelay } from "./relay.ts";

// Each relay made here is one worker. What they share is the database and
// Google, both faked by `fetch`, so the test can count what a ring costs.

const secret = "push-secret";

async function serviceAccount() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const der = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", pair.privateKey),
  );
  const body = btoa(String.fromCharCode(...der));
  return {
    project_id: "rift-test",
    client_email: "relay@rift-test.iam.gserviceaccount.com",
    private_key:
      `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`,
  };
}

interface World {
  minted: number;
  bearers: string[];
  kept: { value: string; expiresAt: number } | null;
  dbDown: boolean;
}

function fakeFetch(world: World): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) =>
      Response.json(body, { status });
    if (url === "https://oauth2.googleapis.com/token") {
      world.minted++;
      // Google's answer takes a moment, so rings that arrive meanwhile overlap.
      await new Promise((r) => setTimeout(r, 20));
      return json({ access_token: `google-${world.minted}`, expires_in: 3599 });
    }
    if (url.includes("fcm.googleapis.com")) {
      world.bearers.push(new Headers(init?.headers).get("Authorization") ?? "");
      return json({ name: "sent" });
    }
    if (url.includes("/rest/v1/device_tokens")) {
      return json([{ token: "device-1" }]);
    }
    if (url.endsWith("/rpc/push_access_token")) {
      if (world.dbDown) return json({ message: "down" }, 503);
      const now = Math.floor(Date.now() / 1000);
      return json(
        world.kept && world.kept.expiresAt > now + 60
          ? { value: world.kept.value, expires_at: world.kept.expiresAt }
          : null,
      );
    }
    if (url.endsWith("/rpc/keep_push_access_token")) {
      if (world.dbDown) return json({ message: "down" }, 503);
      const { p_value, p_expires_at } = JSON.parse(String(init?.body));
      world.kept = {
        value: p_value,
        expiresAt: Date.parse(p_expires_at) / 1000,
      };
      return new Response(null, { status: 204 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
}

async function withWorld(world: World, run: () => Promise<void>) {
  const real = globalThis.fetch;
  globalThis.fetch = fakeFetch(world);
  try {
    await run();
  } finally {
    globalThis.fetch = real;
  }
}

async function worker() {
  return createRelay({
    supabaseUrl: "http://central.test",
    serviceRoleKey: "service",
    pushSecret: secret,
    serviceAccount: await serviceAccount(),
  });
}

function ringFor(relay: (req: Request) => Promise<Response>) {
  return relay(
    new Request("http://relay.test", {
      method: "POST",
      headers: { "x-push-secret": secret },
      body: JSON.stringify({
        recipient: "cccc0000-0000-4000-8000-000000000001",
      }),
    }),
  ).then((res) => res.json());
}

Deno.test("the next worker rings with the token the last one minted", async () => {
  const world: World = { minted: 0, bearers: [], kept: null, dbDown: false };
  const [first, second] = [await worker(), await worker()];
  await withWorld(world, async () => {
    assertEquals((await ringFor(first)).rang, 1);
    assertEquals((await ringFor(second)).rang, 1);
  });
  assertEquals(world.minted, 1);
  assertEquals(world.bearers, ["Bearer google-1", "Bearer google-1"]);
});

Deno.test("rings arriving together in one worker share one mint", async () => {
  const world: World = { minted: 0, bearers: [], kept: null, dbDown: false };
  const relay = await worker();
  await withWorld(world, async () => {
    const answers = await Promise.all([
      ringFor(relay),
      ringFor(relay),
      ringFor(relay),
    ]);
    assertEquals(answers.map((a) => a.rang), [1, 1, 1]);
  });
  assertEquals(world.minted, 1);
});

Deno.test("a token with under a minute left is not used; a new one is minted", async () => {
  const now = Math.floor(Date.now() / 1000);
  const world: World = {
    minted: 0,
    bearers: [],
    kept: { value: "nearly-gone", expiresAt: now + 30 },
    dbDown: false,
  };
  await withWorld(world, async () => {
    assertEquals((await ringFor(await worker())).rang, 1);
  });
  assertEquals(world.minted, 1);
  assertEquals(world.bearers, ["Bearer google-1"]);
  assertEquals(world.kept?.value, "google-1");
});

Deno.test("with the database's token unreachable, a ring still goes out", async () => {
  const world: World = { minted: 0, bearers: [], kept: null, dbDown: true };
  const relay = await worker();
  await withWorld(world, async () => {
    assertEquals((await ringFor(relay)).rang, 1);
    // And the worker keeps its own copy for the next ring.
    assertEquals((await ringFor(relay)).rang, 1);
  });
  assertEquals(world.minted, 1);
});

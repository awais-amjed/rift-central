import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

/**
 * Deletes central DM attachment blobs whose messages retention has removed.
 *
 * Called once a day by the database (migration 018), never by clients. The
 * database decides which blobs — `expired_dm_attachments()`, migration 017 —
 * and this only does the part SQL cannot: `storage.protect_delete()` refuses a
 * direct DELETE on `storage.objects`, so removing a blob needs the Storage API
 * and the service key.
 *
 * Deployed with `--no-verify-jwt`, because pg_net carries no JWT. The shared
 * secret in `attachment_sweep_config` is what stands in for one.
 */

const BUCKET = "central-dm-attachments";

/** Blobs per database query and per Storage API call. */
const BATCH = 1000;

/**
 * Batches per invocation. A day's expiries are far below this; the cap exists
 * so a large first backlog cannot run the function past its time limit, and
 * whatever is left is picked up the next day.
 */
const MAX_BATCHES = 20;

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  const expected = Deno.env.get("ATTACHMENT_SWEEP_SECRET") ?? "";
  const given = req.headers.get("x-sweep-secret") ?? "";
  if (req.method !== "POST" || expected.length === 0 || !(await sameSecret(given, expected))) {
    return json({ error: "Not allowed" }, 403);
  }

  let swept = 0;
  for (let batch = 0; batch < MAX_BATCHES; batch++) {
    const { data, error } = await supabase.rpc("expired_dm_attachments", { p_limit: BATCH });
    if (error) {
      console.error("[sweep] listing expired attachments:", error);
      return json({ error: "Could not list expired attachments", swept }, 500);
    }

    const names = (data ?? []) as string[];
    if (names.length === 0) break;

    const { error: removeError } = await supabase.storage.from(BUCKET).remove(names);
    if (removeError) {
      console.error("[sweep] removing attachments:", removeError);
      return json({ error: "Could not remove attachments", swept }, 500);
    }
    swept += names.length;
    if (names.length < BATCH) break;
  }

  console.log(`[sweep] removed ${swept} expired attachment(s)`);
  return json({ swept });
});

/** Compare two secrets in time that does not depend on where they differ. */
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

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

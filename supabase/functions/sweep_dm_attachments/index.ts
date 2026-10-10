import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

/**
 * Deletes the blobs the database says nothing points at any more.
 *
 * Three buckets, one call. DM attachments whose messages retention has
 * removed, directory icons no listing names, and bug report logs whose report
 * is gone — the last two ride along rather than getting functions of their
 * own because each would need the same secret, the same config row and
 * another entry in the same cron job to do the same thing: ask the database
 * what is unreferenced and hand the list to Storage.
 *
 * Called once a day by the database, never by clients. The
 * database decides which blobs — `expired_dm_attachments()` —
 * and this only does the part SQL cannot: `storage.protect_delete()` refuses a
 * direct DELETE on `storage.objects`, so removing a blob needs the Storage API
 * and the service key.
 *
 * Deployed with `--no-verify-jwt`, because pg_net carries no JWT. The shared
 * secret in `attachment_sweep_config` is what stands in for one.
 */

const BUCKET = "central-dm-attachments";
const ICON_BUCKET = "directory-icons";
const BUG_REPORT_BUCKET = "bug-reports";

/** Blobs per database query and per Storage API call. */
const BATCH = 1000;

/**
 * Batches per invocation. A day's expiries are far below this; the cap exists
 * so a large first backlog cannot run the function past its time limit, and
 * whatever is left is picked up the next day.
 */
const MAX_BATCHES = 20;

// `RIFT_SECRET_KEY` first — see `publish_server/index.ts` for why.
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  (Deno.env.get("RIFT_SECRET_KEY") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))!,
);

Deno.serve(async (req) => {
  const expected = Deno.env.get("ATTACHMENT_SWEEP_SECRET") ?? "";
  const given = req.headers.get("x-sweep-secret") ?? "";
  if (req.method !== "POST" || expected.length === 0 || !(await sameSecret(given, expected))) {
    return json({ error: "Not allowed" }, 403);
  }

  const attachments = await drain(BUCKET, "expired_dm_attachments");
  if ("error" in attachments) return attachments.response;

  // Icons after attachments, and never allowed to fail the attachment half:
  // the two are unrelated, and a directory icon left an extra day is a picture
  // nobody sees, while a DM blob left behind is storage somebody pays for.
  const icons = await drain(ICON_BUCKET, "expired_directory_icons");
  const iconsSwept = "error" in icons ? 0 : icons.swept;
  // The same for a bug report's logs, which retention leaves behind when it
  // deletes the report after 90 days.
  const logs = await drain(BUG_REPORT_BUCKET, "expired_bug_report_files");
  const logsSwept = "error" in logs ? 0 : logs.swept;

  console.log(
    `[sweep] removed ${attachments.swept} expired attachment(s), ${iconsSwept} unused icon(s), ` +
      `${logsSwept} expired bug report log(s)`,
  );
  return json({ swept: attachments.swept, icons: iconsSwept, logs: logsSwept });
});

/**
 * Empty one bucket of whatever [rpc] says is unreferenced, a batch at a time.
 *
 * Every RPC answers the same shape — an array of object names — because each
 * asks the same question of different tables, so one loop serves them all.
 */
async function drain(
  bucket: string,
  rpc: string,
): Promise<{ swept: number } | { error: true; response: Response }> {
  let swept = 0;
  for (let batch = 0; batch < MAX_BATCHES; batch++) {
    const { data, error } = await supabase.rpc(rpc, { p_limit: BATCH });
    if (error) {
      console.error(`[sweep] listing from ${rpc}:`, error);
      return { error: true, response: json({ error: `Could not list from ${rpc}`, swept }, 500) };
    }

    const names = (data ?? []) as string[];
    if (names.length === 0) break;

    const { error: removeError } = await supabase.storage.from(bucket).remove(names);
    if (removeError) {
      console.error(`[sweep] removing from ${bucket}:`, removeError);
      return { error: true, response: json({ error: `Could not empty ${bucket}`, swept }, 500) };
    }
    swept += names.length;
    if (names.length < BATCH) break;
  }
  return { swept };
}

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

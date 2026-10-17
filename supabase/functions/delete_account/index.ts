import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

/**
 * Delete the caller's Rift account, and everything central holds for it.
 *
 * Every row an account has hangs off `auth.users` by a cascade — the profile
 * and handle, DMs both ways and their pins, read state, friends and blocks,
 * device tokens, listings, likes, reports and bug reports — so removing the
 * Auth user is one call that takes all of it. What a cascade cannot reach is
 * Storage: `storage.protect_delete()` refuses a DELETE on `storage.objects`,
 * and the bytes live behind the Storage API, so the caller's folders are
 * emptied first, the same way the nightly sweep empties expired ones. The
 * encrypted backup is the one nothing else would ever remove.
 *
 * Only ever the caller: the account comes from the verified token, never the
 * body. And only just after a password sign-in. A session is a long-lived
 * refresh token on a device, so "signed in" alone would let anyone holding an
 * unlocked phone, or a copied token, destroy the account; the app signs in
 * again with the password right before asking, and the token's `amr` says
 * when that was.
 *
 * Moderator accounts live in `auth.users` too, but are not Rift accounts
 * (`central_admins`), and are not deleted here.
 *
 * Nothing on a self-hosted server is touched. Those memberships are separate
 * identities, made from the device's key, that the account never held.
 */

// `RIFT_SECRET_KEY` first — see `publish_server/index.ts` for why.
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  (Deno.env.get("RIFT_SECRET_KEY") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))!,
);

/** Every bucket a person's uploads land in, each under `<uid>/`. */
const BUCKETS = ["backups", "central-dm-attachments", "bug-reports", "directory-icons"];

/** How recent the password sign-in must be. */
const REAUTH_SECONDS = 10 * 60;

/** Names per Storage API listing and per removal. */
const PAGE = 1000;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return fail("method_not_allowed", 405);

  try {
    const token = bearer(req);
    if (!token) return fail("not_authenticated", 401);
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data.user) return fail("not_authenticated", 401);
    const uid = data.user.id;

    if (!signedInWithPasswordSince(token, REAUTH_SECONDS)) {
      return fail("reauthentication_needed", 403);
    }

    const { data: admin, error: adminError } = await supabase
      .from("central_admins").select("user_id").eq("user_id", uid).maybeSingle();
    if (adminError) {
      console.error("[delete_account] reading central_admins:", adminError);
      return fail("unexpected_error", 500);
    }
    if (admin) return fail("moderator_account", 403);

    // Files first: once the user is gone, nothing says whose folder this was.
    for (const bucket of BUCKETS) {
      const names = await namesUnder(bucket, uid);
      for (let i = 0; i < names.length; i += PAGE) {
        const { error: removeError } = await supabase.storage
          .from(bucket).remove(names.slice(i, i + PAGE));
        if (removeError) {
          console.error(`[delete_account] emptying ${bucket}:`, removeError);
          return fail("unexpected_error", 500);
        }
      }
    }

    const { error: deleteError } = await supabase.auth.admin.deleteUser(uid);
    if (deleteError) {
      console.error("[delete_account] deleting the user:", deleteError);
      return fail("unexpected_error", 500);
    }
    return json({ success: true, data: { deleted: true } }, 200);
  } catch (err) {
    console.error("[delete_account]", err);
    return fail("unexpected_error", 500);
  }
});

/**
 * Every object name under `<folder>/` in [bucket], however deep: a bug
 * report's logs sit a folder further down, under the report's id. A listing
 * names a folder with a null id, and is paged.
 */
async function namesUnder(bucket: string, folder: string): Promise<string[]> {
  const names: string[] = [];
  const folders = [folder];
  while (folders.length > 0) {
    const path = folders.pop()!;
    for (let offset = 0; ; offset += PAGE) {
      const { data, error } = await supabase.storage.from(bucket)
        .list(path, { limit: PAGE, offset });
      if (error) throw new Error(`listing ${bucket}/${path}: ${error.message}`);
      for (const entry of data ?? []) {
        const name = `${path}/${entry.name}`;
        if (entry.id === null) folders.push(name);
        else names.push(name);
      }
      if ((data ?? []).length < PAGE) break;
    }
  }
  return names;
}

/**
 * Whether [token] says its session began with a password at most [seconds]
 * ago. Read without verifying the signature, which `getUser` above has already
 * done by asking Auth.
 */
function signedInWithPasswordSince(token: string, seconds: number): boolean {
  try {
    const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(part.padEnd(part.length + (4 - part.length % 4) % 4, "=")));
    const now = Date.now() / 1000;
    return (claims.amr ?? []).some((entry: { method?: string; timestamp?: number }) =>
      entry.method === "password" && typeof entry.timestamp === "number" &&
      now - entry.timestamp <= seconds
    );
  } catch {
    return false;
  }
}

function bearer(req: Request): string {
  const header = req.headers.get("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

function fail(code: string, status: number): Response {
  return json({ success: false, error: code, code }, status);
}

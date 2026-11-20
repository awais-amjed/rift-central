-- ============================================================
-- Rift central — 015: what a deleted account leaves behind
-- ============================================================
-- From the Nov 18 review (finding 14). Deleting an account removed every row
-- that hangs off `auth.users` and emptied its Storage folders, and two things
-- outlived it anyway:
--
--   auth.audit_log_entries  Auth's record of every sign-up, sign-in, refresh
--                           and deletion: the address, the IP and the
--                           browser, in rows that name no user by key, so no
--                           cascade reaches them. Nothing pruned them, and
--                           every hourly dump carried them. Auth now writes
--                           them only to its own log (the compose file sets
--                           GOTRUE_AUDIT_LOG_DISABLE_POSTGRES); this empties
--                           the table once, and nightly after, so a restored
--                           dump does not bring them back for good.
--   backups                 an account removed any way but `delete_account`
--                           (from Auth's admin API, say), or a backup uploaded
--                           in the hour a deleted account's session still
--                           held, stays forever: nothing else ever removes a
--                           backup. `orphaned_backups` names them, and the
--                           nightly sweep removes them through Storage.
--
-- DM files of a deleted account need nothing new: the sweep takes every one
-- after 31 days. Bug report files go with their report, which cascades.
-- ============================================================

-- ============================================================
-- 1. Auth's audit log
-- ============================================================

DELETE FROM auth.audit_log_entries;

-- At 03:37, between the night's other jobs (006, 008) and off the hourly
-- backup's :07. The table should stay empty; this is for the day it is not.
SELECT cron.unschedule('central-audit-log-prune')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-audit-log-prune');

SELECT cron.schedule(
  'central-audit-log-prune',
  '37 3 * * *',
  $$ DELETE FROM auth.audit_log_entries; $$
);

-- ============================================================
-- 2. Backups nobody owns
-- ============================================================
-- A backup is `<uid>/vault.json` (014), so the folder names its account. One
-- whose account is gone is unreadable by anybody but the service key, and
-- removable only through Storage, which the sweep does with this list.

CREATE OR REPLACE FUNCTION orphaned_backups(p_limit INTEGER DEFAULT 1000)
  RETURNS SETOF TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'backups'
     AND NOT EXISTS (SELECT 1 FROM auth.users u
                      WHERE u.id::text = split_part(o.name, '/', 1))
   ORDER BY o.name
   LIMIT GREATEST(p_limit, 0)
$$;

REVOKE ALL ON FUNCTION orphaned_backups(INTEGER) FROM PUBLIC, anon, authenticated;
-- The sweep calls it with the service key.
GRANT EXECUTE ON FUNCTION orphaned_backups(INTEGER) TO service_role;

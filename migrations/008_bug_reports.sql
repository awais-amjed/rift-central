-- ============================================================
-- Rift central — 008: bug reports
-- ============================================================
-- Someone whose share stopped or whose app closed can now send what happened:
-- a few words, the version and system, and the app's own log files. Rift
-- keeps a log of every session on the device (the app's ARCHITECTURE.md, "The
-- app's log"); until now it went nowhere, so a problem on a tester's machine
-- left nothing to read.
--
-- The same shape as a directory report, because the same people read it: a
-- signed-in account files one through a function that holds a daily ceiling,
-- and only a moderator on the admin site, with a second factor, reads them.
-- Unlike a directory report it is not about anybody else, so there is nothing
-- to snapshot and nothing to hide.
--
-- **The logs are personal data**, and are treated as such: a private bucket,
-- the reporter's own folder, nobody else's eyes but a moderator's, and gone
-- after 90 days with the report. The app takes tokens out of every line
-- before it is written, and never logs a message; what is left is the
-- version, ids, error text, device names and a shared window's title.
-- ============================================================

-- One report. `version` and `system` come from the app and are not trusted:
-- they say what the reporter's copy claims to be, which is what a moderator
-- wants to read, and the length checks keep them from being anything more.
CREATE TABLE IF NOT EXISTS bug_reports (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  reporter_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  description TEXT        NOT NULL CHECK (length(btrim(description)) BETWEEN 1 AND 4000),
  version     TEXT        NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
  system      TEXT        NOT NULL CHECK (length(system) BETWEEN 1 AND 300),
  -- Set when a moderator has read it and is done with it; the report stays
  -- until retention takes it, so a problem that comes back can be compared.
  resolved_at TIMESTAMPTZ,
  resolved_by UUID        REFERENCES central_admins(user_id) ON DELETE SET NULL
);

-- The daily ceiling counts a reporter's recent rows.
CREATE INDEX IF NOT EXISTS idx_bug_reports_reporter
  ON bug_reports (reporter_id, created_at DESC);

-- The moderator's list, newest first, and retention's range.
CREATE INDEX IF NOT EXISTS idx_bug_reports_created
  ON bug_reports (created_at DESC);

-- How many reports one account may send per rolling day. A tester sending
-- one after each thing that goes wrong is well inside it; a loop is not.
CREATE OR REPLACE FUNCTION daily_bug_report_quota() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 10 $$;

-- Log files one report may carry: this session's and the ones before it,
-- since a crash is reported from the session after it.
CREATE OR REPLACE FUNCTION bug_report_file_limit() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 4 $$;

-- ---------- sending ----------
-- File a report and get its id, which names the folder its logs go in:
-- `bug-reports/<your uid>/<report id>/<file>`. The logs are uploaded after
-- the row exists, so that the bucket can ask whose report a folder is.
CREATE OR REPLACE FUNCTION submit_bug_report(
  p_description TEXT,
  p_version     TEXT,
  p_system      TEXT
) RETURNS UUID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_id UUID;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'reporter_has_no_profile';
  END IF;
  IF (SELECT count(*) FROM bug_reports
       WHERE reporter_id = auth.uid()
         AND created_at > now() - INTERVAL '1 day') >= daily_bug_report_quota() THEN
    RAISE EXCEPTION 'bug_report_limit_reached';
  END IF;

  INSERT INTO bug_reports (reporter_id, description, version, system)
  VALUES (auth.uid(), btrim(p_description), btrim(p_version), btrim(p_system))
  RETURNING id INTO v_id;
  RETURN v_id;
END; $$;

COMMENT ON FUNCTION submit_bug_report(TEXT, TEXT, TEXT) IS
  'Send a bug report to central''s moderators. Returns its id, the folder its '
  'log files go in. Ten a day.';

-- Whether an upload to `bug-reports` may land at `p_name`: in the caller's own
-- folder, under one of their own reports filed in the last hour, and while
-- that report holds fewer than `bug_report_file_limit()` files. The bucket's
-- insert policy asks this, as definer, because the policy runs as the member
-- and `bug_reports` lets members read nothing.
--
-- The hour is the window the app has to upload what it just reported; after
-- it, a report's folder takes nothing new, so an old report id is not a
-- place to keep putting bytes.
CREATE OR REPLACE FUNCTION bug_report_takes_file(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_parts  TEXT[] := string_to_array(p_name, '/');
  v_folder TEXT;
BEGIN
  IF auth.uid() IS NULL OR array_length(v_parts, 1) <> 3
     OR v_parts[1] <> auth.uid()::text
     OR v_parts[2] !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_parts[3] = '' THEN
    RETURN FALSE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM bug_reports
                  WHERE id = v_parts[2]::uuid
                    AND reporter_id = auth.uid()
                    AND created_at > now() - INTERVAL '1 hour') THEN
    RETURN FALSE;
  END IF;
  -- A prefix range rather than `foldername`, for the reason the icon ceiling
  -- in 005 gives: it is answered by Storage's own (bucket_id, name COLLATE
  -- "C") index. '0' follows '/' in byte order with nothing between.
  v_folder := v_parts[1] || '/' || v_parts[2];
  RETURN (SELECT count(*) FROM storage.objects o
           WHERE o.bucket_id = 'bug-reports'
             AND o.name COLLATE "C" >= v_folder || '/'
             AND o.name COLLATE "C" <  v_folder || '0') < bug_report_file_limit();
END; $$;

-- ---------- the moderator's side ----------
-- Every report, newest first, open ones before resolved ones, each with the
-- reporter's handle and the files it carries. The page fetches a file
-- through Storage, which the select policy below lets a moderator do.
CREATE OR REPLACE FUNCTION moderation_bug_reports() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_out JSONB;
BEGIN
  PERFORM assert_central_admin();

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', r.id, 'created_at', r.created_at,
           'description', r.description, 'version', r.version,
           'system', r.system, 'reporter_handle', u.handle,
           'resolved_at', r.resolved_at, 'resolved_by', a.name,
           'files', (
             SELECT COALESCE(jsonb_agg(jsonb_build_object(
                      'name', o.name,
                      'size', (o.metadata ->> 'size')::bigint)
                      ORDER BY o.name), '[]'::jsonb)
               FROM storage.objects o
              WHERE o.bucket_id = 'bug-reports'
                AND o.name COLLATE "C" >= r.reporter_id::text || '/' || r.id::text || '/'
                AND o.name COLLATE "C" <  r.reporter_id::text || '/' || r.id::text || '0'))
           ORDER BY r.resolved_at IS NOT NULL, r.created_at DESC), '[]'::jsonb)
    INTO v_out
    FROM bug_reports r
    JOIN users u ON u.id = r.reporter_id
    LEFT JOIN central_admins a ON a.user_id = r.resolved_by;
  RETURN v_out;
END; $$;

-- Mark a report done, or open again.
CREATE OR REPLACE FUNCTION moderation_resolve_bug_report(
  p_report   UUID,
  p_resolved BOOLEAN
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM assert_central_admin();
  UPDATE bug_reports
     SET resolved_at = CASE WHEN p_resolved THEN now() END,
         resolved_by = CASE WHEN p_resolved THEN auth.uid() END
   WHERE id = p_report;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bug_report_not_found';
  END IF;
END; $$;

-- ---------- retention ----------
-- Log files whose report is gone — taken by retention, or with the account
-- that sent it — for the nightly sweep, which deletes them through Storage
-- (`storage.protect_delete()` refuses a direct DELETE). The hour of grace
-- covers the moment between a report's row and its first upload, which is
-- not a gap here, and a file whose name is no report's at all, which is.
CREATE OR REPLACE FUNCTION expired_bug_report_files(
  p_limit INTEGER  DEFAULT 1000,
  p_grace INTERVAL DEFAULT '1 hour'
) RETURNS SETOF TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'bug-reports'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM bug_reports r
                      WHERE r.reporter_id::text = split_part(o.name, '/', 1)
                        AND r.id::text = split_part(o.name, '/', 2))
   ORDER BY o.name
   LIMIT GREATEST(p_limit, 0)
$$;

-- Reports older than 90 days go at 03:27, before the sweep at 03:47 (006),
-- which then takes their files.
SELECT cron.unschedule('central-bug-report-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-bug-report-retention');
SELECT cron.schedule(
  'central-bug-report-retention',
  '27 3 * * *',
  $$DELETE FROM bug_reports WHERE created_at < now() - interval '90 days'$$
);

-- ============================================================
-- Storage
-- ============================================================
-- Private, 10 MB a file: the app gzips a session's log before it uploads, and
-- a session's file is at most 8 MB before that.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('bug-reports', 'bug-reports', false, 10485760)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 10485760;

DROP POLICY IF EXISTS bug_reports_insert ON storage.objects;
CREATE POLICY bug_reports_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'bug-reports' AND bug_report_takes_file(name));

-- The reporter may read their own files back (Storage reads the row it has
-- just written), and a moderator may read all of them. Nobody updates or
-- deletes: a report's files are what was sent, and the sweep removes them.
DROP POLICY IF EXISTS bug_reports_select ON storage.objects;
CREATE POLICY bug_reports_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'bug-reports'
         AND ((storage.foldername(name))[1] = (SELECT auth.uid())::text
              OR (SELECT is_central_admin())));

-- ============================================================
-- Grants
-- ============================================================
-- 007's blanket revoke ran before these functions existed, so each is
-- revoked here and granted by name. The table gets no grant at all, like the
-- directory's moderation tables: sending is `submit_bug_report`, which holds
-- the ceiling, and reading is `moderation_bug_reports`, which asks for a
-- moderator.
REVOKE ALL ON bug_reports FROM anon, authenticated;
ALTER TABLE bug_reports ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON FUNCTION daily_bug_report_quota()                FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION bug_report_file_limit()                 FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION submit_bug_report(TEXT, TEXT, TEXT)     FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION bug_report_takes_file(TEXT)             FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_bug_reports()                FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_resolve_bug_report(UUID, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION expired_bug_report_files(INTEGER, INTERVAL) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION submit_bug_report(TEXT, TEXT, TEXT) TO authenticated;
-- Asked by the insert policy, which runs as the member.
GRANT EXECUTE ON FUNCTION bug_report_takes_file(TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_bug_reports() TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_resolve_bug_report(UUID, BOOLEAN) TO authenticated;
-- The sweep calls it with the service key.
GRANT EXECUTE ON FUNCTION expired_bug_report_files(INTEGER, INTERVAL) TO service_role;

-- ============================================================
-- Rift central — 028: a moderator deletes a bug report
-- ============================================================
-- Until now a bug report stayed until its 90 days were up, read or not. A
-- moderator can now delete one before then: a duplicate, a report that is
-- no report at all, or one whose logs should not be kept a day longer than
-- it took to read them.
--
-- Only the row goes here. Its log files are then a report's that no longer
-- exists, which is exactly what `expired_bug_report_files` (008) offers the
-- nightly sweep at 03:47, so they go the same night, through Storage, the
-- way retention's do. Nothing can read them meanwhile: a member reads only
-- their own folder, and the moderator's page lists files by report.
--
-- A deleted report still counts against its sender's day. The ceiling in
-- `submit_bug_report` counted the reporter's rows, so a delete gave a slot
-- back, and a sender whose reports were being cleared could keep sending,
-- each one posted to the webhook again. A report deleted within a day of
-- being sent leaves its sender and time in `bug_report_deletions`, which
-- the ceiling counts too; a delete prunes the rows a day has passed.
-- ============================================================

-- What a deleted report leaves for the ceiling: who sent it, and when.
CREATE TABLE IF NOT EXISTS bug_report_deletions (
  reporter_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sent_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bug_report_deletions_reporter
  ON bug_report_deletions (reporter_id, sent_at DESC);

ALTER TABLE bug_report_deletions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bug_report_deletions FROM PUBLIC, anon, authenticated;

-- 008's, counting deleted reports as sent.
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
         AND created_at > now() - INTERVAL '1 day')
     + (SELECT count(*) FROM bug_report_deletions
         WHERE reporter_id = auth.uid()
           AND sent_at > now() - INTERVAL '1 day') >= daily_bug_report_quota() THEN
    RAISE EXCEPTION 'bug_report_limit_reached';
  END IF;

  INSERT INTO bug_reports (reporter_id, description, version, system)
  VALUES (auth.uid(), btrim(p_description), btrim(p_version), btrim(p_system))
  RETURNING id INTO v_id;
  RETURN v_id;
END; $$;

CREATE OR REPLACE FUNCTION moderation_delete_bug_report(p_report UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_reporter UUID;
  v_sent     TIMESTAMPTZ;
BEGIN
  PERFORM assert_central_admin();
  DELETE FROM bug_reports WHERE id = p_report
    RETURNING reporter_id, created_at INTO v_reporter, v_sent;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'bug_report_not_found';
  END IF;
  DELETE FROM bug_report_deletions WHERE sent_at <= now() - INTERVAL '1 day';
  IF v_sent > now() - INTERVAL '1 day' THEN
    INSERT INTO bug_report_deletions (reporter_id, sent_at) VALUES (v_reporter, v_sent);
  END IF;
END; $$;

COMMENT ON FUNCTION moderation_delete_bug_report(UUID) IS
  'Delete a bug report now, for a moderator. Its log files go at the next '
  'nightly sweep.';

REVOKE ALL ON FUNCTION moderation_delete_bug_report(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION moderation_delete_bug_report(UUID) TO authenticated;

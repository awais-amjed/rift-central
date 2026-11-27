-- ============================================================
-- Rift central — 029: a moderator deletes several bug reports at once
-- ============================================================
-- 028 deletes one report. The admin page now lets a moderator tick several
-- and delete them together, and this takes them in one call, so they go
-- all or none, and the page reloads once rather than once a report.
--
-- The same rules as 028: only the rows go, their log files at the nightly
-- sweep, and each one sent within the last day still counts against its
-- sender's ceiling through `bug_report_deletions`. An id that is no report
-- (one another moderator deleted a moment before) is passed over, since
-- what was asked for is gone either way; the count says how many went.
-- ============================================================

-- The most one call takes: well above a long day's reports, and a bound on
-- the work one request can ask for.
CREATE OR REPLACE FUNCTION bug_report_delete_limit() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 500 $$;

CREATE OR REPLACE FUNCTION moderation_delete_bug_reports(p_reports UUID[]) RETURNS INTEGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_count INTEGER;
BEGIN
  PERFORM assert_central_admin();
  IF COALESCE(cardinality(p_reports), 0) = 0 THEN
    RAISE EXCEPTION 'no_bug_reports_given';
  END IF;
  IF cardinality(p_reports) > bug_report_delete_limit() THEN
    RAISE EXCEPTION 'too_many_bug_reports';
  END IF;

  DELETE FROM bug_report_deletions WHERE sent_at <= now() - INTERVAL '1 day';
  WITH gone AS (
    DELETE FROM bug_reports WHERE id = ANY (p_reports)
      RETURNING reporter_id, created_at
  ), counted AS (
    INSERT INTO bug_report_deletions (reporter_id, sent_at)
    SELECT reporter_id, created_at FROM gone
     WHERE created_at > now() - INTERVAL '1 day'
  )
  SELECT count(*) INTO v_count FROM gone;
  RETURN v_count;
END; $$;

COMMENT ON FUNCTION moderation_delete_bug_reports(UUID[]) IS
  'Delete several bug reports now, for a moderator, and say how many went. '
  'Their log files go at the next nightly sweep.';

REVOKE ALL ON FUNCTION bug_report_delete_limit()               FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_delete_bug_reports(UUID[])   FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION moderation_delete_bug_reports(UUID[]) TO authenticated;

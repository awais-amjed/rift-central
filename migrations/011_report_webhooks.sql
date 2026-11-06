-- ============================================================
-- Rift central — 011: reports post to a webhook as they arrive
-- ============================================================
-- A report waited on the admin site until somebody thought to look. Now each
-- new one also posts to a webhook, so it turns up in a channel on the
-- moderator's own server: bug reports to one, directory reports to another.
--
-- What is sent: for a bug report, its words, version and system; for a directory
-- report, the listing's name, the reason and the reporter's words. Never the
-- reporter, and never a bug report's log files, which stay in their private
-- bucket for a moderator to open. The text is readable by whoever hosts that
-- channel, and a webhook's messages are not encrypted, so **the channel has
-- to be private to the moderators**. A copy there also outlives the 90 days
-- central keeps a report, until somebody deletes it.
--
-- Posting is best effort. pg_net queues the request and returns, nothing
-- retries it, and a failure to queue is caught, so a report is always saved
-- whatever happens to its message. The admin site stays the whole record.
-- ============================================================

-- One row for each kind of report, and no row means that kind posts nothing.
-- The URL holds the webhook's secret, so no session can read this table: only
-- the SECURITY DEFINER function below does.
CREATE TABLE IF NOT EXISTS report_webhook_config (
  kind      TEXT PRIMARY KEY CHECK (kind IN ('bug', 'directory')),
  url       TEXT NOT NULL,
  -- Where a moderator opens the report; left out of the message when empty.
  admin_url TEXT
);

ALTER TABLE report_webhook_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON report_webhook_config FROM PUBLIC, anon, authenticated;

-- Queue one message. Takes the kind rather than a URL, so that nothing else
-- can use it to send anywhere. A warning names only the error's code: pg_net's
-- own message could quote the URL, and the logs are not where a secret goes.
CREATE OR REPLACE FUNCTION post_report_to_webhook(p_kind TEXT, p_text TEXT)
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg report_webhook_config;
BEGIN
  SELECT * INTO v_cfg FROM report_webhook_config WHERE kind = p_kind;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  PERFORM net.http_post(
    url     := v_cfg.url,
    headers := jsonb_build_object('Content-Type', 'application/json'),
    body    := jsonb_build_object('text',
                 p_text || COALESCE(E'\nOpen in admin: ' || NULLIF(v_cfg.admin_url, ''), ''))
  );
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'report webhook: could not queue a % report (%)', p_kind, SQLSTATE;
END; $$;

CREATE OR REPLACE FUNCTION announce_bug_report()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  PERFORM post_report_to_webhook('bug',
    '🐞 Bug report — ' || NEW.version || ', ' || NEW.system || E'\n' || NEW.description);
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION announce_directory_report()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  PERFORM post_report_to_webhook('directory',
    '🚩 Directory report — '
      || CASE WHEN NEW.server_listing_id IS NOT NULL THEN 'server' ELSE 'bot' END
      || ' "' || COALESCE(NEW.snapshot ->> 'name', 'unnamed') || '", reason: ' || NEW.reason
      || COALESCE(E'\n' || NULLIF(btrim(NEW.details), ''), ''));
  RETURN NEW;
END; $$;

-- On insert only. Reporting a listing again while the first report is open
-- updates that row, and the queue counts people, not presses, so it posts once.
DROP TRIGGER IF EXISTS announce_bug_report ON bug_reports;
CREATE TRIGGER announce_bug_report
  AFTER INSERT ON bug_reports
  FOR EACH ROW EXECUTE FUNCTION announce_bug_report();

DROP TRIGGER IF EXISTS announce_directory_report ON directory_reports;
CREATE TRIGGER announce_directory_report
  AFTER INSERT ON directory_reports
  FOR EACH ROW EXECUTE FUNCTION announce_directory_report();

REVOKE ALL ON FUNCTION post_report_to_webhook(TEXT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION announce_bug_report()              FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION announce_directory_report()        FROM PUBLIC, anon, authenticated;

-- ============================================================
-- Rift central server — 018: run the attachment sweep daily
-- ============================================================
-- Kept apart from 017 because pg_cron only installs in the database named by
-- `cron.database_name`, so the policy tests' scratch database cannot apply it —
-- the same reason 004 is left out of them.
--
-- Half an hour after 004's retention job (03:17), so the messages that expire
-- today are already gone. The sweep only removes blobs older than 31 days, so
-- the order is tidiness rather than correctness.

SELECT cron.unschedule('central-dm-attachment-sweep')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-dm-attachment-sweep');

SELECT cron.schedule(
  'central-dm-attachment-sweep',
  '47 3 * * *',
  $$SELECT request_attachment_sweep()$$
);

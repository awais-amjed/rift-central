-- ============================================================
-- Rift central server — 020: retention keeps only the age limit
-- ============================================================
-- 004's job, without the ranking: 019's send_dm keeps each conversation to
-- its newest 500 as it goes, so the night has only the 30 days to enforce, and
-- idx_dm_messages_created makes that a range scan.
--
-- Its own file because pg_cron runs in one database only, the same reason 004
-- and 018 are kept apart from what the tests apply.

SELECT cron.unschedule('central-dm-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-dm-retention');

SELECT cron.schedule(
  'central-dm-retention',
  '17 3 * * *',
  $$ DELETE FROM dm_messages WHERE created_at < now() - interval '30 days'; $$
);

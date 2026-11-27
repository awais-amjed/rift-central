-- ============================================================
-- Rift central — 026: directory search by index, a bounded job log
-- ============================================================
-- Two nits from the Nov 27 review. Neither changes what anybody may see or do.
--
--   1. A directory search, servers or bots, is "name or description contains
--      these letters" (`ILIKE '%q%'`), which no ordinary index can answer, so
--      every search read every listing. Trigram indexes answer it.
--   2. pg_cron writes a row for every job it runs into `cron.job_run_details`
--      and never deletes one. Six jobs a night is small, but it only grows.
-- ============================================================

-- ---------- 1. search ----------
-- pg_trgm indexes each three-letter piece of the text, so "contains" becomes
-- an index lookup. One index per column, because the app asks for
-- `name ILIKE … OR description ILIKE …` and the planner combines the two
-- (a BitmapOr). Measured Nov 27 on a copy of `public_servers` (rolled back):
-- a word no listing has took 7.4 ms at 5,000 listings and 149 ms at 100,000
-- as a full read, and 0.06 and 0.08 ms with these. A common word was already
-- fast, since the browse order's index finds 51 matches early, and the
-- planner still takes that path for it; and a search of one or two letters
-- has no trigram to look up, so it does as it did. At 100,000 listings the
-- two indexes were 14 MB beside a 34 MB table. A write to a listing's name or
-- description updates them; a like does not touch either column.
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;

CREATE INDEX IF NOT EXISTS idx_public_servers_name_trgm
  ON public_servers USING GIN (name extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_public_servers_description_trgm
  ON public_servers USING GIN (description extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_public_bots_name_trgm
  ON public_bots USING GIN (name extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_public_bots_description_trgm
  ON public_bots USING GIN (description extensions.gin_trgm_ops);

-- ---------- 2. the job log ----------
-- A month of it: enough to see a job that has been failing, and why. A run
-- still going has no end time and is kept. At 04:02, after the night's other
-- jobs (03:17 to 03:57).
SELECT cron.unschedule('central-job-log-prune')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-job-log-prune');
SELECT cron.schedule(
  'central-job-log-prune',
  '2 4 * * *',
  $$ DELETE FROM cron.job_run_details WHERE end_time < now() - interval '30 days'; $$
);

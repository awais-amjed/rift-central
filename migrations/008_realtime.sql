-- ============================================================
-- Rift central server — 008: realtime
-- ============================================================
-- What a client may subscribe to. `CentralDmRepository.subscribeIncoming`
-- watches `dm_messages` filtered on `recipient_id`, and Realtime re-checks
-- 002's policies per subscriber, so a client only ever receives rows it could
-- have selected anyway.
--
-- This was missing. The central project predates its migration set — it was
-- provisioned by pasting SQL into the Management API as features landed (see
-- 001's header), and the publication was one of the things configured by hand
-- in the dashboard rather than in SQL. Rebuilding the schema from these files
-- therefore produced a database that was correct in every respect except that
-- nothing was published, and the failure is silent: sends succeed, rows land,
-- policies pass, and the recipient simply never hears about them. Central DMs
-- only appeared when something forced a refetch — reopening the conversation.
-- Found Aug 23 2026 driving two real clients; see MANUAL_TESTING.md.
--
-- The self-hosted tier has always had its equivalent
-- (`self_hosted_server_migrations/004_realtime.sql`), which is why channel
-- messages and server DMs delivered live throughout and only central did not.
--
-- Note that a policy consulting an RLS-locked table always evaluates false
-- here, silently — which looks exactly like Realtime being broken. 002's
-- helpers are SECURITY DEFINER for that reason.

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE dm_messages;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- `users` and `read_state` are deliberately absent. Nothing on the client
-- watches them: the directory is searched on demand, and a read cursor is
-- written by the only client that reads it. Publishing a table nobody
-- subscribes to only widens what Realtime has to authorize per change.

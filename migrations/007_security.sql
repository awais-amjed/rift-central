-- ============================================================
-- Rift central — 007: grants, RLS, and every policy
-- ============================================================
-- Who may read and write what, in one file.
--
-- **It is last on purpose.** Supabase's default privileges grant EXECUTE on
-- every new function in `public` to `anon` and `authenticated`, and
-- `ALTER DEFAULT PRIVILEGES ... REVOKE` does not undo them — revoking from a
-- default that holds no explicit grant is a no-op. So the blanket
-- `REVOKE ALL ON ALL FUNCTIONS` only means anything once every function
-- exists, and anything reachable afterwards is reachable because it is named
-- here. `is_handle_available` is the one thing `anon` is given, because
-- choosing a handle happens before there is an account.
-- ============================================================

-- ============================================================
-- Grants, RLS, policies
-- ============================================================
-- Central was always meant to be reached directly by clients, so it has had
-- RLS from the start — unlike the self-hosted schema, where the same defaults
-- left three tables open. The same discipline is written down here anyway:
-- `anon` gets nothing, members get named columns, and every table's policies
-- sit next to each other.

-- ============================================================
-- 1. Grants
-- ============================================================

REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;

GRANT SELECT, INSERT ON users TO authenticated;

GRANT UPDATE (handle, chat_public_key, signing_public_key) ON users TO authenticated;

-- No INSERT: new messages go through send_dm(), which is where the daily quota
-- lives. Editing and deleting your own are ordinary writes — an edit is not a
-- new message and must not cost quota.
GRANT SELECT, DELETE ON dm_messages TO authenticated;

GRANT UPDATE (ciphertext, nonce, signature, key_version) ON dm_messages TO authenticated;

-- Read-only: pinning is `set_pinned`, which holds the cap.
GRANT SELECT ON dm_message_pins TO authenticated;

GRANT SELECT, INSERT ON read_state TO authenticated;

GRANT UPDATE (last_read_id, updated_at) ON read_state TO authenticated;

DROP POLICY IF EXISTS users_insert_self ON users;
CREATE POLICY users_insert_self ON users FOR INSERT TO authenticated
  WITH CHECK (id = auth.uid());

DROP POLICY IF EXISTS users_update_self ON users;
CREATE POLICY users_update_self ON users FOR UPDATE TO authenticated
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

DROP POLICY IF EXISTS dm_message_pins_select ON dm_message_pins;
CREATE POLICY dm_message_pins_select ON dm_message_pins FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) IN (user_low, user_high));

DROP POLICY IF EXISTS dm_messages_select ON dm_messages;
CREATE POLICY dm_messages_select ON dm_messages FOR SELECT TO authenticated
  USING (auth.uid() IN (sender_id, recipient_id));

DROP POLICY IF EXISTS dm_messages_update_own ON dm_messages;
CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid()) WITH CHECK (sender_id = auth.uid());

DROP POLICY IF EXISTS dm_messages_delete_own ON dm_messages;
CREATE POLICY dm_messages_delete_own ON dm_messages FOR DELETE TO authenticated
  USING (sender_id = auth.uid());

DROP POLICY IF EXISTS read_state_own ON read_state;
CREATE POLICY read_state_own ON read_state FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- ============================================================
-- Function privileges
-- ============================================================

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION claim_handle(TEXT, TEXT, TEXT) TO authenticated;

GRANT EXECUTE ON FUNCTION dm_quota()          TO authenticated;

GRANT EXECUTE ON FUNCTION mark_read(read_scope, UUID, BIGINT) TO authenticated;

-- ============================================================
-- Grants and policies
-- ============================================================
-- Read and withdraw are table calls; everything that *writes* a listing goes
-- through publish_server() below, so there is no INSERT or UPDATE grant here
-- and correspondingly no policy for either.

REVOKE ALL ON public_servers FROM anon, authenticated;

GRANT SELECT, DELETE ON public_servers TO authenticated;

DROP POLICY IF EXISTS public_servers_select ON public_servers;
CREATE POLICY public_servers_select ON public_servers FOR SELECT TO authenticated
  USING ((is_listed AND hidden_at IS NULL)
         OR owner_id = auth.uid()
         OR (SELECT is_central_admin()));

DROP POLICY IF EXISTS public_servers_delete_own ON public_servers;
CREATE POLICY public_servers_delete_own ON public_servers FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

-- ============================================================
-- Function privileges
-- ============================================================

REVOKE ALL ON FUNCTION max_public_servers() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                      TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;

-- Unlike daily_dm_quota(), which the client learns through dm_quota() because
-- what it needs is the *remaining* count, the cap is the whole answer here —
-- an account can see its own listings and subtract. Granting the constant
-- lets the publish dialog say "9 of 10" instead of discovering the limit by
-- being refused.
GRANT EXECUTE ON FUNCTION max_public_servers() TO authenticated;

-- ============================================================
-- The bot directory
-- ============================================================
-- Read by everyone signed in, written only by whoever published it — the same
-- shape as `public_servers`, with one difference that matters: `publish_bot`
-- **is** granted to `authenticated`.
--
-- That is not an oversight and it is not a weaker rule. `publish_server` was
-- taken away because central could not tell an admin from any member, and the
-- listing it writes reserves a (host, server) pair the real admin then cannot
-- have. A bot listing reserves nothing, points at no database, and carries no
-- authority — the worst a false one does is describe a program that isn't
-- there, next to a source URL anybody can read. There is nothing here a round
-- trip could verify.

REVOKE ALL ON public_bots FROM anon, authenticated;

GRANT SELECT, DELETE ON public_bots TO authenticated;

DROP POLICY IF EXISTS public_bots_select ON public_bots;
CREATE POLICY public_bots_select ON public_bots FOR SELECT TO authenticated
  USING ((is_listed AND hidden_at IS NULL)
         OR owner_id = auth.uid()
         OR (SELECT is_central_admin()));

DROP POLICY IF EXISTS public_bots_delete_own ON public_bots;
CREATE POLICY public_bots_delete_own ON public_bots FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

-- No UPDATE grant: `publish_bot` is the only way a listing changes, which is
-- what makes the per-account cap unavoidable. The one column somebody else
-- moves is `like_count`, and that is a trigger's doing, not a write anyone is
-- allowed to make.

REVOKE ALL ON FUNCTION max_public_bots() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION publish_bot(UUID, TEXT, TEXT, TEXT, TEXT, TEXT[], JSONB,
                                   BOOLEAN)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION publish_bot(UUID, TEXT, TEXT, TEXT, TEXT, TEXT[], JSONB,
                                      BOOLEAN)
  TO authenticated;

-- Same reasoning as max_public_servers(): the cap is the whole answer, so the
-- dialog can say "9 of 10" rather than find out by being refused.
GRANT EXECUTE ON FUNCTION max_public_bots() TO authenticated;

-- ---------- likes ----------
-- A like is public — the count is the ranking, and a count nobody may check
-- is a number the directory is asking to be trusted on. So the rows are
-- readable by everyone signed in, and writable only as your own.
--
-- INSERT and DELETE rather than an RPC: there is no cap to enforce and no
-- decision to make. The primary key is (bot_id, user_id), so liking twice is
-- a duplicate-key error rather than two votes, and the trigger recounts from
-- the table either way.

REVOKE ALL ON bot_likes FROM anon, authenticated;

GRANT SELECT, INSERT, DELETE ON bot_likes TO authenticated;

DROP POLICY IF EXISTS bot_likes_select ON bot_likes;
CREATE POLICY bot_likes_select ON bot_likes FOR SELECT TO authenticated
  USING (TRUE);

DROP POLICY IF EXISTS bot_likes_insert_own ON bot_likes;
CREATE POLICY bot_likes_insert_own ON bot_likes FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS bot_likes_delete_own ON bot_likes;
CREATE POLICY bot_likes_delete_own ON bot_likes FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- ============================================================
-- Moderating the directory
-- ============================================================
-- A hidden listing leaves everyone's browse by the select policies above,
-- which still show it to its owner — so they can see that it was hidden and
-- why — and to moderators, in a subquery so the check runs once per statement
-- rather than once per row.
--
-- The three moderation tables get no grant at all. Reporting is
-- `report_listing`, which holds the daily ceiling; everything else is a
-- `moderation_*` function that refuses anyone not in `central_admins`. So
-- those are granted to every signed-in account, and the check that matters is
-- inside them — a table grant here would be a second door with no such check.

REVOKE ALL ON central_admins, directory_bans, directory_reports
  FROM anon, authenticated;

GRANT EXECUTE ON FUNCTION is_central_admin() TO authenticated;

GRANT EXECUTE ON FUNCTION report_listing(TEXT, UUID, TEXT, TEXT) TO authenticated;

GRANT EXECUTE ON FUNCTION moderation_queue()  TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_hidden() TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_bans()   TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_set_hidden(TEXT, UUID, BOOLEAN, TEXT)
  TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_dismiss(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_set_banned(UUID, BOOLEAN, TEXT)
  TO authenticated;

DROP POLICY IF EXISTS device_tokens_own ON device_tokens;
CREATE POLICY device_tokens_own ON device_tokens FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON device_tokens FROM anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON device_tokens TO authenticated;

REVOKE ALL ON push_config FROM anon, authenticated;

DROP POLICY IF EXISTS push_relays_own_read ON push_relays;
CREATE POLICY push_relays_own_read ON push_relays FOR SELECT TO authenticated
  USING (owner_id = auth.uid());

DROP POLICY IF EXISTS push_relays_own_delete ON push_relays;
CREATE POLICY push_relays_own_delete ON push_relays FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

REVOKE ALL ON push_relays FROM anon, authenticated;

GRANT SELECT (id, created_at, supabase_url, server_id, label, is_disabled)
  ON push_relays TO authenticated;

GRANT DELETE ON push_relays TO authenticated;

REVOKE ALL ON FUNCTION enroll_push_relay(TEXT, UUID, TEXT) FROM public;

GRANT EXECUTE ON FUNCTION enroll_push_relay(TEXT, UUID, TEXT) TO authenticated;

-- The service role only — this is `push_send`'s, and a client holding a secret
-- has no business spending it directly.
REVOKE ALL ON FUNCTION claim_relay_push(UUID, TEXT, INTEGER) FROM public, anon, authenticated;

DROP POLICY IF EXISTS notification_prefs_own ON notification_prefs;
CREATE POLICY notification_prefs_own ON notification_prefs FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON notification_prefs FROM anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO authenticated;

REVOKE ALL ON FUNCTION notify_level_for(UUID, public.notify_scope, UUID)
  FROM public, anon, authenticated;

-- ============================================================
-- 3. Grants and RLS
-- ============================================================
-- Reads are own-row; every write goes through an RPC below. There is no
-- INSERT/UPDATE/DELETE grant on either table at all, because every state
-- change here has a rule attached — a request may not be accepted by the
-- person who sent it, a block has to tear the friendship down with it — and a
-- rule that lives in a policy has to be re-derived by every policy that reads
-- the table afterwards.

-- `authenticated` has to be named here, and not just `anon`. Supabase ships
-- `ALTER DEFAULT PRIVILEGES ... GRANT ALL ON TABLES TO anon, authenticated`,
-- so a table created in this schema arrives with `arwdDxtm` for both — the
-- first version of this file revoked only `anon` and left `authenticated`
-- holding INSERT, UPDATE and DELETE on the whole friends graph. Nothing got
-- through, because RLS with no write policy denies by default, but "denied by
-- the absence of a policy" is one layer where this file claims two.
REVOKE ALL ON friendships FROM public, anon, authenticated;

REVOKE ALL ON blocks      FROM public, anon, authenticated;

GRANT SELECT ON friendships TO authenticated;

GRANT SELECT ON blocks      TO authenticated;

DROP POLICY IF EXISTS friendships_select_own ON friendships;
CREATE POLICY friendships_select_own ON friendships FOR SELECT TO authenticated
  USING (auth.uid() IN (low_id, high_id));

DROP POLICY IF EXISTS blocks_select_own ON blocks;
CREATE POLICY blocks_select_own ON blocks FOR SELECT TO authenticated
  USING (blocker_id = auth.uid());

DROP POLICY IF EXISTS users_select_directory ON users;
CREATE POLICY users_select_directory ON users FOR SELECT TO authenticated
  USING (id = auth.uid() OR knows_user(id));

-- ============================================================
-- 10. Function privileges
-- ============================================================
-- EXECUTE is revoked from everything below before any of it is granted, so a
-- function is unreachable until it is named. Two are deliberately not named:
-- `are_friends` is the ring
-- trigger's, and answers about a pair neither of whom need be the caller;
-- `_friend_bucket` would answer for any account passed to it.
--
-- `knows_user` *is* named, because the directory policy is made of it — see
-- section 2 for why that is safe and why it is not optional.

-- Revoked from everybody first, including PUBLIC, and this file runs last for
-- exactly that reason. A blanket `REVOKE ALL ON ALL FUNCTIONS` only covers
-- what exists when it runs, and `ALTER DEFAULT PRIVILEGES ... REVOKE` does not
-- cover the rest: revoking from a default that holds no explicit grant is a
-- no-op, so `pg_default_acl` stays empty and every later function keeps
-- Supabase's own default of EXECUTE for `anon` and `authenticated`. Naming
-- each one is the difference between safe and safe on purpose.
REVOKE ALL ON FUNCTION are_friends(UUID, UUID)               FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION knows_user(UUID)                      FROM public, anon;

REVOKE ALL ON FUNCTION friendship_state(UUID)                FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION friend_request(UUID)                  FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION friend_request_by_handle(TEXT)        FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION respond_friend_request(UUID, BOOLEAN) FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION unfriend(UUID)                        FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION block_user(UUID)                      FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION unblock_user(UUID)                    FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION directory_profiles(UUID[])            FROM public, anon, authenticated;

GRANT EXECUTE ON FUNCTION knows_user(UUID)                   TO authenticated;

GRANT EXECUTE ON FUNCTION friendship_state(UUID)             TO authenticated;

GRANT EXECUTE ON FUNCTION friend_request(UUID)               TO authenticated;

GRANT EXECUTE ON FUNCTION friend_request_by_handle(TEXT)     TO authenticated;

GRANT EXECUTE ON FUNCTION respond_friend_request(UUID, BOOLEAN) TO authenticated;

GRANT EXECUTE ON FUNCTION unfriend(UUID)                     TO authenticated;

GRANT EXECUTE ON FUNCTION block_user(UUID)                   TO authenticated;

GRANT EXECUTE ON FUNCTION unblock_user(UUID)                 TO authenticated;

GRANT EXECUTE ON FUNCTION directory_profiles(UUID[])         TO authenticated;

GRANT EXECUTE ON FUNCTION send_dm(UUID, TEXT, TEXT, TEXT, INTEGER) TO authenticated;

GRANT EXECUTE ON FUNCTION set_pinned(BIGINT, BOOLEAN) TO authenticated;

-- ============================================================
-- 5. Privileges
-- ============================================================

REVOKE ALL ON FUNCTION app_friend_state(UUID)                  FROM public, anon;

REVOKE ALL ON FUNCTION friend_counts()                         FROM public, anon;

REVOKE ALL ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER)      FROM public, anon;

GRANT EXECUTE ON FUNCTION app_friend_state(UUID)               TO authenticated;

GRANT EXECUTE ON FUNCTION friend_counts()                      TO authenticated;

GRANT EXECUTE ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER)   TO authenticated;

-- ============================================================
-- A listing must be asked for by an admin
-- ============================================================
-- `publish_server` checked three things: that the caller was signed in, that
-- they had a profile, and that they were not colliding with somebody else's
-- listing. It did not check — and could not — that they administer the server
-- they were listing.
--
-- Central has never heard of a self-hosted database and shares no identity
-- with it: a member signs in there with a key derived on their device, and
-- here with a Rift account, and nothing links the two. So any signed-in
-- account holding a server's URL, id and an invite code could list it. Every
-- *member* of a server holds all three.
--
-- Three things that bought an attacker, in order of how bad they are:
--
--   1. A private server published to the directory with a working join link.
--   2. The listing squatted — (supabase_url, server_id) is unique, so the
--      first claimant holds the only slot and the real admin is refused with
--      `listing_owned_by_another_account` forever.
--   3. A description and tags of the squatter's choosing, under the server's
--      name.
--
-- Push relays meet the same wall and answer it differently: they drop the
-- uniqueness, so squatting a *credential* is harmless. That works
-- there because a relay credential is useless without its secret. A listing is
-- not — it is public, and being the only one is the point.
--
-- The fix is that central asks the server. An admin gets a one-time token from
-- their own server, central redeems it against
-- that server's domain, and only then writes the row. It binds a listing to
-- domain control, which is the one thing central can actually verify.
--
-- The check runs in the `publish_server` edge function, because it needs an
-- HTTP call. What this migration does is make that function the *only* way in.

-- ---------- who may publish ----------
-- The service role's, and nobody else's — revoked with the rest of the
-- directory's functions above. The RPC still owns the cap, the ownership rule
-- and the upsert; it simply cannot be called by the person it is deciding
-- about.

REVOKE ALL ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                         TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION is_handle_available(TEXT) FROM public;

GRANT EXECUTE ON FUNCTION is_handle_available(TEXT) TO anon, authenticated;

-- The edge function reaches it through PostgREST with the service key. Nobody
-- else has a use for a list of other people's blob names.
REVOKE ALL ON FUNCTION expired_dm_attachments(INTEGER) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION expired_dm_attachments(INTEGER) TO service_role;

REVOKE ALL ON attachment_sweep_config FROM anon, authenticated;

REVOKE ALL ON FUNCTION request_attachment_sweep() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION tell_user(UUID, TEXT, JSONB) FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION announce_dm()         FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION announce_prefs()      FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION announce_friendship() FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION announce_block()      FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION can_join_topic(TEXT) FROM public, anon;

GRANT EXECUTE ON FUNCTION can_join_topic(TEXT) TO authenticated;

REVOKE ALL ON dm_conversation_heads FROM anon, authenticated;

REVOKE ALL ON FUNCTION remember_dm_head() FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION forget_dm_head() FROM public, anon, authenticated;

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) FROM public, anon;

GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) TO authenticated;

REVOKE ALL ON FUNCTION unread_counts() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;

-- ============================================================
-- 2. Row-level security
-- ============================================================

ALTER TABLE users                ENABLE ROW LEVEL SECURITY;

ALTER TABLE dm_messages          ENABLE ROW LEVEL SECURITY;

ALTER TABLE dm_message_pins      ENABLE ROW LEVEL SECURITY;

ALTER TABLE read_state           ENABLE ROW LEVEL SECURITY;

ALTER TABLE public_servers ENABLE ROW LEVEL SECURITY;

ALTER TABLE public_bots ENABLE ROW LEVEL SECURITY;

ALTER TABLE bot_likes   ENABLE ROW LEVEL SECURITY;

-- No policies on these three, so RLS alone refuses every direct read and
-- write; the moderation functions reach them as definer.
ALTER TABLE central_admins    ENABLE ROW LEVEL SECURITY;

ALTER TABLE directory_bans    ENABLE ROW LEVEL SECURITY;

ALTER TABLE directory_reports ENABLE ROW LEVEL SECURITY;

ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE push_config ENABLE ROW LEVEL SECURITY;

ALTER TABLE push_relays ENABLE ROW LEVEL SECURITY;

ALTER TABLE notification_prefs ENABLE ROW LEVEL SECURITY;

ALTER TABLE friendships ENABLE ROW LEVEL SECURITY;

ALTER TABLE blocks      ENABLE ROW LEVEL SECURITY;

ALTER TABLE attachment_sweep_config ENABLE ROW LEVEL SECURITY;

-- Nobody reaches this directly. `dm_conversations` is SECURITY DEFINER and is
-- the only reader; a client that could read it could read who talks to whom.
ALTER TABLE dm_conversation_heads ENABLE ROW LEVEL SECURITY;

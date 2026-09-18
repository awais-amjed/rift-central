-- ============================================================
-- Rift central server — policy tests
-- ============================================================
-- Central was always meant to be reached directly by clients, so its rules have
-- always been policies rather than endpoint code. That makes them the *only*
-- thing standing between one account and another's messages, and worth the same
-- suite as the self-hosted side.
--
-- Run against the central project via the Management API (see LOCAL_DEV), or
-- against any database with 001–005 applied:
--
--   psql "$CENTRAL_URL" -v ON_ERROR_STOP=1 \
--     -f central_server_migrations/tests/policies_test.sql
--
-- One transaction, always rolled back: it writes nothing, so it is safe to run
-- against the live project. A failure raises, aborting the transaction.

\set ON_ERROR_STOP on
BEGIN;

-- ── Fixtures ────────────────────────────────────────────────
--   alice and bob have accounts; carol has an auth row but never claimed a
--   handle, which is how "no profile" is testable. Dave is a second unclaimed
--   account, because claiming one is itself a test and carol has to stay
--   profile-less for the send_dm case below.

INSERT INTO auth.users (id) VALUES
  ('cccc0000-0000-4000-8000-000000000001'),  -- alice
  ('cccc0000-0000-4000-8000-000000000002'),  -- bob
  ('cccc0000-0000-4000-8000-000000000003'),  -- carol (no profile, stays that way)
  ('cccc0000-0000-4000-8000-000000000004');  -- dave  (claims one below)

INSERT INTO users (id, handle, chat_public_key, signing_public_key) VALUES
  ('cccc0000-0000-4000-8000-000000000001', 'alice_test', 'chat-alice', 'sign-alice'),
  ('cccc0000-0000-4000-8000-000000000002', 'bob_test',   'chat-bob',   'sign-bob');

INSERT INTO dm_messages (id, sender_id, recipient_id, ciphertext, nonce, signature, key_version)
VALUES (7001, 'cccc0000-0000-4000-8000-000000000002',
              'cccc0000-0000-4000-8000-000000000001', 'from-bob', 'n', 's', 1);

-- Alice and bob are friends, and since 012 that is a *precondition* for the
-- message above rather than a consequence of it: `send_dm` refuses anything
-- between accounts that are not friends, so a fixture with a conversation in
-- it and no friendship behind it is a state the server would never produce.
-- Bob asked, which is consistent with bob having sent the first message.
INSERT INTO friendships (low_id, high_id, requester_id, status) VALUES
  ('cccc0000-0000-4000-8000-000000000001',
   'cccc0000-0000-4000-8000-000000000002',
   'cccc0000-0000-4000-8000-000000000002', 'accepted');

-- ============================================================
-- 1. The unauthenticated role
-- ============================================================

SET LOCAL ROLE anon;

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','dm_messages','read_state','public_servers']
  LOOP
    BEGIN
      EXECUTE format('SELECT 1 FROM %I LIMIT 1', t);
      RAISE EXCEPTION 'FAIL: anon can SELECT %', t;
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
  END LOOP;
  RAISE NOTICE 'ok  anon cannot read any table';
END $$;

RESET ROLE;

-- ============================================================
-- 2. The directory
-- ============================================================
-- It stopped being a directory in 012. `users` used to be readable row-by-row
-- by every signed-in account — "you cannot message someone you cannot find" —
-- and that turned out to mean the whole membership was enumerable by anyone
-- who had signed up. Now you may read your own row and the rows of people you
-- have a standing relationship with; a handle becomes a person only through
-- `friend_request_by_handle`, which asks in the same statement it resolves.
--
-- The stranger half of that is asserted below, once dave has a handle to be a
-- stranger with. What must still not be writable is someone else's row.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Bob: a friend, with a conversation. Both halves of `knows_user` are true
  -- for him, and either alone has to be enough — see section 8.
  IF NOT EXISTS (SELECT 1 FROM users WHERE handle = 'bob_test') THEN
    RAISE EXCEPTION 'FAIL: a friend''s directory row is not readable';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: an account cannot read its own directory row';
  END IF;

  UPDATE users SET handle = 'stolen' WHERE id = 'cccc0000-0000-4000-8000-000000000002';
  IF EXISTS (SELECT 1 FROM users WHERE handle = 'stolen') THEN
    RAISE EXCEPTION 'FAIL: an account rewrote someone else''s handle';
  END IF;

  BEGIN
    INSERT INTO users (id, handle, chat_public_key, signing_public_key)
    VALUES ('cccc0000-0000-4000-8000-000000000003', 'impostor', 'c', 's');
    RAISE EXCEPTION 'FAIL: an account created a profile for someone else';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  the directory is relationship-scoped to read, own-row to write';
END $$;

-- Claiming, the way the client actually does it. This is a regression test:
-- the client used to upsert the table directly and PostgREST put `id` into the
-- DO UPDATE clause, which the column grant doesn't cover — so every first
-- claim died with "permission denied for table users", policies never
-- consulted. The grants are right; the statement was wrong.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000004","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Dave has an auth row and no profile: the first-claim case.
  PERFORM claim_handle('dave_test', 'chat-dave', 'sign-dave');
  IF NOT EXISTS (
    SELECT 1 FROM users WHERE id = auth.uid() AND handle = 'dave_test'
  ) THEN
    RAISE EXCEPTION 'FAIL: claiming a handle did not create the row';
  END IF;

  -- And again, which is the path a re-login takes.
  PERFORM claim_handle('dave_two', 'chat-dave-2', 'sign-dave-2');
  IF NOT EXISTS (
    SELECT 1 FROM users
     WHERE id = auth.uid() AND handle = 'dave_two' AND chat_public_key = 'chat-dave-2'
  ) THEN
    RAISE EXCEPTION 'FAIL: re-claiming did not refresh the row';
  END IF;

  BEGIN
    PERFORM claim_handle('alice_test', 'c', 's');
    RAISE EXCEPTION 'FAIL: a taken handle was claimed twice';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;

  BEGIN
    PERFORM claim_handle('No Spaces', 'c', 's');
    RAISE EXCEPTION 'FAIL: a malformed handle was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  RAISE NOTICE 'ok  claiming a handle works on the first try, and stays yours';
END $$;

-- Dave now has a handle and no relationship with anybody. He is the stranger
-- case, and this is the assertion that ends handle search: alice cannot see
-- his row, cannot find it by handle, and cannot find it by walking the table.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_rows INT;
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE handle = 'dave_two') THEN
    RAISE EXCEPTION 'FAIL: a stranger''s handle is still findable';
  END IF;
  IF EXISTS (SELECT 1 FROM users WHERE handle LIKE 'dav%') THEN
    RAISE EXCEPTION 'FAIL: a stranger is still reachable by prefix search';
  END IF;

  -- The whole table, which is what a client with a REST key would ask for.
  -- Alice knows exactly two rows: her own, and bob's.
  SELECT count(*) INTO v_rows FROM users;
  IF v_rows <> 2 THEN
    RAISE EXCEPTION 'FAIL: the directory returned % rows, not just the two alice knows', v_rows;
  END IF;
  RAISE NOTICE 'ok  a stranger cannot be found, by handle or by listing';
END $$;

-- The cursor write goes through mark_read for the same reason, and the RPC
-- carries a rule the upsert didn't: cursors only move forward.

DO $$
DECLARE v BIGINT;
BEGIN
  v := mark_read('dm', 'cccc0000-0000-4000-8000-000000000001', 9);
  IF v <> 9 THEN
    RAISE EXCEPTION 'FAIL: the cursor did not land on the id asked for';
  END IF;

  v := mark_read('dm', 'cccc0000-0000-4000-8000-000000000001', 4);
  IF v <> 9 THEN
    RAISE EXCEPTION 'FAIL: a late call walked the cursor backwards';
  END IF;
  RAISE NOTICE 'ok  marking read creates the cursor and only moves it forward';
END $$;

-- ============================================================
-- 3. Conversations
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'from-bob') THEN
    RAISE EXCEPTION 'FAIL: a participant cannot read their own conversation';
  END IF;
  RAISE NOTICE 'ok  a participant reads their own conversation';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM dm_messages) THEN
    RAISE EXCEPTION 'FAIL: a third account can read a conversation it is not in';
  END IF;
  RAISE NOTICE 'ok  a conversation is visible only to its two participants';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- There is no INSERT grant at all: every new message goes through send_dm(),
  -- which is where the daily quota lives. Without this, the funnel limit that
  -- keeps central affordable would be optional.
  BEGIN
    INSERT INTO dm_messages (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
    VALUES (auth.uid(), 'cccc0000-0000-4000-8000-000000000001', 'bypass', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a message was inserted without going through send_dm';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  sending is only possible through send_dm (quota enforced)';
END $$;

DO $$
DECLARE v JSONB;
BEGIN
  v := send_dm('cccc0000-0000-4000-8000-000000000001', 'sealed', 'n', 's', 1);
  IF (v->>'id') IS NULL THEN
    RAISE EXCEPTION 'FAIL: send_dm returned no id';
  END IF;
  IF (v->>'remaining')::INT >= (v->>'quota')::INT THEN
    RAISE EXCEPTION 'FAIL: send_dm did not decrement the quota meter';
  END IF;

  BEGIN
    PERFORM send_dm(auth.uid(), 'self', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: an account can DM itself';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'cannot_dm_self' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000003', 'x', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a message was accepted for an account with no profile';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'recipient_has_no_profile' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000001', repeat('x', 16385), 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: an oversized envelope was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'envelope_invalid' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  send_dm validates the envelope, the recipient and the quota';
END $$;

DO $$
DECLARE v_id BIGINT; v_sender UUID; v_at TIMESTAMPTZ; v_before TIMESTAMPTZ;
BEGIN
  SELECT id, created_at INTO v_id, v_before FROM dm_messages WHERE ciphertext = 'sealed';

  -- Two layers guard an edit, and both are worth asserting. First the column
  -- grant: identity and send time are not columns a member may write at all,
  -- so this is refused before any policy or trigger is consulted.
  BEGIN
    UPDATE dm_messages SET sender_id = 'cccc0000-0000-4000-8000-000000000001'
     WHERE id = v_id;
    RAISE EXCEPTION 'FAIL: an edit reassigned the sender';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE dm_messages SET created_at = '2020-01-01T00:00:00Z' WHERE id = v_id;
    RAISE EXCEPTION 'FAIL: an edit backdated the message';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  -- edited_at is the trigger's to stamp, not the author's to choose. Naming it
  -- refuses the whole update, envelope included — the app once sent it with
  -- every edit, and every central DM edit failed.
  BEGIN
    UPDATE dm_messages SET ciphertext = 'hidden edit', edited_at = NULL WHERE id = v_id;
    RAISE EXCEPTION 'FAIL: an edit chose its own edited_at';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Then the trigger, for the columns that *are* writable: it pins everything
  -- else to its old value and stamps edited_at itself.
  UPDATE dm_messages SET ciphertext = 'edited' WHERE id = v_id;
  SELECT sender_id, created_at INTO v_sender, v_at FROM dm_messages WHERE id = v_id;

  IF v_sender <> 'cccc0000-0000-4000-8000-000000000002' THEN
    RAISE EXCEPTION 'FAIL: the sender changed under an envelope edit';
  END IF;
  IF v_at <> v_before THEN
    RAISE EXCEPTION 'FAIL: created_at moved under an envelope edit';
  END IF;
  IF (SELECT edited_at FROM dm_messages WHERE id = v_id) IS NULL THEN
    RAISE EXCEPTION 'FAIL: edited_at was not stamped';
  END IF;
  RAISE NOTICE 'ok  an edit changes the envelope and nothing else';
END $$;

DO $$
BEGIN
  -- 7001 is bob's message. Alice is its recipient, and deleting it is not hers
  -- to do — a hard delete removes it for both sides.
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true);
  DELETE FROM dm_messages WHERE id = 7001;
  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE id = 7001) THEN
    RAISE EXCEPTION 'FAIL: the recipient deleted the sender''s message';
  END IF;
  RAISE NOTICE 'ok  only the sender can delete a message';
END $$;

-- ============================================================
-- 5. Read state and unread counts
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_n INT; v_cursor BIGINT;
BEGIN
  v_n := (unread_counts()->'dms'->>'cccc0000-0000-4000-8000-000000000002')::INT;
  IF v_n IS NULL OR v_n < 1 THEN
    RAISE EXCEPTION 'FAIL: bob''s messages are not counted as unread for alice';
  END IF;

  v_cursor := mark_read('dm', 'cccc0000-0000-4000-8000-000000000002');
  IF (unread_counts()->'dms') ? 'cccc0000-0000-4000-8000-000000000002' THEN
    RAISE EXCEPTION 'FAIL: the conversation is still unread after mark_read';
  END IF;

  IF mark_read('dm', 'cccc0000-0000-4000-8000-000000000002', 1) <> v_cursor THEN
    RAISE EXCEPTION 'FAIL: mark_read moved a cursor backwards';
  END IF;
  RAISE NOTICE 'ok  unread counts follow the cursor, which only moves forward';
END $$;

DO $$
BEGIN
  -- Own-row only, which is also what keeps this from being a read receipt.
  IF EXISTS (SELECT 1 FROM read_state WHERE user_id <> auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: an account can read someone else''s cursors';
  END IF;
  BEGIN
    INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
    VALUES ('cccc0000-0000-4000-8000-000000000002', 'dm', auth.uid(), 99);
    RAISE EXCEPTION 'FAIL: an account can write someone else''s cursor';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  a sender can never see whether their message was read';
END $$;

-- ============================================================
-- 6. Conversation list
-- ============================================================

DO $$
DECLARE
  v    JSONB;
  rows JSONB;
BEGIN
  v := dm_conversations();
  rows := v->'conversations';
  IF jsonb_array_length(rows) <> 1 THEN
    RAISE EXCEPTION 'FAIL: expected one conversation, got %',
      jsonb_array_length(rows);
  END IF;
  IF (rows->0->>'handle') <> 'bob_test' THEN
    RAISE EXCEPTION 'FAIL: the conversation is not resolved against the directory';
  END IF;
  IF (rows->0->'last_message'->>'ciphertext') IS NULL THEN
    RAISE EXCEPTION 'FAIL: the conversation carries no envelope to preview';
  END IF;
  IF (v->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: one conversation was reported as a partial page';
  END IF;
  RAISE NOTICE 'ok  dm_conversations returns one entry per peer, newest first';
END $$;

-- The row carries everything it draws, which is the point of 013: the badge,
-- the cursor a read writes back, and how much this person may interrupt. Each
-- of those used to be a separate unbounded read of a table with one row per
-- conversation, scanned on the client.
--
-- Section 5 left alice caught up, so a fresh message from bob is what gives
-- this something to count.
--
-- Inserted with bob's claim in force, because `dm_messages_stamp_sender`
-- overwrites `sender_id` with `auth.uid()` whatever the row says — which is
-- the point of that trigger and worth not fighting.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true); END $$;
RESET ROLE;
INSERT INTO dm_messages (id, sender_id, recipient_id, ciphertext, nonce,
                         signature, key_version)
VALUES (7100, 'cccc0000-0000-4000-8000-000000000002',
        'cccc0000-0000-4000-8000-000000000001',
        'newer', 'n', 's', 1);
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_row JSONB;
BEGIN
  v_row := dm_conversations()->'conversations'->0;

  IF (v_row->>'unread')::INT <> 1 THEN
    RAISE EXCEPTION 'FAIL: expected one unread, got %', v_row->>'unread';
  END IF;
  IF (v_row->>'latest_inbound')::BIGINT <> 7100 THEN
    RAISE EXCEPTION 'FAIL: the cursor to write back is %',
      v_row->>'latest_inbound';
  END IF;
  -- The newest envelope is the one just sent, or the preview is stale.
  IF (v_row->'last_message'->>'id')::BIGINT <> 7100 THEN
    RAISE EXCEPTION 'FAIL: the preview is not the newest message';
  END IF;
  -- Present and null: null is "the default", which the client names. A missing
  -- key would mean the level was never asked for at all.
  IF NOT (v_row ? 'level') THEN
    RAISE EXCEPTION 'FAIL: the notification level is missing entirely';
  END IF;
  RAISE NOTICE 'ok  and carries the badge, the cursor and the level with it';
END $$;

-- And the cursor it hands back is the one that clears the badge — they have to
-- come from the same read, or marking read would skip whatever arrived between
-- two calls.
DO $$
DECLARE v_row JSONB;
BEGIN
  PERFORM mark_read('dm'::read_scope,
                    'cccc0000-0000-4000-8000-000000000002',
                    (dm_conversations()->'conversations'->0->>'latest_inbound')::BIGINT);
  v_row := dm_conversations()->'conversations'->0;
  IF (v_row->>'unread')::INT <> 0 THEN
    RAISE EXCEPTION 'FAIL: reading it left % unread', v_row->>'unread';
  END IF;
  RAISE NOTICE 'ok  and the cursor it hands back is the one that clears it';
END $$;

-- ============================================================
-- 7. The public server directory
-- ============================================================
-- A listing is the one thing here that is meant to be read by strangers, so
-- what these check is the opposite of everywhere else: that it *is* visible,
-- and that visibility still stops at writing.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v public_servers;
BEGIN
  v := publish_server('https://alpha.supabase.co',
                      'aaaa0000-0000-4000-8000-000000000001',
                      'invite-alpha', '  Alpha  ', 'A place', NULL,
                      ARRAY['gaming','tech'], 12, TRUE);
  IF v.owner_id <> auth.uid() THEN
    RAISE EXCEPTION 'FAIL: the listing was not bound to the caller';
  END IF;
  IF v.name <> 'Alpha' THEN
    RAISE EXCEPTION 'FAIL: the name was stored unbtrimmed';
  END IF;

  -- Re-publishing the same server edits rather than duplicating: it is the
  -- same server, and the admin has to be able to change the description.
  v := publish_server('https://alpha.supabase.co',
                      'aaaa0000-0000-4000-8000-000000000001',
                      'invite-alpha-2', 'Alpha', 'Edited', NULL,
                      ARRAY['gaming'], 13, TRUE);
  IF (SELECT count(*) FROM public_servers) <> 1 THEN
    RAISE EXCEPTION 'FAIL: re-publishing created a second listing';
  END IF;
  IF v.invite_code <> 'invite-alpha-2' OR v.member_count <> 13 THEN
    RAISE EXCEPTION 'FAIL: re-publishing did not update the row';
  END IF;

  BEGIN
    PERFORM publish_server('https://alpha.supabase.co',
                           'aaaa0000-0000-4000-8000-000000000002',
                           'c', 'Bad tags', NULL, NULL,
                           ARRAY['Not A Tag'], 0, TRUE);
    RAISE EXCEPTION 'FAIL: a malformed tag was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  -- Delisted, not deleted: still the owner's row, out of everyone's browse.
  PERFORM publish_server('https://beta.supabase.co',
                         'aaaa0000-0000-4000-8000-000000000003',
                         'invite-beta', 'Beta', NULL, NULL, '{}', 3, FALSE);
  RAISE NOTICE 'ok  publishing creates one listing per (host, server) and edits it after';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public_servers WHERE name = 'Alpha') THEN
    RAISE EXCEPTION 'FAIL: a listed server is not visible to another account';
  END IF;
  IF EXISTS (SELECT 1 FROM public_servers WHERE name = 'Beta') THEN
    RAISE EXCEPTION 'FAIL: a delisted server is visible to another account';
  END IF;

  -- No INSERT or UPDATE grant at all: publish_server is the only way in, which
  -- is what makes the per-account cap and the ownership check unavoidable.
  BEGIN
    INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code, name)
    VALUES (auth.uid(), 'https://gamma.supabase.co',
            'aaaa0000-0000-4000-8000-000000000004', 'c', 'Gamma');
    RAISE EXCEPTION 'FAIL: a listing was inserted without going through publish_server';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    UPDATE public_servers SET name = 'Hijacked' WHERE name = 'Alpha';
    RAISE EXCEPTION 'FAIL: a listing was updated directly';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Deleting is a plain policy-checked write, and the policy is own-row.
  DELETE FROM public_servers WHERE name = 'Alpha';
  IF NOT EXISTS (SELECT 1 FROM public_servers WHERE name = 'Alpha') THEN
    RAISE EXCEPTION 'FAIL: an account withdrew someone else''s listing';
  END IF;

  -- Central cannot verify that anyone is an admin of a server it has never
  -- heard of, so the first account to publish a (host, server) owns the
  -- listing. What it must not do is let the second one take it over.
  BEGIN
    PERFORM publish_server('https://alpha.supabase.co',
                           'aaaa0000-0000-4000-8000-000000000001',
                           'squatted', 'Alpha', NULL, NULL, '{}', 0, TRUE);
    RAISE EXCEPTION 'FAIL: a second account repointed an existing listing';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'listing_owned_by_another_account' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a listing is public to read, and only its owner can change it';
END $$;

DO $$
DECLARE i INTEGER;
BEGIN
  FOR i IN 1..max_public_servers() LOOP
    PERFORM publish_server('https://n' || i || '.supabase.co',
                           gen_random_uuid(), 'code', 'S' || i,
                           NULL, NULL, '{}', 0, TRUE);
  END LOOP;

  BEGIN
    PERFORM publish_server('https://over.supabase.co', gen_random_uuid(),
                           'code', 'One too many', NULL, NULL, '{}', 0, TRUE);
    RAISE EXCEPTION 'FAIL: an account listed more servers than the cap allows';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'listing_cap_reached' THEN RAISE; END IF;
  END;

  -- The cap counts listings, not saves: editing one you already hold at the
  -- cap must still work, or an account at ten servers could never fix a typo.
  PERFORM publish_server('https://n1.supabase.co',
                         (SELECT server_id FROM public_servers
                           WHERE supabase_url = 'https://n1.supabase.co'),
                         'code', 'S1 renamed', NULL, NULL, '{}', 1, TRUE);
  RAISE NOTICE 'ok  the per-account cap bounds new listings without freezing old ones';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Carol has an auth row and never claimed a handle. A listing is owned by an
  -- account, and an account here is its directory row.
  BEGIN
    PERFORM publish_server('https://carol.supabase.co', gen_random_uuid(),
                           'code', 'Carols', NULL, NULL, '{}', 0, TRUE);
    RAISE EXCEPTION 'FAIL: an account with no profile published a listing';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'owner_has_no_profile' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  publishing requires an account with a claimed handle';
END $$;


-- ============================================================
-- 8. Friends, requests and blocks
-- ============================================================
-- The gate added in 012. Its one sentence is "you cannot send anything to
-- somebody who is not your friend", and most of what follows is that sentence
-- checked from the angles a client could otherwise get wrong: the side that
-- asked cannot answer, a withdrawn request buys nothing, a block is silent
-- from the side it lands on, and none of it is reachable by writing to a table
-- directly.
--
-- Alice and bob arrive here as friends (see the fixtures). Dave arrives as a
-- stranger with a handle, which is what makes him useful.

-- ---------- a stranger is unreachable, in both senses ----------

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF friendship_state('cccc0000-0000-4000-8000-000000000004') <> 'none' THEN
    RAISE EXCEPTION 'FAIL: alice and dave are not strangers to begin with';
  END IF;

  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000004', 'hi', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a stranger was messaged';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a stranger cannot be sent anything at all';
END $$;

-- ---------- a handle becomes a person, and only this way ----------
-- The lookup and the request are one statement on purpose: an RPC that merely
-- resolved a handle to an id would be the enumeration this migration removes,
-- minus the typing. Every successful resolution costs the caller a visible row
-- in somebody's Pending list.

DO $$
DECLARE v JSONB;
BEGIN
  -- Case, and surrounding whitespace, are the user's typing rather than their
  -- intent. Handles are lowercase by the column's own CHECK.
  v := friend_request_by_handle('  DAVE_TWO  ');
  IF (v->>'state') <> 'outgoing' THEN
    RAISE EXCEPTION 'FAIL: asking a stranger did not create an outgoing request, got %', v;
  END IF;
  IF (v->>'handle') <> 'dave_two' THEN
    RAISE EXCEPTION 'FAIL: the request did not answer with the handle it resolved';
  END IF;

  -- Asking twice is the same request, not two.
  IF (friend_request_by_handle('dave_two')->>'state') <> 'outgoing' THEN
    RAISE EXCEPTION 'FAIL: re-asking changed the state';
  END IF;
  IF (SELECT count(*) FROM friendships
       WHERE low_id  = LEAST(auth.uid(), 'cccc0000-0000-4000-8000-000000000004'::UUID)
         AND high_id = GREATEST(auth.uid(), 'cccc0000-0000-4000-8000-000000000004'::UUID)) <> 1 THEN
    RAISE EXCEPTION 'FAIL: asking twice made two rows';
  END IF;

  BEGIN
    PERFORM friend_request_by_handle('nobody_at_all');
    RAISE EXCEPTION 'FAIL: a handle nobody owns was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'no_such_user' THEN RAISE; END IF;
  END;

  -- Not a handle at all. Refused on shape, without touching the table.
  BEGIN
    PERFORM friend_request_by_handle('Not A Handle!');
    RAISE EXCEPTION 'FAIL: a malformed handle reached the directory';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'no_such_user' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM friend_request_by_handle('alice_test');
    RAISE EXCEPTION 'FAIL: an account befriended itself';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'cannot_friend_self' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a full handle sends a request; anything else sends nothing';
END $$;

-- ---------- a pending request carries nothing ----------
-- This is the hole the first version of 012 left: the request *was* a message,
-- so withdrawing and asking again bought another one, over and over. Now the
-- allowance is zero on both sides of the withdraw.

DO $$
BEGIN
  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000004', 'while you decide', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a pending request let a message through';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;

  PERFORM unfriend('cccc0000-0000-4000-8000-000000000004');   -- withdraw
  PERFORM friend_request_by_handle('dave_two');               -- and ask again

  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000004', 'second go', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: withdraw-and-resend bought a message';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;

  IF EXISTS (SELECT 1 FROM dm_messages
              WHERE recipient_id = 'cccc0000-0000-4000-8000-000000000004') THEN
    RAISE EXCEPTION 'FAIL: dave received something before accepting anything';
  END IF;
  RAISE NOTICE 'ok  withdrawing and re-asking delivers nothing, however often';
END $$;

-- ---------- the requester cannot answer their own request ----------

DO $$
BEGIN
  BEGIN
    PERFORM respond_friend_request('cccc0000-0000-4000-8000-000000000004', TRUE);
    RAISE EXCEPTION 'FAIL: the requester accepted their own request';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_your_request' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a request is answered by the side that did not send it';
END $$;

-- ---------- but the pending peer can be seen, and only the pending peer ----------
-- A request has to put a handle in front of the person deciding, or Pending is
-- a list of UUIDs. That is `knows_user`'s friendship half, and it is why the
-- directory predicate is "any relationship" rather than "accepted".

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000004","role":"authenticated"}', true); END $$;

DO $$
DECLARE v JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users WHERE handle = 'alice_test') THEN
    RAISE EXCEPTION 'FAIL: dave cannot see who is asking to be his friend';
  END IF;
  IF EXISTS (SELECT 1 FROM users WHERE handle = 'bob_test') THEN
    RAISE EXCEPTION 'FAIL: one request made the rest of the directory visible';
  END IF;

  v := friend_bucket('incoming');
  IF jsonb_array_length(v->'rows') <> 1 THEN
    RAISE EXCEPTION 'FAIL: the request is not in dave''s incoming list';
  END IF;
  IF (v->'rows'->0->>'handle') <> 'alice_test' THEN
    RAISE EXCEPTION 'FAIL: the incoming request has no handle on it';
  END IF;
  IF jsonb_array_length(friend_bucket('outgoing')->'rows') <> 0 THEN
    RAISE EXCEPTION 'FAIL: a received request was counted as sent';
  END IF;
  -- And the count agrees with the rows, since the badge is drawn from the
  -- count and the tab from the rows.
  IF (friend_counts()->>'incoming')::INT <> 1
     OR (friend_counts()->>'outgoing')::INT <> 0 THEN
    RAISE EXCEPTION 'FAIL: the counts disagree with the buckets: %', friend_counts();
  END IF;
  RAISE NOTICE 'ok  a request shows the asker''s handle, and nobody else''s';
END $$;

-- ---------- declining removes the request and only the request ----------

DO $$
BEGIN
  IF respond_friend_request('cccc0000-0000-4000-8000-000000000001', FALSE) <> 'none' THEN
    RAISE EXCEPTION 'FAIL: declining did not end in none';
  END IF;
  IF friendship_state('cccc0000-0000-4000-8000-000000000001') <> 'none' THEN
    RAISE EXCEPTION 'FAIL: the declined request is still standing';
  END IF;
  IF EXISTS (SELECT 1 FROM users WHERE handle = 'alice_test') THEN
    RAISE EXCEPTION 'FAIL: a declined asker is still visible in the directory';
  END IF;
  RAISE NOTICE 'ok  declining clears the row, and the asker goes back to being a stranger';
END $$;

-- ---------- accepting is the only thing that opens the composer ----------

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v JSONB;
BEGIN
  PERFORM friend_request_by_handle('dave_two');
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000004","role":"authenticated"}', true);
  IF respond_friend_request('cccc0000-0000-4000-8000-000000000001', TRUE) <> 'friends' THEN
    RAISE EXCEPTION 'FAIL: accepting did not end in friends';
  END IF;

  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true);
  v := send_dm('cccc0000-0000-4000-8000-000000000004', 'now we can talk', 'n', 's', 1);
  IF (v->>'state') <> 'friends' THEN
    RAISE EXCEPTION 'FAIL: a send between friends did not report friends';
  END IF;
  RAISE NOTICE 'ok  accepting, and nothing else, opens the composer';
END $$;

-- ---------- crossing requests collapse into a friendship ----------
-- Two people who ask each other at the same time have already agreed. A pair
-- with a request pending in both directions would be a state with no button
-- for it.

DO $$
BEGIN
  PERFORM unfriend('cccc0000-0000-4000-8000-000000000004');
  PERFORM friend_request_by_handle('dave_two');

  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000004","role":"authenticated"}', true);
  IF friend_request('cccc0000-0000-4000-8000-000000000001') <> 'friends' THEN
    RAISE EXCEPTION 'FAIL: asking back did not accept';
  END IF;
  RAISE NOTICE 'ok  asking somebody who has already asked you accepts instead';
END $$;

-- ---------- unfriending ends the relationship, not the history ----------

DO $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true);
  PERFORM unfriend('cccc0000-0000-4000-8000-000000000004');

  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'now we can talk') THEN
    RAISE EXCEPTION 'FAIL: unfriending deleted the conversation';
  END IF;
  -- Still readable, because the key that opens it is derived from a row this
  -- account must keep being able to fetch. A conversation is not something one
  -- of two people gets to erase from the other.
  IF NOT EXISTS (SELECT 1 FROM users WHERE handle = 'dave_two') THEN
    RAISE EXCEPTION 'FAIL: unfriending made the peer''s keys unreadable';
  END IF;
  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000004', 'one more', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: an ex-friend could still be messaged';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  unfriending closes the composer and keeps the history';
END $$;

-- ---------- blocking ----------
-- Three things at once: the relationship ends, the handle stops resolving, and
-- the person blocked is never told. The third is the one worth being careful
-- about — being told is an invitation to make a second account.

DO $$
DECLARE v JSONB;
BEGIN
  IF block_user('cccc0000-0000-4000-8000-000000000002') <> 'blocked' THEN
    RAISE EXCEPTION 'FAIL: block_user did not report blocked';
  END IF;
  IF EXISTS (SELECT 1 FROM friendships
              WHERE low_id  = LEAST(auth.uid(), 'cccc0000-0000-4000-8000-000000000002'::UUID)
                AND high_id = GREATEST(auth.uid(), 'cccc0000-0000-4000-8000-000000000002'::UUID)) THEN
    RAISE EXCEPTION 'FAIL: a block left the friendship standing';
  END IF;

  BEGIN
    PERFORM friend_request_by_handle('bob_test');
    RAISE EXCEPTION 'FAIL: an account re-added somebody it had blocked without unblocking';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'blocked' THEN RAISE; END IF;
  END;

  -- The blocked account is still listed *by handle*, or it could not be
  -- unblocked. `friend_bucket` is SECURITY DEFINER for exactly this row.
  v := friend_bucket('blocked');
  IF jsonb_array_length(v->'rows') <> 1
     OR (v->'rows'->0->>'handle') <> 'bob_test' THEN
    RAISE EXCEPTION 'FAIL: the block list cannot name who is on it';
  END IF;
  -- And a blocked peer's conversation leaves the list, in the query rather
  -- than in the client — see section 9.
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(
               dm_conversations()->'conversations') c
              WHERE c->>'peer_id' = 'cccc0000-0000-4000-8000-000000000002') THEN
    RAISE EXCEPTION 'FAIL: a blocked peer is still in the conversation list';
  END IF;
  RAISE NOTICE 'ok  blocking ends the friendship and stays undoable';
END $$;

DO $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true);

  -- Bob is not told, and cannot find out.
  IF EXISTS (SELECT 1 FROM blocks) THEN
    RAISE EXCEPTION 'FAIL: the blocked account can read the block';
  END IF;
  IF friendship_state('cccc0000-0000-4000-8000-000000000001') <> 'none' THEN
    RAISE EXCEPTION 'FAIL: being blocked is distinguishable from being unfriended';
  END IF;

  -- Their old conversation still opens: blocking takes away reach, not the
  -- ability to read what was already said. The peer's row stays fetchable
  -- because the DM key is derived from the key published in it.
  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'from-bob') THEN
    RAISE EXCEPTION 'FAIL: a block deleted the conversation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE handle = 'alice_test') THEN
    RAISE EXCEPTION 'FAIL: a block made the blocker''s published keys unreadable';
  END IF;

  -- But the handle no longer resolves to anybody, which is what "cannot find
  -- you" has to mean — and it is refused with the sentence a handle nobody
  -- owns gets, not with one that says a block happened.
  BEGIN
    PERFORM friend_request_by_handle('alice_test');
    RAISE EXCEPTION 'FAIL: a blocked account could still send a request';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'blocked' THEN
      RAISE EXCEPTION 'FAIL: the refusal told the blocked account it was blocked';
    END IF;
    IF SQLERRM <> 'no_such_user' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000001', 'hello?', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a blocked account could still send a message';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a block is silent, and reads as a handle that never existed';
END $$;

-- ---------- unblocking restores reachability and nothing else ----------

DO $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true);
  PERFORM unblock_user('cccc0000-0000-4000-8000-000000000002');

  IF friendship_state('cccc0000-0000-4000-8000-000000000002') <> 'none' THEN
    RAISE EXCEPTION 'FAIL: unblocking restored the friendship';
  END IF;
  BEGIN
    PERFORM send_dm('cccc0000-0000-4000-8000-000000000002', 'back?', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: unblocking reopened the composer';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_friends' THEN RAISE; END IF;
  END;
  IF (friend_request_by_handle('bob_test')->>'state') <> 'outgoing' THEN
    RAISE EXCEPTION 'FAIL: unblocking did not restore reachability';
  END IF;
  RAISE NOTICE 'ok  unblocking makes two strangers, which is where they started';
END $$;

-- ---------- none of it is reachable by writing to the tables ----------
-- There is no INSERT, UPDATE or DELETE grant on either table, because every
-- change here carries a rule with it and a rule that lives in a policy has to
-- be re-derived by every policy that reads the table afterwards.

DO $$
BEGIN
  BEGIN
    UPDATE friendships SET status = 'accepted'
     WHERE auth.uid() IN (low_id, high_id);
    RAISE EXCEPTION 'FAIL: an account accepted a friendship by writing to the table';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    INSERT INTO friendships (low_id, high_id, requester_id, status)
    VALUES (LEAST(auth.uid(), 'cccc0000-0000-4000-8000-000000000004'::UUID),
            GREATEST(auth.uid(), 'cccc0000-0000-4000-8000-000000000004'::UUID),
            auth.uid(), 'accepted');
    RAISE EXCEPTION 'FAIL: an account made itself somebody''s friend';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    INSERT INTO blocks (blocker_id, blocked_id)
    VALUES ('cccc0000-0000-4000-8000-000000000002', auth.uid());
    RAISE EXCEPTION 'FAIL: an account wrote someone else''s block list';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Reading somebody else's list is not refused any more — it is unsayable.
  -- `_friend_bucket` took the account to answer about as a parameter, and this
  -- checked that a caller could not pass a stranger's id to it. `friend_bucket`
  -- (014) has no such parameter: it answers about `auth.uid()` and there is
  -- nowhere to name anyone else. That is the better shape, so what is asserted
  -- is that the hole is gone rather than guarded.
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = '_friend_bucket') THEN
    RAISE EXCEPTION 'FAIL: a function that answers about a named account is back';
  END IF;
  IF pg_get_function_identity_arguments(
       'friend_bucket(TEXT, TEXT, INTEGER)'::regprocedure) LIKE '%uuid%' THEN
    RAISE EXCEPTION 'FAIL: friend_bucket can be pointed at another account';
  END IF;
  RAISE NOTICE 'ok  every relationship change goes through an RPC';
END $$;

RESET ROLE;

-- ============================================================
-- 9. The friends graph a tab at a time (014)
-- ============================================================
-- `friend_list` answered all four buckets at once because the client needed all
-- of them to draw anything. It no longer does: the counts feed the badge and
-- the tab labels, the per-peer state rides on the conversation row, and what is
-- left is three lists that only their own tab reads.
--
-- Its fixtures are its own — five friends for bob to page through and one
-- stranger to walk the state machine with — because the sections above leave
-- alice and bob mid-relationship and a test that assumed otherwise would be
-- asserting the order of this file rather than the behaviour.

RESET ROLE;

INSERT INTO auth.users (id)
SELECT ('cccc0000-0000-4000-8000-0000000001' || lpad(i::TEXT, 2, '0'))::UUID
  FROM generate_series(1, 5) i;
INSERT INTO users (id, handle, chat_public_key, signing_public_key)
SELECT ('cccc0000-0000-4000-8000-0000000001' || lpad(i::TEXT, 2, '0'))::UUID,
       'pal' || i, 'chat-pal' || i, 'sign-pal' || i
  FROM generate_series(1, 5) i;
INSERT INTO friendships (low_id, high_id, status, requester_id)
SELECT LEAST('cccc0000-0000-4000-8000-000000000002'::UUID, p.id),
       GREATEST('cccc0000-0000-4000-8000-000000000002'::UUID, p.id),
       'accepted', 'cccc0000-0000-4000-8000-000000000002'
  FROM users p WHERE p.handle LIKE 'pal%';

INSERT INTO auth.users (id) VALUES ('cccc0000-0000-4000-8000-0000000002ff');
INSERT INTO users (id, handle, chat_public_key, signing_public_key)
VALUES ('cccc0000-0000-4000-8000-0000000002ff', 'stranger',
        'chat-stranger', 'sign-stranger');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true); END $$;

-- Where one account stands with one person, asked about that person rather
-- than derived from four whole lists.
DO $$
BEGIN
  IF app_friend_state('cccc0000-0000-4000-8000-0000000002ff') <> 'none' THEN
    RAISE EXCEPTION 'FAIL: two strangers are not strangers: %',
      app_friend_state('cccc0000-0000-4000-8000-0000000002ff');
  END IF;

  PERFORM friend_request('cccc0000-0000-4000-8000-0000000002ff');
  IF app_friend_state('cccc0000-0000-4000-8000-0000000002ff') <> 'outgoing' THEN
    RAISE EXCEPTION 'FAIL: a request this account sent reads as %',
      app_friend_state('cccc0000-0000-4000-8000-0000000002ff');
  END IF;

  -- The same row, from the other side. Getting these two backwards is the one
  -- way this function can be wrong without looking wrong.
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-0000000002ff","role":"authenticated"}', true);
  IF app_friend_state('cccc0000-0000-4000-8000-000000000002') <> 'incoming' THEN
    RAISE EXCEPTION 'FAIL: a request received reads as %',
      app_friend_state('cccc0000-0000-4000-8000-000000000002');
  END IF;

  PERFORM respond_friend_request('cccc0000-0000-4000-8000-000000000002', TRUE);
  IF app_friend_state('cccc0000-0000-4000-8000-000000000002') <> 'friends' THEN
    RAISE EXCEPTION 'FAIL: accepting did not make them friends';
  END IF;
  RAISE NOTICE 'ok  one peer''s state is asked about, not derived from a graph';
END $$;

-- Paging, on the handle. A handle is unique, so it is a total order on its own
-- and needs no tiebreaker — unlike a display name, which is why the member
-- roster's cursor (self-hosted 039) carries an id alongside it.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE
  v_page  JSONB;
  v_walk  TEXT[] := ARRAY[]::TEXT[];
  v_after TEXT;
  v_all   TEXT[];
  v_n     INT;
BEGIN
  v_n := (friend_counts()->>'friends')::INT;
  SELECT array_agg(e->>'handle' ORDER BY e->>'handle') INTO v_all
    FROM jsonb_array_elements(friend_bucket('friends', NULL, 100)->'rows') e;

  -- The count and the rows are two different queries behind one screen, so a
  -- disagreement is a badge that never matches the tab under it.
  IF v_n <> array_length(v_all, 1) THEN
    RAISE EXCEPTION 'FAIL: the count says % and the tab holds %',
      v_n, array_length(v_all, 1);
  END IF;
  IF v_n < 6 THEN
    RAISE EXCEPTION 'FAIL: too few friends for the seam to mean anything: %', v_n;
  END IF;

  -- Walked two at a time, which puts several seams inside the list where a
  -- skipped or repeated row would show.
  LOOP
    v_page := friend_bucket('friends', v_after, 2);
    EXIT WHEN jsonb_array_length(v_page->'rows') = 0;
    SELECT v_walk || array_agg(e->>'handle' ORDER BY e->>'handle') INTO v_walk
      FROM jsonb_array_elements(v_page->'rows') e;
    v_after := v_walk[array_length(v_walk, 1)];
    EXIT WHEN NOT (v_page->>'has_more')::BOOLEAN;
  END LOOP;

  IF v_walk <> v_all THEN
    RAISE EXCEPTION 'FAIL: paging lost or repeated a row: % vs %', v_walk, v_all;
  END IF;

  -- A page exactly the limit long is the end, not a promise of another — the
  -- bug the spare row exists to avoid.
  IF (friend_bucket('friends', NULL, v_n)->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: an exact page promised one more friend';
  END IF;
  IF NOT (friend_bucket('friends', NULL, v_n - 1)->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: all but one friend claimed to be all of them';
  END IF;
  RAISE NOTICE 'ok  a tab pages on the handle, and an exact page is the end';
END $$;

-- The conversation row carries the state, which is the whole reason
-- `app_friend_state` exists: the tile's menu asks it, and holding the graph to
-- answer was the cost.
DO $$
DECLARE v_row JSONB;
BEGIN
  v_row := dm_conversations()->'conversations'->0;
  IF v_row IS NULL THEN
    RAISE EXCEPTION 'FAIL: bob has no conversation, so this proves nothing';
  END IF;
  IF NOT (v_row ? 'state') THEN
    RAISE EXCEPTION 'FAIL: the conversation row does not carry a state at all';
  END IF;
  -- Never 'blocked': those conversations are gone from the list entirely.
  IF (v_row->>'state') = 'blocked' THEN
    RAISE EXCEPTION 'FAIL: a blocked peer''s conversation is still listed';
  END IF;
  RAISE NOTICE 'ok  and rides on the conversation row that needs it';
END $$;

-- A bucket nobody is in is an empty list rather than a null the client guards.
DO $$
BEGIN
  IF friend_bucket('blocked')->'rows' <> '[]'::jsonb THEN
    RAISE EXCEPTION 'FAIL: an empty bucket is not an empty list';
  END IF;
  IF (friend_counts()->>'blocked')::INT <> 0 THEN
    RAISE EXCEPTION 'FAIL: an empty block list counted as non-empty';
  END IF;
  RAISE NOTICE 'ok  and an empty tab is a list, not a null';
END $$;


-- ============================================================
-- Asking whether a handle is free, before there is an account (016)
-- ============================================================
-- Sign-up asks this as `anon`. It answers a boolean and nothing else: it
-- never says yes to a name the CHECK constraint would refuse, and never says
-- who holds one that is taken.
SET LOCAL ROLE anon;
DO $$
BEGIN
  IF is_handle_available('bob_test') THEN
    RAISE EXCEPTION 'FAIL: a taken handle reads as free';
  END IF;
  IF NOT is_handle_available('nobody_yet') THEN
    RAISE EXCEPTION 'FAIL: a free handle reads as taken';
  END IF;
  -- Folded the way the directory is, so `Bob_Test` is not a second free name.
  IF is_handle_available(' Bob_Test ') THEN
    RAISE EXCEPTION 'FAIL: case and whitespace made a taken handle look free';
  END IF;
  IF is_handle_available('no') OR is_handle_available('has space') THEN
    RAISE EXCEPTION 'FAIL: a handle the constraint would refuse reads as free';
  END IF;
  RAISE NOTICE 'ok  sign-up can ask whether a handle is free, and only that';
END $$;

-- ============================================================
-- Central DM attachments (017)
-- ============================================================
-- Blobs are written as `<uploader uid>/<random>.bin`. Rows are inserted as the
-- superuser because a member's INSERT is 005's to test, and the backdated ones
-- stand in for blobs whose messages retention has already removed.

RESET ROLE;
INSERT INTO storage.objects (bucket_id, name, owner, created_at) VALUES
  ('central-dm-attachments', 'cccc0000-0000-4000-8000-000000000001/alice-new.bin', 'cccc0000-0000-4000-8000-000000000001', now()),
  ('central-dm-attachments', 'cccc0000-0000-4000-8000-000000000002/bob-new.bin',   'cccc0000-0000-4000-8000-000000000002', now()),
  ('central-dm-attachments', 'cccc0000-0000-4000-8000-000000000001/alice-old.bin', 'cccc0000-0000-4000-8000-000000000001', now() - interval '40 days'),
  ('central-dm-attachments', 'cccc0000-0000-4000-8000-000000000002/bob-30d.bin',   'cccc0000-0000-4000-8000-000000000002', now() - interval '30 days'),
  ('backups',                'cccc0000-0000-4000-8000-000000000001/vault-old.bin', 'cccc0000-0000-4000-8000-000000000001', now() - interval '90 days');

SET LOCAL ROLE authenticated;

DO $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true);

  DELETE FROM storage.objects WHERE name = 'cccc0000-0000-4000-8000-000000000002/bob-new.bin';
  DELETE FROM storage.objects WHERE name = 'cccc0000-0000-4000-8000-000000000001/alice-new.bin';

  IF NOT EXISTS (SELECT 1 FROM storage.objects WHERE name = 'cccc0000-0000-4000-8000-000000000002/bob-new.bin') THEN
    RAISE EXCEPTION 'FAIL: a member deleted another member''s attachment';
  END IF;
  -- Without 017's policy this delete matched nothing and raised nothing, which
  -- is exactly how the app's "delete the message's files" call freed no bytes.
  IF EXISTS (SELECT 1 FROM storage.objects WHERE name = 'cccc0000-0000-4000-8000-000000000001/alice-new.bin') THEN
    RAISE EXCEPTION 'FAIL: a member could not delete their own attachment';
  END IF;
  RAISE NOTICE 'ok  a member deletes their own attachments and nobody else''s';
END $$;

DO $$
BEGIN
  BEGIN
    PERFORM expired_dm_attachments();
    RAISE EXCEPTION 'FAIL: a member listed other people''s expired attachments';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM request_attachment_sweep();
    RAISE EXCEPTION 'FAIL: a member triggered the attachment sweep';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM 1 FROM attachment_sweep_config;
    RAISE EXCEPTION 'FAIL: a member read the sweep''s secret';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  the sweep, its list and its secret are out of members'' reach';
END $$;

SET LOCAL ROLE service_role;

DO $$
DECLARE v_names TEXT[];
BEGIN
  v_names := expired_dm_attachments();
  -- Not bob's 30-day blob: its message may still exist until retention runs.
  -- Not the old vault backup: another bucket, kept on its own terms.
  IF v_names IS DISTINCT FROM ARRAY['cccc0000-0000-4000-8000-000000000001/alice-old.bin'] THEN
    RAISE EXCEPTION 'FAIL: the sweep would remove %', v_names;
  END IF;
  IF cardinality(expired_dm_attachments(0)) <> 0 THEN
    RAISE EXCEPTION 'FAIL: a zero limit still listed attachments';
  END IF;
  RAISE NOTICE 'ok  the sweep lists central attachments older than 31 days, and only those';
END $$;

RESET ROLE;

-- ---------- a conversation is held to 500 as it is written ----------
-- 019 moved the cap from a nightly ranking of the whole table into send_dm.
-- A conversation already at the cap loses its oldest message on the next send,
-- and nobody else's conversation is touched.

DO $$ BEGIN PERFORM set_config('request.jwt.claims', '{}', true); END $$;

INSERT INTO auth.users (id) VALUES
  ('cccc0000-0000-4000-8000-000000000005'),  -- erin
  ('cccc0000-0000-4000-8000-000000000006');  -- finn
INSERT INTO users (id, handle, chat_public_key, signing_public_key) VALUES
  ('cccc0000-0000-4000-8000-000000000005', 'erin_test', 'chat-erin', 'sign-erin'),
  ('cccc0000-0000-4000-8000-000000000006', 'finn_test', 'chat-finn', 'sign-finn');
INSERT INTO friendships (low_id, high_id, requester_id, status) VALUES
  ('cccc0000-0000-4000-8000-000000000005',
   'cccc0000-0000-4000-8000-000000000006',
   'cccc0000-0000-4000-8000-000000000006', 'accepted');

-- Two days old, so they fill the conversation without spending today's quota.
INSERT INTO dm_messages
       (sender_id, recipient_id, ciphertext, nonce, signature, key_version, created_at)
SELECT CASE WHEN g % 2 = 0 THEN 'cccc0000-0000-4000-8000-000000000005'::uuid
            ELSE 'cccc0000-0000-4000-8000-000000000006'::uuid END,
       CASE WHEN g % 2 = 0 THEN 'cccc0000-0000-4000-8000-000000000006'::uuid
            ELSE 'cccc0000-0000-4000-8000-000000000005'::uuid END,
       'old-' || g, 'n', 's', 1, now() - interval '2 days'
  FROM generate_series(1, 500) g;

CREATE TEMP TABLE others_before AS
  SELECT count(*) AS n FROM dm_messages
   WHERE 'cccc0000-0000-4000-8000-000000000005' NOT IN (sender_id, recipient_id);
GRANT SELECT ON others_before TO authenticated;

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000005","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_count INTEGER;
BEGIN
  PERFORM send_dm('cccc0000-0000-4000-8000-000000000006', 'the 501st', 'n', 's', 1);
  SELECT count(*) INTO v_count FROM dm_messages;  -- erin sees exactly this pair
  IF v_count <> 500 THEN
    RAISE EXCEPTION 'FAIL: the conversation holds % messages, not 500', v_count;
  END IF;
  IF EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'old-1') THEN
    RAISE EXCEPTION 'FAIL: the oldest message survived the cap';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'old-2')
     OR NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'the 501st') THEN
    RAISE EXCEPTION 'FAIL: the cap removed more than the one message past it';
  END IF;
  RAISE NOTICE 'ok  a send past 500 removes the conversation''s oldest message, and only that';
END $$;

-- ---------- one conversation, in the list's own shape (021) ----------

DO $$
DECLARE v JSONB;
BEGIN
  v := dm_conversations(30, NULL, 'cccc0000-0000-4000-8000-000000000006');
  IF jsonb_array_length(v->'conversations') <> 1
     OR v->'conversations'->0->>'peer_id' <> 'cccc0000-0000-4000-8000-000000000006'
     OR v->'conversations'->0->'last_message'->>'ciphertext' <> 'the 501st'
     OR (v->>'has_more')::boolean THEN
    RAISE EXCEPTION 'FAIL: asking for one conversation answered %', v;
  END IF;
  IF v->'conversations'->0 IS DISTINCT FROM dm_conversations()->'conversations'->0 THEN
    RAISE EXCEPTION 'FAIL: one conversation is not the same row as the list''s';
  END IF;
  v := dm_conversations(30, NULL, 'cccc0000-0000-4000-8000-000000000001');
  IF jsonb_array_length(v->'conversations') <> 0 THEN
    RAISE EXCEPTION 'FAIL: a conversation that does not exist was answered with %', v;
  END IF;
  RAISE NOTICE 'ok  one conversation comes back as the list draws it, or not at all';
END $$;

-- ---------- 022: the list is read from a head nobody else can see ----------
-- The conversation list used to find each peer's newest message by reading
-- every message the caller had ever sent or received. `dm_conversation_heads`
-- is that answer, kept as it is written — so the list costs a page instead of
-- a history. It is also a map of who talks to whom, which is why no account
-- can read it.

DO $$
BEGIN
  PERFORM 1 FROM dm_conversation_heads;
  RAISE EXCEPTION 'FAIL: an account can read who talks to whom';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'ok  the conversation heads are out of every account''s reach';
END $$;

RESET ROLE;

DO $$
DECLARE
  v_erin   UUID := 'cccc0000-0000-4000-8000-000000000005';
  v_finn   UUID := 'cccc0000-0000-4000-8000-000000000006';
  v_newest BIGINT;
  v_second BIGINT;
  v_row    JSONB;
BEGIN
  SELECT max(d.id) INTO v_newest FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(v_erin, v_finn)
     AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_erin, v_finn);

  IF (SELECT last_message_id FROM dm_conversation_heads
       WHERE user_id = v_erin AND peer_id = v_finn) IS DISTINCT FROM v_newest
     OR (SELECT last_message_id FROM dm_conversation_heads
          WHERE user_id = v_finn AND peer_id = v_erin) IS DISTINCT FROM v_newest THEN
    RAISE EXCEPTION 'FAIL: a head does not point at the conversation''s newest message';
  END IF;
  RAISE NOTICE 'ok  both sides of a conversation point at its newest message';

  -- The only delete that moves a head, and the one neither the 500 cap nor
  -- the retention job ever performs: they take the oldest.
  SELECT max(d.id) INTO v_second FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(v_erin, v_finn)
     AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_erin, v_finn)
     AND d.id < v_newest;

  DELETE FROM dm_messages WHERE id = v_newest;

  IF (SELECT last_message_id FROM dm_conversation_heads
       WHERE user_id = v_erin AND peer_id = v_finn) IS DISTINCT FROM v_second
     OR (SELECT last_message_id FROM dm_conversation_heads
          WHERE user_id = v_finn AND peer_id = v_erin) IS DISTINCT FROM v_second THEN
    RAISE EXCEPTION 'FAIL: deleting the newest message left a head pointing at it';
  END IF;

  -- And the list agrees, which is the only reason the head exists. auth.uid()
  -- is erin whatever the role is, and dm_conversations is SECURITY DEFINER.
  v_row := dm_conversations(30, NULL, v_finn)->'conversations'->0;
  IF (v_row->'last_message'->>'id')::BIGINT IS DISTINCT FROM v_second THEN
    RAISE EXCEPTION 'FAIL: the list previews % after the newest was deleted',
      v_row->'last_message'->>'id';
  END IF;
  RAISE NOTICE 'ok  deleting the newest message walks the head back, and the list with it';

  -- An emptied conversation is not a conversation. Without this the list
  -- carries a peer whose last message cannot be joined, and the tile vanishes
  -- from the page it was counted into.
  DELETE FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(v_erin, v_finn)
     AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_erin, v_finn);

  IF EXISTS (SELECT 1 FROM dm_conversation_heads
              WHERE (user_id = v_erin AND peer_id = v_finn)
                 OR (user_id = v_finn AND peer_id = v_erin)) THEN
    RAISE EXCEPTION 'FAIL: an emptied conversation kept its head';
  END IF;
  IF jsonb_array_length(dm_conversations()->'conversations') <> 0 THEN
    RAISE EXCEPTION 'FAIL: an emptied conversation is still in the list';
  END IF;
  RAISE NOTICE 'ok  and an emptied conversation leaves the list entirely';
END $$;

DO $$ BEGIN EXECUTE 'SET LOCAL ROLE authenticated'; END $$;

RESET ROLE;

DO $$ BEGIN
  IF (SELECT count(*) FROM dm_messages
       WHERE 'cccc0000-0000-4000-8000-000000000005' NOT IN (sender_id, recipient_id))
     <> (SELECT n FROM others_before) THEN
    RAISE EXCEPTION 'FAIL: capping one conversation deleted from another';
  END IF;
  RAISE NOTICE 'ok  capping one conversation leaves every other one alone';
END $$;

ROLLBACK;

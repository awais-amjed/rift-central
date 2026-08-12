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
-- Deliberately readable by every signed-in account: you cannot message someone
-- you cannot find. What must not be writable is someone else's row.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users WHERE handle = 'bob_test') THEN
    RAISE EXCEPTION 'FAIL: the directory is not readable by a signed-in account';
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
  RAISE NOTICE 'ok  the directory is public to read, own-row to write';
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
DECLARE v JSONB;
BEGIN
  v := dm_conversations();
  IF jsonb_array_length(v) <> 1 THEN
    RAISE EXCEPTION 'FAIL: expected one conversation, got %', jsonb_array_length(v);
  END IF;
  IF (v->0->>'peer_name') <> 'bob_test' THEN
    RAISE EXCEPTION 'FAIL: the conversation is not resolved against the directory';
  END IF;
  IF (v->0->'last_message'->>'ciphertext') IS NULL THEN
    RAISE EXCEPTION 'FAIL: the conversation carries no envelope to preview';
  END IF;
  RAISE NOTICE 'ok  dm_conversations returns one entry per peer, newest first';
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

RESET ROLE;
ROLLBACK;

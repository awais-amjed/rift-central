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
  FOREACH t IN ARRAY ARRAY['users','dm_messages','dm_message_reactions','read_state']
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
-- 4. Reactions
-- ============================================================

DO $$
BEGIN
  INSERT INTO dm_message_reactions (message_id, user_id, emoji)
  VALUES (7001, auth.uid(), '👍');

  BEGIN
    INSERT INTO dm_message_reactions (message_id, user_id, emoji)
    VALUES (7001, 'cccc0000-0000-4000-8000-000000000002', '👎');
    RAISE EXCEPTION 'FAIL: an account reacted as somebody else';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  you may only react as yourself';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"cccc0000-0000-4000-8000-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM dm_message_reactions) THEN
    RAISE EXCEPTION 'FAIL: reactions on a private conversation are visible to outsiders';
  END IF;
  RAISE NOTICE 'ok  reactions inherit the conversation''s visibility';
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

RESET ROLE;
ROLLBACK;

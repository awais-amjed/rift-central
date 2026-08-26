-- ============================================================
-- Rift central server — 012: friends, requests, blocks
-- ============================================================
-- Until now anybody could message anybody, and anybody could be found by
-- typing three letters. 002 argued for an open directory — you cannot message
-- someone you cannot find — but "findable" had silently come to mean
-- "enumerable, reachable, without limit, forever". The directory was the
-- product; an open inbox behind it was an accident.
--
-- The rule this file establishes is one sentence:
--
--   **You cannot send anything to somebody who is not your friend.**
--
-- Not one message, not a message that doubles as a request — nothing. Contact
-- begins with a friend request and a friend request carries no payload, so
-- there is no channel to abuse and nothing to withdraw-and-resend. Accepting
-- is what opens the composer, and it is the only thing that does.
--
-- ── How you find somebody ───────────────────────────────────
-- By typing their handle in full. There is no prefix search on this server any
-- more: `users` is no longer readable row-by-row by every signed-in account,
-- and the only way to turn a handle into a person is
-- `friend_request_by_handle`, which asks and answers in the same statement.
-- You learn that a handle exists by successfully asking its owner to be
-- friends — which is a fact they are told about at the same moment, and which
-- costs you a row in their Pending list.
--
-- That is the whole of the trade. An exact-handle directory is still an
-- existence oracle for handles you can guess; what it is not is a list. You
-- cannot walk it, sample it, or watch it grow, and a handle nobody told you is
-- 20 characters of `[a-z0-9_]`.
--
-- Three tables' worth of behaviour in two:
--
--   friendships   one row per *pair*, canonical (low_id < high_id), carrying
--                 who asked and whether it was answered.
--   blocks        directed. Ends the relationship in both directions and takes
--                 the handle out of reach.
--
-- ── What the operator learns ────────────────────────────────
-- Who is friends with whom, and who asked. That is not new information: the
-- same server already stores `dm_messages.sender_id`/`recipient_id` in the
-- clear, so the social graph was always legible here — this only names it. No
-- message content is involved at any point; this file never looks inside an
-- envelope.
--
-- ── Deletion ────────────────────────────────────────────────
-- Nothing here deletes a message. Declining a request removes the request;
-- unfriending removes the friendship; blocking removes both and adds a row.
-- All three leave the conversation exactly where it was, because a request now
-- arrives empty — there is nothing of theirs to throw away — and because a
-- conversation the two of you already had is not something one of you gets to
-- erase from the other. Two people who unfriend, re-request and accept find
-- their history where they left it.

-- ============================================================
-- 1. Types and tables
-- ============================================================

DO $$ BEGIN
  CREATE TYPE friend_status AS ENUM ('pending', 'accepted');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- One row per pair, not per direction. A friendship is symmetric, and two
-- rows for one relationship is two chances to disagree about it — a pair that
-- is friends from one side and pending from the other has no meaning and no
-- way to be repaired. `low_id < high_id` makes "are these two related" a
-- primary-key lookup rather than an OR over two columns.
--
-- `requester_id` is the asymmetry that is real: somebody asked, and until it
-- is answered the two sides of this row are not the same. `requested_at` is
-- when the *current* request began, which survives an unfriend-and-ask-again
-- where `updated_at` would not.
CREATE TABLE IF NOT EXISTS friendships (
  low_id       UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  high_id      UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requester_id UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status       friend_status NOT NULL,
  requested_at TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
  PRIMARY KEY (low_id, high_id),
  CHECK (low_id < high_id),
  CHECK (requester_id IN (low_id, high_id))
);

CREATE INDEX IF NOT EXISTS idx_friendships_high ON friendships (high_id);

-- Directed, and deliberately not visible to the person blocked: there is no
-- policy anywhere that lets you read a row where you are `blocked_id`, and no
-- function granted to `authenticated` that will answer the question either.
-- Being told you have been blocked is an invitation to make a second account.
CREATE TABLE IF NOT EXISTS blocks (
  blocker_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id <> blocked_id)
);

CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks (blocked_id);

-- ============================================================
-- 2. Predicates
-- ============================================================
-- All SECURITY DEFINER, and none of them granted to `authenticated` unless the
-- client genuinely has to ask. 008's header spells out why DEFINER is not
-- optional: a policy that consults an RLS-locked table evaluates false,
-- silently, and looks exactly like Realtime being broken.

-- Asked about a pair rather than about the caller, because one of its callers
-- is the ring trigger, which runs for a recipient who is not the session user.
-- Revoked from `authenticated` for exactly that reason.
CREATE OR REPLACE FUNCTION are_friends(p_a UUID, p_b UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM friendships f
     WHERE f.low_id  = LEAST(p_a, p_b)
       AND f.high_id = GREATEST(p_a, p_b)
       AND f.status  = 'accepted'
  );
$$;

-- Whether the caller has any standing reason to see somebody's directory row:
-- a friendship or request in either direction, or a message that has passed
-- between them. This is what the directory policy is made of — see section 3.
--
-- Granted to `authenticated`, and it has to be: an RLS policy is evaluated as
-- the querying role, so a policy built on a function the role cannot execute
-- fails with "permission denied" on every read of the table — including the
-- caller's own row.
--
-- That is safe here in a way `blocked_between` was not. Everything this
-- function looks at is already readable by the caller: `friendships` rows they
-- are a member of, and `dm_messages` rows they sent or received. It reaches no
-- further than the client can, and reports only about the caller's own
-- relationships — never the other party's decisions.
CREATE OR REPLACE FUNCTION knows_user(p_other UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM friendships f
     WHERE f.low_id  = LEAST(auth.uid(), p_other)
       AND f.high_id = GREATEST(auth.uid(), p_other)
  ) OR EXISTS (
    SELECT 1 FROM dm_messages d
     WHERE (d.sender_id = auth.uid() AND d.recipient_id = p_other)
        OR (d.sender_id = p_other     AND d.recipient_id = auth.uid())
  );
$$;

-- The caller's relationship with one person, as the client spells it:
--   none | incoming | outgoing | friends | blocked
--
-- `blocked` means *I* blocked them. There is no value for "they blocked me" —
-- see the `blocks` comment. From that side it looks like `none` that refuses.
CREATE OR REPLACE FUNCTION friendship_state(p_other UUID) RETURNS TEXT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
  v_row friendships%ROWTYPE;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF EXISTS (SELECT 1 FROM blocks b
              WHERE b.blocker_id = v_me AND b.blocked_id = p_other) THEN
    RETURN 'blocked';
  END IF;

  SELECT * INTO v_row FROM friendships f
   WHERE f.low_id = LEAST(v_me, p_other) AND f.high_id = GREATEST(v_me, p_other);
  IF NOT FOUND THEN RETURN 'none'; END IF;
  IF v_row.status = 'accepted' THEN RETURN 'friends'; END IF;
  RETURN CASE WHEN v_row.requester_id = v_me THEN 'outgoing' ELSE 'incoming' END;
END; $$;

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

ALTER TABLE friendships ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocks      ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS friendships_select_own ON friendships;
CREATE POLICY friendships_select_own ON friendships FOR SELECT TO authenticated
  USING (auth.uid() IN (low_id, high_id));

-- Only the blocker. A `blocked_id = auth.uid()` clause here would undo the
-- one thing the table is careful about.
DROP POLICY IF EXISTS blocks_select_own ON blocks;
CREATE POLICY blocks_select_own ON blocks FOR SELECT TO authenticated
  USING (blocker_id = auth.uid());

-- ---------- the directory stops being a directory ----------
-- Replaces 002's `USING (true)`. This is the change that ends handle search:
-- you may read your own row, and the rows of people you already have some
-- standing relationship with. Everybody else is not hidden behind a filter the
-- client is trusted to apply — they are not returned.
--
-- What still works, and has to:
--   * `dm_conversations()` (003) is SECURITY INVOKER and joins `users` for the
--     peer's handle and keys. Every peer it names is somebody messages have
--     passed with, so `knows_user` is true for all of them.
--   * A DM key is derived from the peer's published X25519 key and re-read on
--     every launch. Blocking must not make the *other* person's copy of the
--     conversation stop opening — so the predicate is "we have history",
--     deliberately *not* "we are still on speaking terms". Blocking takes away
--     reach and discoverability; it does not reach into somebody else's device
--     and make their messages unreadable.
--   * `claim_handle` (003) is SECURITY INVOKER and upserts on conflict, which
--     needs the existing row to be visible. `id = auth.uid()` is first for
--     that reason, and is unconditional.
DROP POLICY IF EXISTS users_select_directory ON users;
CREATE POLICY users_select_directory ON users FOR SELECT TO authenticated
  USING (id = auth.uid() OR knows_user(id));

-- ---------- gone, and on purpose ----------
-- Both are dropped *here*, after the policy above has been replaced, because
-- the policy this file is superseding was built out of `blocked_between` and
-- Postgres will not drop a function something still depends on.
--
-- `request_message_cap()` counted the messages a stranger was allowed in front
-- of somebody who had not answered. The allowance is zero now, and zero is not
-- a number worth a function.
--
-- `blocked_between()` answered "is there a block between me and this person"
-- to `authenticated`. It was the old directory policy's predicate, and it was
-- also the one thing on this server that would tell a blocked account it had
-- been blocked. The policy no longer needs it and nothing else should have it.
DROP FUNCTION IF EXISTS request_message_cap();
DROP FUNCTION IF EXISTS blocked_between(UUID);

-- ============================================================
-- 4. Sending, with the gate
-- ============================================================
-- Replaces 003's version. Everything 003 checked still happens in the same
-- order; what is new sits between the profile checks and the quota, because a
-- refused message must not spend quota.
--
-- One line does the work. There is no branch for strangers because there is no
-- case for strangers: the friendship is either accepted or the send is over.

CREATE OR REPLACE FUNCTION send_dm(
  recipient   UUID,
  ciphertext  TEXT,
  nonce       TEXT,
  signature   TEXT,
  key_version INTEGER
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota CONSTANT INTEGER := daily_dm_quota();
  v_me    UUID := auth.uid();
  v_sent  INTEGER;
  v_id    BIGINT;
  v_at    TIMESTAMPTZ;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF recipient = v_me THEN
    RAISE EXCEPTION 'cannot_dm_self';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = v_me) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = recipient) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;
  IF length(ciphertext) > 16384 OR length(nonce) > 64
     OR length(signature) > 128 OR key_version < 1 THEN
    RAISE EXCEPTION 'envelope_invalid';
  END IF;

  -- The gate. `blocked` is not raised separately: blocking deletes the
  -- friendship, so a blocked pair is a pair that is not friends, and the
  -- sender learns exactly what a stranger learns. Which of the two blocked the
  -- other — or whether anybody did — is nobody's business but the blocker's.
  IF NOT are_friends(v_me, recipient) THEN
    RAISE EXCEPTION 'not_friends';
  END IF;

  SELECT count(*) INTO v_sent FROM dm_messages
   WHERE sender_id = v_me AND created_at > now() - interval '24 hours';
  IF v_sent >= v_quota THEN
    RAISE EXCEPTION 'quota_exceeded';
  END IF;

  INSERT INTO dm_messages
         (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
  VALUES (v_me, recipient, ciphertext, nonce, signature, key_version)
  RETURNING id, created_at INTO v_id, v_at;

  -- `state` is always 'friends' — nothing else gets this far. It is still in
  -- the answer because the client compares it with what it believes and
  -- re-reads the graph when they differ, which is how a device that missed a
  -- Realtime frame notices.
  RETURN jsonb_build_object(
    'id', v_id, 'created_at', v_at, 'state', 'friends',
    'remaining', v_quota - v_sent - 1, 'quota', v_quota
  );
END; $$;

-- ============================================================
-- 5. Asking, answering, ending
-- ============================================================

-- Ask somebody to be friends. Idempotent, and it collapses the crossing case:
-- if they have already asked you, asking back is accepting.
--
-- Takes an id, so its callers are the places you already have one: a
-- conversation you used to have, a person you unfriended, the by-handle
-- wrapper below. Nothing hands out ids you have no relationship with.
CREATE OR REPLACE FUNCTION friend_request(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me  UUID := auth.uid();
  v_low UUID;
  v_high UUID;
  v_row friendships%ROWTYPE;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF p_user = v_me THEN RAISE EXCEPTION 'cannot_friend_self'; END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = v_me) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;
  IF EXISTS (
    SELECT 1 FROM blocks b
     WHERE (b.blocker_id = v_me    AND b.blocked_id = p_user)
        OR (b.blocker_id = p_user  AND b.blocked_id = v_me)
  ) THEN
    RAISE EXCEPTION 'blocked';
  END IF;

  v_low  := LEAST(v_me, p_user);
  v_high := GREATEST(v_me, p_user);

  SELECT * INTO v_row FROM friendships f
   WHERE f.low_id = v_low AND f.high_id = v_high FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO friendships (low_id, high_id, requester_id, status)
         VALUES (v_low, v_high, v_me, 'pending')
    ON CONFLICT (low_id, high_id) DO NOTHING;
    RETURN 'outgoing';
  END IF;

  IF v_row.status = 'accepted' THEN RETURN 'friends'; END IF;
  IF v_row.requester_id = v_me THEN RETURN 'outgoing'; END IF;

  UPDATE friendships SET status = 'accepted', updated_at = now()
   WHERE low_id = v_low AND high_id = v_high;
  RETURN 'friends';
END; $$;

-- The only way a handle becomes a person on this server.
--
-- It resolves and asks in one statement on purpose. A `find_user(handle)` that
-- merely answered with an id would be a cheap, silent, repeatable oracle — the
-- same enumeration this file removes, minus the typing. Here the answer *is*
-- the request: every successful lookup lands in somebody's Pending list, under
-- your handle, where they can decline it or block you for it.
--
-- Two ways to fail, and they are different on purpose:
--
--   no_such_user  the handle is not taken, is malformed, **or** its owner has
--                 blocked you. All three are the same sentence, because the
--                 third must be indistinguishable from the first.
--   blocked       *you* blocked *them*. Your own decision, and one you can
--                 undo, so you are told plainly rather than left confused by
--                 a handle you know exists.
CREATE OR REPLACE FUNCTION friend_request_by_handle(p_handle TEXT) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_handle TEXT := lower(trim(COALESCE(p_handle, '')));
  v_user   users%ROWTYPE;
  v_state  TEXT;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = v_me) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;

  -- The same shape 001 puts on the column. Anything that could not be a handle
  -- is not looked up at all — there is no point touching the table to learn
  -- that `Bob!` was never allowed to exist.
  IF v_handle !~ '^[a-z0-9_]{3,20}$' THEN
    RAISE EXCEPTION 'no_such_user';
  END IF;

  SELECT * INTO v_user FROM users u WHERE u.handle = v_handle;
  IF NOT FOUND THEN RAISE EXCEPTION 'no_such_user'; END IF;
  IF v_user.id = v_me THEN RAISE EXCEPTION 'cannot_friend_self'; END IF;

  -- Order matters. Theirs first, so that somebody who has blocked you is
  -- reported as a handle that does not exist rather than as a block.
  IF EXISTS (SELECT 1 FROM blocks b
              WHERE b.blocker_id = v_user.id AND b.blocked_id = v_me) THEN
    RAISE EXCEPTION 'no_such_user';
  END IF;
  IF EXISTS (SELECT 1 FROM blocks b
              WHERE b.blocker_id = v_me AND b.blocked_id = v_user.id) THEN
    RAISE EXCEPTION 'blocked';
  END IF;

  v_state := friend_request(v_user.id);
  RETURN jsonb_build_object('handle', v_user.handle, 'state', v_state);
END; $$;

-- Accept or decline something *they* asked for. The requester cannot call this
-- on their own request — that is what the `requester_id <> v_me` check is; a
-- self-accept would be the whole gate gone in one RPC. Withdrawing your own is
-- `unfriend`.
--
-- Declining removes the request and nothing else. A request arrives empty now,
-- so there is nothing of theirs to delete, and any conversation the two of you
-- had before is older than this request and not its to erase.
CREATE OR REPLACE FUNCTION respond_friend_request(
  p_user   UUID,
  p_accept BOOLEAN
) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me  UUID := auth.uid();
  v_low UUID;
  v_high UUID;
  v_row friendships%ROWTYPE;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;

  v_low  := LEAST(v_me, p_user);
  v_high := GREATEST(v_me, p_user);

  SELECT * INTO v_row FROM friendships f
   WHERE f.low_id = v_low AND f.high_id = v_high FOR UPDATE;
  IF NOT FOUND OR v_row.status <> 'pending' THEN
    RAISE EXCEPTION 'no_pending_request';
  END IF;
  IF v_row.requester_id = v_me THEN
    RAISE EXCEPTION 'not_your_request';
  END IF;

  IF p_accept THEN
    UPDATE friendships SET status = 'accepted', updated_at = now()
     WHERE low_id = v_low AND high_id = v_high;
    RETURN 'friends';
  END IF;

  DELETE FROM friendships WHERE low_id = v_low AND high_id = v_high;
  RETURN 'none';
END; $$;

-- Ends the relationship in either state: unfriending a friend, or withdrawing
-- a request you sent. Both are "there is no longer a row", which is also what
-- makes the absence of a row mean exactly one thing.
--
-- Withdrawing is cheap and repeatable, and that is fine now: a withdrawn
-- request took nothing with it and a re-sent one delivers nothing. It moves a
-- line in and out of a list. Under the old rule each round trip bought the
-- sender another message, which is why it was worth doing over and over.
CREATE OR REPLACE FUNCTION unfriend(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  DELETE FROM friendships
   WHERE low_id = LEAST(v_me, p_user) AND high_id = GREATEST(v_me, p_user);
  RETURN 'none';
END; $$;

CREATE OR REPLACE FUNCTION block_user(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF p_user = v_me THEN RAISE EXCEPTION 'cannot_block_self'; END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;

  INSERT INTO blocks (blocker_id, blocked_id) VALUES (v_me, p_user)
  ON CONFLICT DO NOTHING;

  -- A block that left the friendship standing would be a pair that is
  -- simultaneously friends and unable to speak, and `friendship_state` would
  -- have to pick one to report. It also has to take a *pending* row with it,
  -- or blocking somebody who has asked to be your friend leaves their request
  -- sitting in your list.
  DELETE FROM friendships
   WHERE low_id = LEAST(v_me, p_user) AND high_id = GREATEST(v_me, p_user);
  RETURN 'blocked';
END; $$;

-- Unblocking restores nothing but reachability: no friendship comes back, and
-- the two are strangers again, which is the state they were in before.
CREATE OR REPLACE FUNCTION unblock_user(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  DELETE FROM blocks WHERE blocker_id = v_me AND blocked_id = p_user;
  RETURN 'none';
END; $$;

-- ============================================================
-- 6. Reading the whole graph in one call
-- ============================================================
-- Four lists, one round trip. The client needs all of them to draw anything —
-- the badge on Friends, whether the composer is open, whether a conversation
-- is with somebody you are still friends with — and fetching them separately
-- means drawing a screen from four different moments.
--
-- SECURITY DEFINER for the `blocked` list specifically: section 3's directory
-- policy hides those rows from the caller once the friendship is gone, and a
-- blocked list with no handles in it is a list of UUIDs nobody can unblock on
-- purpose.
CREATE OR REPLACE FUNCTION friend_list() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;

  RETURN jsonb_build_object(
    'friends',  COALESCE(_friend_bucket(v_me, 'accepted', NULL),  '[]'::jsonb),
    'incoming', COALESCE(_friend_bucket(v_me, 'pending', FALSE),  '[]'::jsonb),
    'outgoing', COALESCE(_friend_bucket(v_me, 'pending', TRUE),   '[]'::jsonb),
    'blocked',  COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
               'id', u.id, 'handle', u.handle,
               'chat_public_key', u.chat_public_key,
               'signing_public_key', u.signing_public_key,
               'since', b.created_at
             ) ORDER BY u.handle)
        FROM blocks b JOIN users u ON u.id = b.blocked_id
       WHERE b.blocker_id = v_me), '[]'::jsonb)
  );
END; $$;

-- One bucket of `friend_list`. `p_mine` selects the side of a pending row:
-- TRUE for requests this account sent, FALSE for ones it received, NULL for
-- accepted rows where the question does not apply.
CREATE OR REPLACE FUNCTION _friend_bucket(
  p_me     UUID,
  p_status friend_status,
  p_mine   BOOLEAN
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT jsonb_agg(jsonb_build_object(
           'id', u.id, 'handle', u.handle,
           'chat_public_key', u.chat_public_key,
           'signing_public_key', u.signing_public_key,
           'since', f.updated_at
         ) ORDER BY u.handle)
    FROM friendships f
    JOIN users u
      ON u.id = CASE WHEN f.low_id = p_me THEN f.high_id ELSE f.low_id END
   WHERE p_me IN (f.low_id, f.high_id)
     AND f.status = p_status
     AND (p_mine IS NULL OR (f.requester_id = p_me) = p_mine);
$$;

-- ============================================================
-- 6b. Reading the directory rows behind a conversation
-- ============================================================
-- The shape the client actually asks in: "here are the peers in my
-- conversation list, give me their handles and keys". It answers exactly what
-- section 3's policy would answer for the same ids — the `EXISTS` here is the
-- message half of `knows_user` — and it exists as its own function so the
-- client has one call rather than a table read whose result silently depends
-- on a policy.
--
-- It cannot be used to browse: an id you have never exchanged a message with
-- answers nothing, however you came by it.
CREATE OR REPLACE FUNCTION directory_profiles(p_ids UUID[]) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', u.id, 'handle', u.handle,
           'chat_public_key', u.chat_public_key,
           'signing_public_key', u.signing_public_key
         )), '[]'::jsonb)
    FROM users u
   WHERE u.id = ANY (p_ids)
     AND EXISTS (
       SELECT 1 FROM dm_messages d
        WHERE (d.sender_id = auth.uid() AND d.recipient_id = u.id)
           OR (d.sender_id = u.id AND d.recipient_id = auth.uid())
     );
$$;

-- ============================================================
-- 7. Ringing
-- ============================================================
-- Replaces 011's version, one line longer. `send_dm` already refuses anything
-- from a non-friend, so the check is belt and braces — but this trigger is the
-- loudest thing the server can do, it fires on an INSERT rather than on the
-- RPC, and a future path into `dm_messages` that forgets the gate should not
-- also get to wake somebody's phone.
--
-- Note the order: the friendship check sits *above* the notification level,
-- because a level is a preference about people you have accepted and a
-- stranger has never had the chance to be given one.

CREATE OR REPLACE FUNCTION ring_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg push_config;
BEGIN
  IF NOT are_friends(NEW.sender_id, NEW.recipient_id) THEN
    RETURN NEW;
  END IF;
  IF notify_level_for(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;

  SELECT * INTO v_cfg FROM push_config LIMIT 1;
  IF v_cfg IS NULL THEN
    RETURN NEW;   -- push not configured on this deployment
  END IF;

  IF EXISTS (
    SELECT 1 FROM dm_messages d
     WHERE d.recipient_id = NEW.recipient_id
       AND d.sender_id    = NEW.sender_id
       AND d.id < NEW.id
       AND d.id > COALESCE((SELECT r.last_read_id FROM read_state r
                             WHERE r.user_id = NEW.recipient_id
                               AND r.scope = 'dm'
                               AND r.scope_id = NEW.sender_id), 0)
  ) THEN
    RETURN NEW;
  END IF;

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-push-secret', v_cfg.secret
               ),
    body    := jsonb_build_object('recipient', NEW.recipient_id)
  );
  RETURN NEW;
END; $$;

-- ============================================================
-- 8. Realtime
-- ============================================================
-- A request accepted on a phone has to reach the desktop, for the same reason
-- 011 published `notification_prefs`: the alternative is per-device state that
-- happens to be stored on a server. It matters more now than it did — the
-- composer's very existence depends on the friendship, so a desktop that
-- missed the acceptance is a desktop with no way to type.
--
-- `REPLICA IDENTITY FULL` because declining, withdrawing, unfriending and
-- unblocking are all DELETEs, and the default replica identity ships a primary
-- key the subscriber then cannot match against its own id.
--
-- A client filters `friendships` on `low_id` and `high_id` separately, since a
-- Realtime filter is one column: two bindings, one channel.

ALTER TABLE friendships REPLICA IDENTITY FULL;
ALTER TABLE blocks      REPLICA IDENTITY FULL;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE friendships;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE blocks;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- 9. Backfill
-- ============================================================
-- Everybody who has already spoken is already friends. Applying the gate
-- retroactively would turn every existing conversation into a pair who can
-- read their history and not add to it, waiting on a request neither of them
-- sent.
--
-- `requester_id` is whoever sent the first message of the pair, and
-- `requested_at` is when — which is as close to the truth as the data gets,
-- and true enough for a row that is already accepted.

INSERT INTO friendships (low_id, high_id, requester_id, status, requested_at)
SELECT low, high, requester, 'accepted', first_at
  FROM (
    SELECT DISTINCT ON (LEAST(sender_id, recipient_id),
                        GREATEST(sender_id, recipient_id))
           LEAST(sender_id, recipient_id)    AS low,
           GREATEST(sender_id, recipient_id) AS high,
           sender_id                         AS requester,
           created_at                        AS first_at
      FROM dm_messages
     ORDER BY LEAST(sender_id, recipient_id),
              GREATEST(sender_id, recipient_id), id ASC
  ) pairs
ON CONFLICT (low_id, high_id) DO NOTHING;

-- ============================================================
-- 10. Function privileges
-- ============================================================
-- 003 revoked EXECUTE by default, so anything created here is unreachable
-- until named. Two are deliberately not named: `are_friends` is the ring
-- trigger's, and answers about a pair neither of whom need be the caller;
-- `_friend_bucket` would answer for any account passed to it.
--
-- `knows_user` *is* named, because the directory policy is made of it — see
-- section 2 for why that is safe and why it is not optional.

-- Revoked from everybody first, including PUBLIC. 003's blanket REVOKE ran
-- before these functions existed, and its `ALTER DEFAULT PRIVILEGES` only
-- covers what the role that ran it goes on to create — so a function added
-- here inherits Postgres's default of EXECUTE for PUBLIC unless it is said
-- out loud. Each one below re-checks `auth.uid()`, so nothing was reachable
-- that mattered; naming it is the difference between safe and safe on purpose.
REVOKE ALL ON FUNCTION are_friends(UUID, UUID)               FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION knows_user(UUID)                      FROM public, anon;
REVOKE ALL ON FUNCTION _friend_bucket(UUID, friend_status, BOOLEAN)
                                                             FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION friendship_state(UUID)                FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION friend_request(UUID)                  FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION friend_request_by_handle(TEXT)        FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION respond_friend_request(UUID, BOOLEAN) FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION unfriend(UUID)                        FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION block_user(UUID)                      FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION unblock_user(UUID)                    FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION friend_list()                         FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION directory_profiles(UUID[])            FROM public, anon, authenticated;

GRANT EXECUTE ON FUNCTION knows_user(UUID)                   TO authenticated;
GRANT EXECUTE ON FUNCTION friendship_state(UUID)             TO authenticated;
GRANT EXECUTE ON FUNCTION friend_request(UUID)               TO authenticated;
GRANT EXECUTE ON FUNCTION friend_request_by_handle(TEXT)     TO authenticated;
GRANT EXECUTE ON FUNCTION respond_friend_request(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION unfriend(UUID)                     TO authenticated;
GRANT EXECUTE ON FUNCTION block_user(UUID)                   TO authenticated;
GRANT EXECUTE ON FUNCTION unblock_user(UUID)                 TO authenticated;
GRANT EXECUTE ON FUNCTION friend_list()                      TO authenticated;
GRANT EXECUTE ON FUNCTION directory_profiles(UUID[])         TO authenticated;
GRANT EXECUTE ON FUNCTION send_dm(UUID, TEXT, TEXT, TEXT, INTEGER) TO authenticated;

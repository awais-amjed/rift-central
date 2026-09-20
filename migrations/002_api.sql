-- ============================================================
-- Rift central — 002: the RPCs
-- ============================================================
-- What a client calls. As on a server, these exist for what RLS cannot say on
-- its own: a write that has to check something first, a read that has to be
-- bounded, and an action across several tables that must happen all at once.
--
-- Two of them exist for a narrower reason worth knowing: **a PostgREST upsert
-- cannot be used against a column-granted table.** The generated
-- `ON CONFLICT DO UPDATE` writes every payload column including the conflict
-- key, and the privilege check happens at plan time — so it is refused whether
-- or not the row exists. `claim_handle` and `mark_read` do those upserts
-- without touching the key.
-- ============================================================

-- ============================================================
-- RPCs
-- ============================================================
-- Central has no edge functions at all. Everything a client does here is either
-- a policy-checked table call or one of these.

-- How many messages one account may send per rolling day. The funnel limit
-- that keeps central's hosting cost flat; enforced server-side so a modified
-- client can't spend more.
CREATE OR REPLACE FUNCTION daily_dm_quota() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

-- ============================================================
-- Claiming a handle
-- ============================================================
-- Creating or refreshing your own directory row. A client cannot do this as a
-- plain upsert: PostgREST writes every column of the payload into the DO UPDATE
-- clause, `id` included, and `id` is deliberately not in the UPDATE grant — so
-- the statement is refused before it ever reaches a policy, whether or not the
-- row exists. This does the same upsert without touching the key.
--
-- SECURITY INVOKER on purpose: the grants and policies in 007 still apply, so
-- this widens nothing. It only spells the statement in a way the grants allow.
CREATE OR REPLACE FUNCTION claim_handle(
  p_handle             TEXT,
  p_chat_public_key    TEXT,
  p_signing_public_key TEXT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  INSERT INTO users (id, handle, chat_public_key, signing_public_key)
       VALUES (auth.uid(), p_handle, p_chat_public_key, p_signing_public_key)
  ON CONFLICT (id) DO UPDATE
          SET handle             = EXCLUDED.handle,
              chat_public_key    = EXCLUDED.chat_public_key,
              signing_public_key = EXCLUDED.signing_public_key;
END; $$;

CREATE OR REPLACE FUNCTION dm_quota() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota CONSTANT INTEGER := daily_dm_quota();
  v_sent  INTEGER;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  SELECT count(*) INTO v_sent FROM dm_messages
   WHERE sender_id = auth.uid() AND created_at > now() - interval '24 hours';
  RETURN jsonb_build_object('quota', v_quota,
                            'remaining', greatest(v_quota - v_sent, 0));
END; $$;

CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_target BIGINT := p_last_read_id;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    SELECT COALESCE(max(d.id), 0) INTO v_target
      FROM dm_messages d
     WHERE d.sender_id = p_scope_id AND d.recipient_id = auth.uid();
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (auth.uid(), p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
              updated_at   = now()
    RETURNING last_read_id INTO v_target;

  RETURN v_target;
END; $$;

-- ============================================================
-- Publishing
-- ============================================================
-- How many servers one account may list. Not a storage bound — a listing is
-- tiny — but a bound on how much of a directory one account can be.

CREATE OR REPLACE FUNCTION max_public_servers() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 10 $$;

-- Create or update your listing for one server, in one statement.
--
-- SECURITY DEFINER rather than INVOKER (which is what claim_handle needed for
-- the same upsert shape) because two of the checks here are over rows the
-- caller cannot see: the per-account cap counts their own rows, but the
-- ownership check has to read a row that may be *delisted and someone else's*,
-- which the select policy hides. Under INVOKER that case would surface as a
-- unique violation on (supabase_url, server_id) — a confusing error for a
-- comprehensible situation. `owner_id` is taken from auth.uid() and never from
-- the caller, so the definer rights widen nothing.
CREATE OR REPLACE FUNCTION publish_server(
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_url     TEXT    DEFAULT NULL,
  p_tags         TEXT[]  DEFAULT '{}',
  p_member_count INTEGER DEFAULT 0,
  p_is_listed    BOOLEAN DEFAULT TRUE
) RETURNS public_servers
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_owner UUID;
  v_count INTEGER;
  v_row   public_servers;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  -- The listing is owned by an account, and an account here is its directory
  -- row — the same precondition send_dm() has for a sender.
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE supabase_url = p_supabase_url AND server_id = p_server_id;

  IF v_owner IS NOT NULL AND v_owner <> auth.uid() THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = auth.uid();
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_url, tags,
                              member_count, is_listed)
       VALUES (auth.uid(), p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_url,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (supabase_url, server_id) DO UPDATE
          SET invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_url     = EXCLUDED.icon_url,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

-- ---------- listing a bot ----------
-- How many bots one account may list. Same argument as max_public_servers():
-- not a storage bound, a bound on how much of a directory one account can be.

CREATE OR REPLACE FUNCTION max_public_bots() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 10 $$;

-- Create or update your own bot listing.
--
-- Unlike `publish_server`, this is reachable by `authenticated` and needs no
-- proof of anything. There is nothing to prove: a bot listing points at no
-- database central could ask, and it holds no slot anyone else could be
-- locked out of — see the table's own note in 001. The rules it does enforce
-- are its own: you must have a profile, you own what you publish, and ten is
-- the ceiling.
--
-- SECURITY DEFINER for the same reason `publish_server` is: there is no
-- INSERT or UPDATE grant on the table, so this function is the only way a row
-- is written and the cap cannot be gone around by writing one directly.
-- `owner_id` comes from auth.uid() and never from an argument.
--
-- [p_id] null creates; anything else edits that row, which must be yours.
-- Editing by id rather than upserting on (owner_id, name) is what lets a bot
-- be renamed — an upsert on the name would quietly leave the old listing
-- behind and spend another slot.
CREATE OR REPLACE FUNCTION publish_bot(
  p_id          UUID    DEFAULT NULL,
  p_name        TEXT    DEFAULT NULL,
  p_source_url  TEXT    DEFAULT NULL,
  p_description TEXT    DEFAULT NULL,
  p_icon_url    TEXT    DEFAULT NULL,
  p_tags        TEXT[]  DEFAULT '{}',
  p_manifest    JSONB   DEFAULT NULL,
  p_is_listed   BOOLEAN DEFAULT TRUE
) RETURNS public_bots
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_count INTEGER;
  v_row   public_bots;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;

  IF p_id IS NULL THEN
    SELECT count(*) INTO v_count FROM public_bots WHERE owner_id = auth.uid();
    IF v_count >= max_public_bots() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;

    INSERT INTO public_bots (owner_id, name, description, icon_url,
                             source_url, tags, manifest, is_listed)
         VALUES (auth.uid(), btrim(p_name), p_description, p_icon_url,
                 p_source_url, COALESCE(p_tags, '{}'), p_manifest,
                 COALESCE(p_is_listed, TRUE))
      RETURNING * INTO v_row;
    RETURN v_row;
  END IF;

  -- `owner_id` in the predicate rather than a separate check: the row is
  -- readable by everyone, so a WHERE that matched it and then refused would
  -- be a slower way to say the same thing.
  UPDATE public_bots
     SET name        = btrim(p_name),
         description = p_description,
         icon_url    = p_icon_url,
         source_url  = p_source_url,
         tags        = COALESCE(p_tags, '{}'),
         manifest    = p_manifest,
         is_listed   = COALESCE(p_is_listed, TRUE),
         updated_at  = now()
   WHERE id = p_id AND owner_id = auth.uid()
   RETURNING * INTO v_row;

  IF v_row.id IS NULL THEN
    RAISE EXCEPTION 'listing_not_yours';
  END IF;
  RETURN v_row;
END; $$;

COMMENT ON FUNCTION publish_bot(UUID, TEXT, TEXT, TEXT, TEXT, TEXT[], JSONB, BOOLEAN) IS
  'Create or edit the caller''s own bot listing. Unlike publish_server this '
  'needs no proof-of-admin round trip, because a bot listing names no server '
  'and reserves nothing anyone else could want — see public_bots in 001.';

-- ---------- enrolling ----------
-- The one moment the secret exists outside this table. The caller is the
-- server's admin, signed in to central; their client writes what comes back
-- into that server's `push_config` over its own admin-only endpoint. Neither
-- half is enough alone, which is what makes squatting on a (url, id) pair
-- pointless.

CREATE OR REPLACE FUNCTION enroll_push_relay(
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_label        TEXT DEFAULT NULL
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_owner  UUID := auth.uid();
  v_secret TEXT;
  v_id     UUID;
BEGIN
  IF v_owner IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  -- A bound on minting, not on servers: nobody administers twenty servers and
  -- re-enrols each of them often, and an account that appears to is scripted.
  IF (SELECT count(*) FROM push_relays WHERE owner_id = v_owner) >= 20 THEN
    RAISE EXCEPTION 'too_many_relays';
  END IF;

  v_secret := encode(gen_random_bytes(32), 'base64');

  INSERT INTO push_relays (owner_id, supabase_url, server_id, label, secret_hash)
  VALUES (v_owner, p_supabase_url, p_server_id, p_label,
          encode(digest(v_secret, 'sha256'), 'hex'))
  RETURNING id INTO v_id;

  RETURN jsonb_build_object('relay_id', v_id, 'secret', v_secret);
END; $$;

-- ---------- spending ----------
-- Verify, meter and increment in one statement, because `push_send` runs many
-- at once and two forwards that each read 19,999 must not both be allowed.
-- Returns false for an unknown id, a wrong secret, a revoked credential and an
-- exhausted day alike: a caller learns only that it may not send.

CREATE OR REPLACE FUNCTION claim_relay_push(
  p_relay_id UUID,
  p_secret   TEXT,
  p_count    INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_ok BOOLEAN;
BEGIN
  UPDATE push_relays
     SET rung_today  = CASE WHEN window_date = current_date
                            THEN rung_today + p_count ELSE p_count END,
         window_date = current_date
   WHERE id = p_relay_id
     AND NOT is_disabled
     AND secret_hash = encode(digest(p_secret, 'sha256'), 'hex')
     AND (CASE WHEN window_date = current_date THEN rung_today + p_count
               ELSE p_count END) <= daily_cap
   RETURNING true INTO v_ok;

  RETURN COALESCE(v_ok, false);
END; $$;

-- What a conversation is set to, default included. SECURITY DEFINER because
-- the ring trigger asks it about the *recipient*, whose rows the sender's
-- session may not read.
CREATE OR REPLACE FUNCTION notify_level_for(
  p_user UUID, p_scope public.notify_scope, p_scope_id UUID
) RETURNS public.notify_level LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT COALESCE(
    (SELECT p.level FROM notification_prefs p
      WHERE p.user_id = p_user AND p.scope = p_scope AND p.scope_id = p_scope_id),
    'all'::notify_level
  );
$$;

-- ============================================================
-- 2. Predicates
-- ============================================================
-- All SECURITY DEFINER, and none of them granted to `authenticated` unless the
-- client genuinely has to ask. DEFINER is not optional here: a policy that
-- consults an RLS-locked table evaluates false, silently, and looks exactly
-- like Realtime being broken.

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

  -- The same shape the column's own CHECK has. Anything that could not be a handle
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
-- The friends graph, a tab at a time
-- ============================================================
-- The obvious shape is one call returning all four buckets: the client needs
-- all of them to draw anything, so fetching them separately means drawing a
-- screen from four different moments.
--
-- That is not true for long. Only a handful of *derived facts* are ever needed
-- outside their own tab:
--
--   * how many requests are waiting  — the badge on the app rail, which is on
--     screen wherever you are;
--   * who is blocked                 — the conversation list leaves them out;
--   * where you stand with one peer  — what a conversation tile's menu offers.
--
-- None of those needs the rows. So the counts become a scalar, the block filter
-- moves into `dm_conversations` where the rows it filters already are, and the
-- per-peer state rides on the conversation row beside the unread count and the
-- notification level. What is left is three lists that are each only read by
-- the tab showing them — and those can be fetched when that tab is opened, and
-- paged.
--
-- ---------- why the block filter belongs here ----------
--
-- Dropping blocked peers from the conversation list in the client, *after* the
-- page arrives, only works while the list is the whole thing. Once it is
-- paged, a page of thirty containing four blocked peers renders twenty-six
-- rows while `has_more` and the cursor were both computed for thirty. The
-- list is quietly shorter than it should be, and every further page
-- compounds it.
--
-- A filter has to be on the same side of the page boundary as the paging. This
-- puts it there.

-- ============================================================
-- 1. Where one account stands with one person
-- ============================================================
-- The same four answers `FriendDirectory.stateFor` gave, asked about one peer
-- instead of derived from four whole lists. Named for the client's enum so the
-- two cannot drift: `friends`, `incoming`, `outgoing`, `blocked`, `none`.

CREATE OR REPLACE FUNCTION app_friend_state(p_peer UUID) RETURNS TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
    -- First, and it wins any disagreement: blocking tears the friendship down
    -- with it, so the two cannot both be true — but "blocked" is the answer
    -- that fails safe if they ever are.
    WHEN EXISTS (SELECT 1 FROM blocks b
                  WHERE b.blocker_id = auth.uid() AND b.blocked_id = p_peer)
      THEN 'blocked'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'accepted')
      THEN 'friends'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'pending' AND f.requester_id = auth.uid())
      THEN 'outgoing'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'pending')
      THEN 'incoming'
    ELSE 'none'
  END
$$;

-- ============================================================
-- 3. How many, without the rows
-- ============================================================
-- What the rail badge and the three tab labels need, and all they need. Small
-- enough to be eager, which is the whole reason the rows no longer have to be.

CREATE OR REPLACE FUNCTION friend_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'friends',  (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'accepted'),
    -- Incoming only. Waiting for an answer is not something to be notified
    -- about, so an outgoing request is not in the badge.
    'incoming', (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'pending' AND f.requester_id <> auth.uid()),
    'outgoing', (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'pending' AND f.requester_id = auth.uid()),
    'blocked',  (SELECT count(*) FROM blocks b WHERE b.blocker_id = auth.uid()))
$$;

COMMENT ON FUNCTION friend_counts() IS
  'How many friends, requests each way, and blocks — for the rail badge and '
  'the tab labels, so the rows behind them can wait until a tab is opened.';

-- ============================================================
-- 4. One tab of the graph, paged
-- ============================================================
-- Keyset-paged on the peer's handle, which is the order the tabs are already
-- in. A handle is unique, so it is a total order on its own and needs no
-- tiebreaker — unlike a display name, which is why the member roster's cursor
-- carries an id alongside it.

CREATE OR REPLACE FUNCTION friend_bucket(
  p_bucket TEXT,
  p_after  TEXT    DEFAULT NULL,
  p_limit  INTEGER DEFAULT 30
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me    UUID    := auth.uid();
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100);
  v_rows  JSONB;
  v_n     INTEGER;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;

  -- The block list is its own table and its own shape (`since` comes from the
  -- block, not a friendship), so it is its own branch rather than a fourth
  -- status. SECURITY DEFINER matters most here: the directory policy hides
  -- these rows once the friendship is gone, and a blocked list with no handles
  -- in it is a list of UUIDs nobody can unblock on purpose.
  IF p_bucket = 'blocked' THEN
    SELECT jsonb_agg(row ORDER BY handle), count(*) INTO v_rows, v_n
      FROM (
        SELECT u.handle,
               jsonb_build_object(
                 'id', u.id, 'handle', u.handle,
                 'chat_public_key', u.chat_public_key,
                 'signing_public_key', u.signing_public_key,
                 'since', b.created_at) AS row
          FROM blocks b JOIN users u ON u.id = b.blocked_id
         WHERE b.blocker_id = v_me
           AND (p_after IS NULL OR u.handle > p_after)
         ORDER BY u.handle
         LIMIT v_limit + 1) capped;
  ELSE
    SELECT jsonb_agg(row ORDER BY handle), count(*) INTO v_rows, v_n
      FROM (
        SELECT u.handle,
               jsonb_build_object(
                 'id', u.id, 'handle', u.handle,
                 'chat_public_key', u.chat_public_key,
                 'signing_public_key', u.signing_public_key,
                 'since', f.updated_at) AS row
          FROM friendships f
          JOIN users u
            ON u.id = CASE WHEN f.low_id = v_me THEN f.high_id ELSE f.low_id END
         WHERE v_me IN (f.low_id, f.high_id)
           AND f.status = (CASE WHEN p_bucket = 'friends'
                                THEN 'accepted' ELSE 'pending' END)::friend_status
           -- `outgoing` is the ones this account sent, `incoming` the ones it
           -- received; `friends` does not ask the question.
           AND (p_bucket = 'friends'
                OR (f.requester_id = v_me) = (p_bucket = 'outgoing'))
           AND (p_after IS NULL OR u.handle > p_after)
         ORDER BY u.handle
         LIMIT v_limit + 1) capped;
  END IF;

  RETURN jsonb_build_object(
    -- The spare row proves there is another page; it is not part of this one.
    'rows', COALESCE(
      CASE WHEN v_n > v_limit
           THEN (SELECT jsonb_agg(e) FROM (
                   SELECT e FROM jsonb_array_elements(v_rows) e LIMIT v_limit) t)
           ELSE v_rows END, '[]'::jsonb),
    'has_more', COALESCE(v_n, 0) > v_limit);
END; $$;

COMMENT ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER) IS
  'One tab of the friends page — friends, incoming, outgoing or blocked — '
  'keyset-paged on the peer''s handle via p_after. Fetched when that tab is '
  'opened: nothing outside it reads these rows since friend_counts and the '
  'per-conversation state took over the jobs that did.';

COMMENT ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                   TEXT[], INTEGER, BOOLEAN) IS
  'Create or update a listing. Service role only: the edge function of the '
  'same name is the entry point, because it first proves — by redeeming a '
  'one-time token against the server''s own domain — that an admin of that '
  'server asked for this. auth.uid() is still the owner, and is still taken '
  'from the session rather than from an argument.';

-- ---------- who the listing belongs to ----------
-- `publish_server` reads `auth.uid()`, and under the service role there is no
-- session to read it from. The owner therefore has to be passed in, which
-- means this is the one argument the edge function must never take from its
-- caller — it takes it from the verified JWT instead.

CREATE OR REPLACE FUNCTION publish_server_as(
  p_owner        UUID,
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_url     TEXT    DEFAULT NULL,
  p_tags         TEXT[]  DEFAULT '{}',
  p_member_count INTEGER DEFAULT 0,
  p_is_listed    BOOLEAN DEFAULT TRUE
) RETURNS public_servers
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_owner UUID;
  v_count INTEGER;
  v_row   public_servers;
BEGIN
  IF p_owner IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_owner) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE supabase_url = p_supabase_url AND server_id = p_server_id;

  -- Still refused, but it means something different now. Reaching this line
  -- takes a token from the server, so both accounts are administrators of it
  -- — a co-admin taking over a colleague's listing rather than a stranger
  -- taking one hostage.
  IF v_owner IS NOT NULL AND v_owner <> p_owner THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = p_owner;
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_url, tags,
                              member_count, is_listed)
       VALUES (p_owner, p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_url,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (supabase_url, server_id) DO UPDATE
          SET invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_url     = EXCLUDED.icon_url,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

COMMENT ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                      TEXT[], INTEGER, BOOLEAN) IS
  'publish_server with the owner passed in rather than read from a session, '
  'for the edge function that has already verified both the caller''s JWT and '
  'their administration of the server. Service role only.';

-- ============================================================
-- Asking for a handle before there is an account
-- ============================================================
-- A handle was claimed on first opening the DM tab, which is a strange moment
-- to be asked what you are called: the account already existed, the tab was
-- opened for a reason, and the question stood between the person and it.
-- Sign-up asks now. The handle rides in the auth user's metadata until the
-- first signed-in session claims it — the row in `users` needs two public
-- keys that only a device holding the seed can derive, so the claim itself
-- cannot move any earlier than that.
--
-- What *can* move earlier is finding out the name is taken. Sign-up would
-- otherwise succeed, the confirmation mail would go out, and the refusal would
-- arrive a day later on a different screen. So this one question is answerable
-- by somebody who is not signed in yet.
--
-- It tells an anonymous caller whether a handle exists. That is already true
-- of every handle: they are the public names in a directory built for finding
-- people, and `friend_request_by_handle` answers the same question to anyone
-- signed in. What it does not do is say *who* — it answers a boolean and
-- nothing else.

CREATE OR REPLACE FUNCTION is_handle_available(p_handle TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  -- Malformed is "not available" rather than an error: the client has the
  -- same rule and says so first; this only has to never say yes to a name
  -- the CHECK constraint would refuse.
  SELECT lower(trim(p_handle)) ~ '^[a-z0-9_]{3,20}$'
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.handle = lower(trim(p_handle)))
$$;

-- ---------- send_dm, trimming quietly ----------

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
  -- The per-conversation cap. Past it the oldest ciphertext is gone for good.
  v_cap   CONSTANT INTEGER := 500;
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
  -- sender learns exactly what a stranger learns.
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

  -- Written in idx_dm_messages_pair's own terms, so both halves are index
  -- scans of this one conversation; `id <= NULL` deletes nothing. Quietly:
  -- nobody deleted these, the cap did.
  PERFORM set_config('rift.quiet_deletes', 'on', true);
  DELETE FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = LEAST(v_me, recipient)
     AND GREATEST(sender_id, recipient_id) = GREATEST(v_me, recipient)
     AND id <= (
       SELECT d.id FROM dm_messages d
        WHERE LEAST(d.sender_id, d.recipient_id) = LEAST(v_me, recipient)
          AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_me, recipient)
        ORDER BY d.id DESC
       OFFSET v_cap LIMIT 1);
  PERFORM set_config('rift.quiet_deletes', 'off', true);

  -- `state` is always 'friends' — nothing else gets this far. It is still in
  -- the answer because the client compares it with what it believes and
  -- re-reads the graph when they differ.
  RETURN jsonb_build_object(
    'id', v_id, 'created_at', v_at, 'state', 'friends',
    'remaining', v_quota - v_sent - 1, 'quota', v_quota
  );
END; $$;

-- ============================================================
-- 3. The list, read from the heads
-- ============================================================
-- Driven from the heads table rather than from `dm_messages`: the same
-- envelope, the same badge, the same friend state, the same spare row
-- proving `has_more`.
--
-- `p_peer` needs no branch of its own. One conversation is one row
-- of the same index, which is what the two-branch `paired` CTE was working
-- around.

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL,
  p_peer   UUID    DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH page AS (
    SELECT h.last_message_id AS id, h.peer_id AS peer
      FROM dm_conversation_heads h
     WHERE h.user_id = auth.uid()
       AND (p_peer IS NULL OR h.peer_id = p_peer)
       -- Here rather than in the client: a filter on the far side of the page
       -- boundary silently shortens every page it touches.
       AND NOT EXISTS (
         SELECT 1 FROM blocks b
          WHERE b.blocker_id = auth.uid() AND b.blocked_id = h.peer_id)
       AND (p_before IS NULL OR h.last_message_id < p_before)
     ORDER BY h.last_message_id DESC
     -- One row past the page, so "there is more" is proved rather than
     -- guessed from a full page. Same trick the message history uses.
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT d.*, p.peer
      FROM (SELECT * FROM page
             ORDER BY id DESC
             LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)) p
      JOIN dm_messages d ON d.id = p.id
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',            u.id,
             'handle',             u.handle,
             'chat_public_key',    u.chat_public_key,
             'signing_public_key', u.signing_public_key,
             -- Where the caller stands with this person, for the tile's menu.
             -- 'blocked' never appears: those rows are gone above.
             'state', app_friend_state(u.id),
             -- Null means "whatever the default for a DM is". The client owns
             -- that word, so the column is sent as it is rather than resolved.
             'level', (SELECT np.level FROM notification_prefs np
                        WHERE np.user_id = auth.uid()
                          AND np.scope = 'dm'::notify_scope
                          AND np.scope_id = u.id),
             -- What a "mark read" writes back. It has to come from the same
             -- read as the count, or the cursor would skip messages counted a
             -- moment earlier.
             'latest_inbound', COALESCE(
               (SELECT max(d.id) FROM dm_messages d
                 WHERE d.recipient_id = auth.uid() AND d.sender_id = u.id), 0),
             'unread', (
               SELECT count(*) FROM dm_messages d
                WHERE d.recipient_id = auth.uid()
                  AND d.sender_id = u.id
                  AND d.id > COALESCE(
                        (SELECT rs.last_read_id FROM read_state rs
                          WHERE rs.user_id = auth.uid()
                            AND rs.scope = 'dm'::read_scope
                            AND rs.scope_id = u.id), 0)),
             'last_message', jsonb_build_object(
               'id',           k.id,
               'created_at',   k.created_at,
               'sender_id',    k.sender_id,
               'recipient_id', k.recipient_id,
               'ciphertext',   k.ciphertext,
               'nonce',        k.nonce,
               'signature',    k.signature,
               'key_version',  k.key_version,
               'edited_at',    k.edited_at)
           ) AS row,
           k.id AS sort_id
      FROM kept k
      JOIN users u ON u.id = k.peer
  )
  SELECT jsonb_build_object(
           'conversations',
           COALESCE((SELECT jsonb_agg(row ORDER BY sort_id DESC) FROM rows),
                    '[]'::jsonb),
           'has_more',
           (SELECT count(*) FROM page) > (SELECT count(*) FROM kept));
$$;

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) IS
  'The caller''s DM conversations, newest first, a page at a time — or, given '
  'p_peer, just the one with that person. Read from dm_conversation_heads, so '
  'it costs a page rather than a history.';

-- ============================================================
-- A badge stops counting past ninety-nine
-- ============================================================
-- `unread_counts()` counts every unread DM a person has, exactly, and then
-- the client draws "99+" over anything above ninety-nine. So the difference
-- between the true answer and the drawn one is invisible, and the cost of
-- computing it is not: the count is unbounded, which means it grows with the
-- size of the backlog rather than with the size of the screen.
--
-- A server's channel badges stop at the same cap for the same reason.
--
-- Measured on 200,000 accounts, 5,100,000 DMs, 1,200,000 conversations:
--
--   503 conversations, ~40 unread each ......  22.6 ms  →  13.1 ms
--   the same, with 100,000 unread in one ....  235   ms  →  12.2 ms
--
-- The first column is what the size of a backlog costs. The second is that
-- it costs nothing, which is the point: somebody who has ignored a group of
-- friends for a year pays for the conversations they have, not the messages
-- in them.
--
-- ---------- why it is driven from the conversations ----------
--
-- The old shape was one grouped scan of `dm_messages` — every inbound
-- message the caller has, grouped by sender, joined to the read cursor. A
-- cap cannot be applied to that: `LIMIT` on a grouped query limits the
-- groups, not the rows inside them.
--
-- Driving from `dm_conversation_heads` instead gives a loop over the
-- conversations, each of which is a walk of
-- `idx_dm_messages_inbound_pair (recipient_id, sender_id, id)` from the
-- cursor forward, stopping at the cap. A constant sender and a constant
-- cursor are what let the planner use that index as a range — written as one
-- statement with a correlated subquery it chooses a scan instead.
--
-- SECURITY DEFINER, because `dm_conversation_heads` is deliberately
-- unreadable by `authenticated` — no grant, no policy. Every query
-- below is pinned to `auth.uid()`, and the inbound filter is *stricter* than
-- `dm_messages_select` would be — unread mail is what was sent to you, not
-- what you sent.

CREATE OR REPLACE FUNCTION unread_cap() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

COMMENT ON FUNCTION unread_cap() IS
  'Where a badge stops counting. UnreadBadge draws "99+" above ninety-nine, '
  'so a hundred and five thousand are the same picture.';

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_dms    JSONB := '{}'::jsonb;
  v_peer   RECORD;
  v_cursor BIGINT;
  v_n      INTEGER;
BEGIN
  IF v_me IS NULL THEN
    RETURN jsonb_build_object('dms', '{}'::jsonb,
                              'prefs', jsonb_build_object('dms', '{}'::jsonb));
  END IF;

  FOR v_peer IN
    SELECT h.peer_id FROM dm_conversation_heads h WHERE h.user_id = v_me
  LOOP
    SELECT r.last_read_id INTO v_cursor
      FROM read_state r
     WHERE r.user_id = v_me AND r.scope = 'dm' AND r.scope_id = v_peer.peer_id;
    v_cursor := COALESCE(v_cursor, 0);

    SELECT count(*) INTO v_n FROM (
      SELECT 1 FROM dm_messages d
       WHERE d.recipient_id = v_me
         AND d.sender_id = v_peer.peer_id
         AND d.id > v_cursor
       ORDER BY d.id
       LIMIT unread_cap()
    ) capped;

    IF v_n > 0 THEN
      v_dms := v_dms || jsonb_build_object(v_peer.peer_id::TEXT, v_n);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'dms', v_dms,
    'prefs', jsonb_build_object(
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = v_me AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

COMMENT ON FUNCTION unread_counts() IS
  'Unread DM badges and notification levels: {dms, prefs}. Counts stop at '
  'unread_cap(), so the work is the number of conversations rather than the '
  'number of messages in them.';

-- ============================================================
-- Rift central — 001: the tables
-- ============================================================
-- Every type, table and index the shared tier has, in the shape it is meant
-- to have. Nothing here describes how it got that way: central is built by
-- running these seven files in order against an empty database.
--
-- What central is for, and what it deliberately is not: it holds the account,
-- the handle, the friend graph, direct messages and the public directory —
-- the things that cannot live on any one self-hosted server because they span
-- all of them. It holds no server's membership, no channel, and no key. A DM
-- is ciphertext here exactly as a message is on a server.
--
-- Where the rest of it lives:
--   002_api        the RPCs clients call
--   003_triggers   attestation and the derived state
--   004_realtime   what a client may subscribe to, and what is broadcast
--   005_storage    buckets and their policies
--   006_jobs       scheduled cleanup
--   007_security   grants, RLS, and every policy — last, so that everything
--                  it names already exists
-- ============================================================

-- ============================================================
-- Schema
-- ============================================================
-- The central project is the discovery tier: people find each other by handle
-- and exchange first messages, then move real conversations to a self-hosted
-- server they share (ARCHITECTURE.md §4). It runs on no revenue, so its limits
-- — daily send quota, 30-day TTL, per-conversation cap — are the product, not
-- an implementation detail.
--
-- Until now this database had no migrations at all. It was provisioned by
-- pasting SQL into the Management API as features landed, and the only record
-- of its shape was a section of LOCAL_DEV.md. This set is that shape, written
-- down and corrected.
--
-- What changed in the writing down:
--   dm_profiles     -> users              it is the account row, and it will
--                                         hold more than a directory profile
--   user_id         -> id                 matches the self-hosted `users.id`,
--                                         and it is the GoTrue uid either way
--   dm_read_state   -> read_state         same shape as self-hosted, so one
--                                         client path badges both tiers
--
-- Client-facing effect: none of these are new concepts, only names that now
-- agree across the two tiers.

-- Only 'dm' is used here today. The type is shared with the self-hosted schema
-- so the read-cursor table is literally the same table in both places.
DO $$ BEGIN
  CREATE TYPE read_scope AS ENUM ('channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- Accounts
-- ============================================================
-- One row per central account. The handle is the whole point of the tier: it
-- is how someone is found before any contact exists, so the row is public to
-- signed-in users by design — a handle, and the keys needed to seal a first
-- message to them.

CREATE TABLE IF NOT EXISTS users (
  id                 UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  handle             TEXT        NOT NULL UNIQUE
                                 CHECK (handle ~ '^[a-z0-9_]{3,20}$'),
  -- X25519, for the pairwise DH that derives a DM key.
  chat_public_key    TEXT        NOT NULL CHECK (length(chat_public_key) <= 64),
  -- Ed25519, for verifying message signatures.
  signing_public_key TEXT        NOT NULL CHECK (length(signing_public_key) <= 64)
);

-- ============================================================
-- Direct messages
-- ============================================================
-- Same Design-1 envelope as a self-hosted server DM: sealed to a pairwise key,
-- signed by the sender, opaque here.

CREATE TABLE IF NOT EXISTS dm_messages (
  id           BIGSERIAL   PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext   TEXT        NOT NULL CHECK (length(ciphertext) <= 16384),
  nonce        TEXT        NOT NULL CHECK (length(nonce)      <= 64),
  signature    TEXT        NOT NULL CHECK (length(signature)  <= 128),
  key_version  INTEGER     NOT NULL CHECK (key_version >= 1),
  edited_at    TIMESTAMPTZ,
  CHECK (sender_id <> recipient_id)
);

CREATE INDEX IF NOT EXISTS idx_dm_messages_pair ON dm_messages
  (LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id), id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_recipient ON dm_messages (recipient_id, id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_sender    ON dm_messages (sender_id, id);

-- ============================================================
-- Read state
-- ============================================================
-- The newest message read per conversation. Central never needed a fanout
-- table: a client here can already read every message addressed to it, so all
-- that was ever missing was the bookmark.

CREATE TABLE IF NOT EXISTS read_state (
  user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope        read_scope  NOT NULL,
  -- The other person's user id, for 'dm'.
  scope_id     UUID        NOT NULL,
  last_read_id BIGINT      NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES    FROM anon;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon;

-- ============================================================
-- The public server directory
-- ============================================================
-- A server created in the app existed nowhere but on its own Supabase project
-- and in the vaults of the people already on it. There was no way to find one
-- you had not been handed an invite to, which made "self-hosted" and "private"
-- the same word — an operator who *wanted* to be found had no way to say so.
--
-- Central is the only place both sides already share, so the directory lives
-- here for the same reason handles do: you cannot join a server you cannot
-- find. It is the same tier and the same tenancy argument — a listing is a few
-- hundred bytes, it is written when an admin changes it rather than per
-- message, and it costs the project nothing to keep.
--
-- What a listing holds is deliberately **plaintext and public**, and that is
-- not a weakening of the trust model: everything else central stores is
-- encrypted because it belongs to the user, whereas a listing is an
-- advertisement. Its whole purpose is to be read by strangers. Publishing is
-- opt-in, per server, and reversible.
--
-- What it does NOT hold: the server's service key, its LiveKit credentials, or
-- anything about its members. Joining goes through the target server's own
-- `register` exactly as an invite link does — central hands out the address,
-- never the authority.

-- ============================================================
-- Listings
-- ============================================================
-- The unique key is (supabase_url, server_id) rather than server_id alone
-- because one Supabase project can host several servers, and
-- because a server id is only meaningful next to the host that issued it.

CREATE TABLE IF NOT EXISTS public_servers (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- The account that published it. Deleting the account withdraws the listing,
  -- which is right: nobody else is in a position to keep it accurate.
  owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Where the server lives. Not a foreign key to anything — this database has
  -- never heard of that Supabase project and never will.
  -- https only: central makes a request to this URL, so what may be
  -- written here is a security question rather than a formatting one.
  -- `http://` to a link-local address is the cloud-metadata attack in one
  -- line. `https://` to a *private* address is refused in the edge function,
  -- after resolution, where a DNS answer can be checked.
  supabase_url TEXT        NOT NULL CHECK (supabase_url ~ '^https://[^ ]+$'
                                           AND length(supabase_url) <= 200),
  server_id    UUID        NOT NULL,

  -- An ordinary invite code on the target server, minted unlimited-use and
  -- permissionless by the admin's client. It is what makes the listing worth
  -- anything, and revoking it there is what makes a listing stop working
  -- without central being involved at all.
  invite_code  TEXT        NOT NULL CHECK (length(invite_code) BETWEEN 4 AND 64),

  name         TEXT        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 64),
  description  TEXT                 CHECK (length(description) <= 300),
  icon_url     TEXT                 CHECK (length(icon_url) <= 500),

  -- Up to five lowercase slugs, which is the whole of the browser's filtering.
  -- A fixed category list would need a migration every time a community turns
  -- out to be about something we didn't think of.
  tags         TEXT[]      NOT NULL DEFAULT '{}'
                           CHECK (cardinality(tags) <= 5
                                  AND array_to_string(tags, ',') ~
                                      '^([a-z0-9-]{2,20}(,[a-z0-9-]{2,20})*)?$'),

  -- Self-reported by the admin's client, because central cannot count members
  -- of a database it has no credentials for. Treat it as what the operator
  -- claimed when they last saved, which is what `updated_at` is shown for.
  member_count INTEGER     NOT NULL DEFAULT 0 CHECK (member_count >= 0),

  -- Delisting keeps the row (and its invite code, and its description) while
  -- taking it out of the browser, so hiding a server for a week is not the
  -- same act as giving up its listing.
  is_listed    BOOLEAN     NOT NULL DEFAULT TRUE,

  UNIQUE (supabase_url, server_id)
);

-- Browsing is "listed, most populous first"; searching adds an ILIKE on top of
-- it. The table is small enough that the tag filter can scan, but a GIN index
-- costs one line and stops that being true only by luck.
CREATE INDEX IF NOT EXISTS idx_public_servers_browse
  ON public_servers (is_listed, member_count DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_public_servers_tags ON public_servers USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_public_servers_owner ON public_servers (owner_id);

-- ============================================================
-- Push notifications
-- ============================================================
-- Local notifications only fire while the process is alive. On Android that
-- means they stop as soon as the system suspends the app, which is most of the
-- time — so a message arriving then was silently lost until the user next
-- opened Rift. Only a push can wake it.
--
-- What travels in a push is nothing: no sender, no text, no conversation, not
-- even ciphertext. An FCM payload is readable by Google and forwardable by
-- whatever relays it, so anything put in one is disclosed to both. This is a
-- doorbell — the same shape as the Realtime doorbells the client already uses,
-- where the database is the truth and the ping only says "look again". The
-- phone holds the keys, so it can fetch and decrypt the message itself once it
-- is awake, and the notification loses no detail for being announced by an
-- empty envelope.

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;

-- ---------- where an account can be reached ----------
-- A row is a device, not a person: the same account on a phone and a tablet is
-- two rows and both should ring. The token is the key because FCM hands the
-- same one back to a reinstalled app, and a device that changes hands must
-- replace the previous owner's row rather than accumulate beside it.

CREATE TABLE IF NOT EXISTS device_tokens (
  token      TEXT        PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform   TEXT        NOT NULL CHECK (platform IN ('android', 'ios', 'web')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id);

-- ---------- where to ring ----------
-- One row, and nobody can read it. The sender lives in an edge function
-- holding the FCM credentials; this is only the address and the shared secret
-- that proves a call came from here. RLS with no policy at all is the point:
-- the trigger below reaches it as SECURITY DEFINER and no session ever can.

CREATE TABLE IF NOT EXISTS push_config (
  id       BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
  endpoint TEXT    NOT NULL,
  secret   TEXT    NOT NULL
);

-- ============================================================
-- Relaying pushes for self-hosted servers
-- ============================================================
-- An FCM registration token is scoped to the Firebase project the app was
-- built against, so only the holder of Rift's credentials can wake a Rift
-- install. Somebody running their own server has no such credentials and must
-- not be handed them — which would leave every self-hosted community unable to
-- reach its own members' phones. So they ask here, and central forwards.
--
-- The whole of what central learns by forwarding is a device token and a
-- moment. Not the sender, not the text, not the server or channel it happened
-- in: the payload `push_send` builds is empty either way.
--
-- What makes that safe to offer is that it is *credentialled*. Without one,
-- this would be an open FCM proxy for Rift's project, and anyone who came by a
-- token could ring the phone behind it. A credential is enrolled by a signed-in
-- central account — the server's admin — which gives every forward an owner,
-- a daily ceiling and a revoke button.

-- ---------- credentials ----------
-- No uniqueness on (supabase_url, server_id), deliberately. A unique key would
-- let the first account to name somebody else's server hold the only slot for
-- it, and central cannot check who really administers a database it has never
-- heard of. Minting a second credential for the same server is harmless: it is
-- only usable by whoever holds its secret, and the server itself stores one.
--
-- The URL and id are recorded for the owner's benefit — so a revoke list reads
-- as server names rather than as opaque ids. Nothing here trusts them.

CREATE TABLE IF NOT EXISTS push_relays (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  supabase_url TEXT        NOT NULL CHECK (supabase_url ~ '^https?://[^ ]+$'
                                           AND length(supabase_url) <= 200),
  server_id    UUID        NOT NULL,
  label        TEXT                 CHECK (length(label) <= 64),

  -- Only the digest. The secret is shown once, at enrolment, and written
  -- straight into the asking server's `push_config`; a leak of this table
  -- forwards nothing.
  secret_hash  TEXT        NOT NULL,

  -- A ceiling per calendar day (UTC), rolled by `claim_relay_push`. Generous
  -- for a community server and small enough that a stolen credential is a
  -- nuisance rather than a bill.
  daily_cap    INTEGER     NOT NULL DEFAULT 20000 CHECK (daily_cap > 0),
  rung_today   INTEGER     NOT NULL DEFAULT 0,
  window_date  DATE        NOT NULL DEFAULT current_date,

  is_disabled  BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_push_relays_owner ON push_relays (owner_id);

-- ============================================================
-- Per-conversation notification levels
-- ============================================================
-- The central half of a server's `notification_prefs`. Same table, same defaults,
-- same client path — minus the channel half, because central has no rooms.
--
-- So there are two levels here in practice, `all` and `none`: a DM is somebody
-- talking to you, and there is nobody else in it to be named among. `mentions`
-- exists in the type only so both tiers spell the setting the same way; a row
-- that somehow says it reads as `all`, which is the answer that loses nobody a
-- message.

DO $$ BEGIN
  CREATE TYPE notify_level AS ENUM ('all', 'mentions', 'none');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Spelled the same way as on a self-hosted server so both tiers answer one
-- client path, `server` included — central has no servers to scope anything
-- to, in the same way it has no channels and `read_scope` carries 'channel'
-- here regardless. An unused value costs nothing; two different types would
-- cost a branch in every caller.
DO $$ BEGIN
  CREATE TYPE notify_scope AS ENUM ('server', 'channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Keyed exactly like `read_state`. A row exists only where somebody has
-- changed something, so the default costs no write and "reset" is a DELETE.
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      notify_scope NOT NULL,
  -- The other person's user id, for 'dm'.
  scope_id   UUID         NOT NULL,
  level      notify_level NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

-- Watched, so a level set on one device reaches the others.
--
-- Without this the setting is per-device in everything but storage: written to
-- central, read once at sign-in, and never looked at again — so the desktop
-- you left open goes on announcing a conversation you muted on your phone.
-- Own-row RLS applies to a subscription as it does to a read, so what arrives
-- is only ever your own rows.
--
-- `REPLICA IDENTITY FULL` because clearing a pref is a DELETE, and a default
-- replica identity ships only the primary key — which here is the whole of
-- what the row said.
ALTER TABLE notification_prefs REPLICA IDENTITY FULL;

-- ============================================================
-- Friends, requests, blocks
-- ============================================================
-- Until now anybody could message anybody, and anybody could be found by
-- typing three letters. An open directory is the point — you cannot message
-- someone you cannot find — but "findable" must not mean "enumerable,
-- reachable, without limit, forever". The directory is the product; an open
-- inbox behind it would be an accident.
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
-- 8. Realtime
-- ============================================================
-- A request accepted on a phone has to reach the desktop, for the same reason
-- a notification preference does: the alternative is per-device state that
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

-- ============================================================
-- The conversation list, answered by the database
-- ============================================================
-- The self-hosted tier already learned this lesson; its own `dm_conversations`
-- carries the note:
--
--   "This was an edge function that pulled a thousand rows and grouped them in
--    TypeScript; DISTINCT ON does it in the database and returns only what's
--    shown."
--
-- Central was still running the version that lesson was about — in Dart rather
-- than TypeScript, but the same shape: `listRecentMessages(limit: 1000)`, then
-- a client-side scan for the newest row per peer and a second scan for the
-- unread counts. Three things were wrong with it, and only the first is about
-- bandwidth:
--
--   1. A thousand envelopes crossed the wire to render a list of, typically,
--      a dozen rows.
--   2. Past a thousand *total* envelopes it stopped being correct. An old
--      conversation fell off the list silently, and since those same rows were
--      where the unread badges came from, the badge went with it.
--   3. It could not page. There was nowhere to put the 31st conversation,
--      because the client had no cursor into a list it was deriving.
--
-- So the whole question moves here, and the answer carries everything a row
-- draws: the peer, their published keys, the newest envelope, the unread count,
-- the newest inbound id a "mark read" writes back, and how much that person is
-- allowed to interrupt. One paged call replaces four unbounded ones —
-- `listRecentMessages`, `directory_profiles`, `listReadCursors` and
-- `listNotificationLevels`, the last two of which grow a row per conversation
-- and so had a ceiling of their own.
--
-- ---------- why SECURITY DEFINER ----------
--
-- The same reason `directory_profiles` is. `users_select_directory` is
-- relationship-scoped — `id = auth.uid() OR knows_user(id)` — and a
-- conversation must keep opening after an unfriend or a block, because a DM key
-- is derived from the peer's published X25519 key and re-read on every launch.
-- A version that stopped answering would quietly make the other person's copy
-- of the conversation undecryptable. So the gate here is the same one
-- `directory_profiles` uses and no wider: a row appears only for somebody the
-- caller has actually exchanged a message with, which is exactly what having a
-- conversation means.

-- ============================================================
-- 1. Indexes for the per-peer questions
-- ============================================================
-- `idx_dm_messages_recipient (recipient_id, id)` already exists and answers
-- "my inbox, newest first". What the unread count and the newest-inbound id ask
-- is narrower — *this peer's* messages to me — and the pair columns let both be
-- an index range scan instead of a filter over the whole inbox.

CREATE INDEX IF NOT EXISTS idx_dm_messages_inbound_pair
  ON dm_messages (recipient_id, sender_id, id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_outbound_pair
  ON dm_messages (sender_id, recipient_id, id);

-- Where the sweep function lives, and the secret that proves a call came from
-- this database. One row that no session can read, exactly like push_config:
-- only the SECURITY DEFINER function below reaches it.
CREATE TABLE IF NOT EXISTS attachment_sweep_config (
  id       BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
  endpoint TEXT    NOT NULL,
  secret   TEXT    NOT NULL
);

-- ============================================================
-- DM limits that cost what they touch
-- ============================================================
-- Three queries grew with the size of the whole table rather than with the
-- one account or conversation they were about:
--
--   * The daily quota (send_dm, dm_quota) counts a sender's last 24 hours, but
--     the only index on the sender was (sender_id, id), so every send walked
--     every message that account had ever sent.
--   * Retention's age limit filtered on created_at, which had no index: a full
--     scan of dm_messages every night.
--   * Retention's 500-per-conversation cap ranked every row in the table by
--     conversation, every night, to find the few past the cap.
--
-- The first two get indexes. The third belongs at the one moment a
-- conversation can go past the cap — a send — where it is a walk down one
-- conversation's index instead of a sort of everyone's, so the nightly job
-- does not do it at all.

CREATE INDEX IF NOT EXISTS idx_dm_messages_sender_created
  ON dm_messages (sender_id, created_at);

CREATE INDEX IF NOT EXISTS idx_dm_messages_created
  ON dm_messages (created_at);

-- ============================================================
-- A conversation knows its own newest message
-- ============================================================
-- `dm_conversations()` read every DM you had ever exchanged with anybody in
-- order to hand back thirty rows. It could not do otherwise: the list is
-- ordered by each conversation's newest message, and the only way to find
-- that was `DISTINCT ON (peer)` over the whole of `dm_messages`, peer by peer,
-- sorted. Measured on a copy of this schema with 200 conversations of 500
-- messages — the per-conversation cap `send_dm` enforces, so this is the shape a
-- heavy account actually has:
--
--   dm_conversations() ....................... 230-270 ms
--   dm_conversations(30, NULL, <peer>) .......     2.4 ms
--
-- The narrow one is a hundred times faster because naming both people lets it
-- walk `idx_dm_messages_pair`. The wide one has no such index and cannot have
-- one:
--
--   * **There is no column to index.** "Peer" means whoever is not the
--     caller — a CASE evaluated per query, different for every account that
--     asks. An index is a fixed structure; this is not a fixed value.
--   * **A conversation lives under two keys.** What you sent is filed by
--     sender, what you received by recipient, and the newest message may be
--     either. No single index sees a whole conversation.
--   * **Even a perfect index would only save the sort.** `DISTINCT ON` still
--     walks every one of your messages to find each peer's maximum.
--
-- So this is the index, written by hand, because Postgres cannot derive it:
-- one row per person you talk to, holding the id of that conversation's
-- newest message. The list becomes a range scan of your own rows, newest
-- first, stop at thirty — the cost of a page rather than the cost of your
-- history.
--
-- Two rows per conversation, one from each side, rather than one keyed on the
-- ordered pair. A pair key sorts by whichever uuid happens to be lower, so
-- "my conversations" would be a scan of both halves and a merge; a row per
-- participant makes it one index and one direction. A conversation is small
-- and a duplicate of two uuids and a bigint is nothing next to what it buys.

-- ============================================================
-- 1. The heads
-- ============================================================

CREATE TABLE IF NOT EXISTS dm_conversation_heads (
  user_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_message_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, peer_id)
);

COMMENT ON TABLE dm_conversation_heads IS
  'One row per person you have a conversation with, holding that '
  'conversation''s newest message id. Maintained by trigger; it is what makes '
  'the conversation list cost a page instead of a history.';

-- The whole point: your conversations, newest first, without a sort.
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_recent
  ON dm_conversation_heads (user_id, last_message_id DESC);

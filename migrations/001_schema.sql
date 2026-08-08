-- ============================================================
-- Rift central server — 001: schema
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
--   dm_reactions    -> dm_message_reactions   same name as the self-hosted
--                                         table holding the same thing
--   dm_read_state   -> read_state         same shape as self-hosted, so one
--                                         client path badges both tiers
--
-- Client-facing effect: none of these are new concepts, only names that now
-- agree across the two tiers.

CREATE EXTENSION IF NOT EXISTS pg_cron;

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
-- signed-in users by design (002) — a handle, and the keys needed to seal a
-- first message to them.

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

-- New sends go through send_dm() so the quota is enforced in one place, but
-- edits and deletes are ordinary RLS writes — so the server's word about who
-- sent a message and when still has to be enforced here rather than trusted
-- from the client.
CREATE OR REPLACE FUNCTION attest_dm() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;
    RETURN NEW;
  END IF;

  NEW.id           := OLD.id;
  NEW.sender_id    := OLD.sender_id;
  NEW.recipient_id := OLD.recipient_id;
  NEW.created_at   := OLD.created_at;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS attest_dm_messages ON dm_messages;
CREATE TRIGGER attest_dm_messages BEFORE INSERT OR UPDATE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION attest_dm();

-- ============================================================
-- Reactions
-- ============================================================
-- Not E2E, same accepted trade-off as the self-hosted tier: the server sees who
-- reacted with which emoji, never what the message said.

CREATE TABLE IF NOT EXISTS dm_message_reactions (
  message_id BIGINT      NOT NULL REFERENCES dm_messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)       ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_dm_message_reactions_message
  ON dm_message_reactions (message_id);

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

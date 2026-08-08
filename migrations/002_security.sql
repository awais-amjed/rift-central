-- ============================================================
-- Rift central server — 002: grants, RLS, policies
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
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES    FROM anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;

GRANT SELECT, INSERT ON users TO authenticated;
GRANT UPDATE (handle, chat_public_key, signing_public_key) ON users TO authenticated;

-- No INSERT: new messages go through send_dm(), which is where the daily quota
-- lives. Editing and deleting your own are ordinary writes — an edit is not a
-- new message and must not cost quota.
GRANT SELECT, DELETE ON dm_messages TO authenticated;
GRANT UPDATE (ciphertext, nonce, signature, key_version) ON dm_messages TO authenticated;

GRANT SELECT, INSERT, DELETE ON dm_message_reactions TO authenticated;

GRANT SELECT, INSERT ON read_state TO authenticated;
GRANT UPDATE (last_read_id, updated_at) ON read_state TO authenticated;

-- ============================================================
-- 2. Row-level security
-- ============================================================

ALTER TABLE users                ENABLE ROW LEVEL SECURITY;
ALTER TABLE dm_messages          ENABLE ROW LEVEL SECURITY;
ALTER TABLE dm_message_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_state           ENABLE ROW LEVEL SECURITY;

-- ---------- users (the directory) ----------
-- Readable by every signed-in account on purpose: you cannot message someone
-- you cannot find, and the row holds only a handle and two public keys.

DROP POLICY IF EXISTS users_select_directory ON users;
CREATE POLICY users_select_directory ON users FOR SELECT TO authenticated
  USING (true);

DROP POLICY IF EXISTS users_insert_self ON users;
CREATE POLICY users_insert_self ON users FOR INSERT TO authenticated
  WITH CHECK (id = auth.uid());

DROP POLICY IF EXISTS users_update_self ON users;
CREATE POLICY users_update_self ON users FOR UPDATE TO authenticated
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- ---------- dm_messages ----------

DROP POLICY IF EXISTS dm_messages_select ON dm_messages;
CREATE POLICY dm_messages_select ON dm_messages FOR SELECT TO authenticated
  USING (auth.uid() IN (sender_id, recipient_id));

DROP POLICY IF EXISTS dm_messages_update_own ON dm_messages;
CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid()) WITH CHECK (sender_id = auth.uid());

-- Hard delete, and it removes the message for the recipient too: there is one
-- row per message, and in an E2E app "deleted" has to mean the ciphertext is
-- gone rather than hidden behind a flag.
DROP POLICY IF EXISTS dm_messages_delete_own ON dm_messages;
CREATE POLICY dm_messages_delete_own ON dm_messages FOR DELETE TO authenticated
  USING (sender_id = auth.uid());

-- ---------- reactions ----------

DROP POLICY IF EXISTS dm_reactions_select ON dm_message_reactions;
CREATE POLICY dm_reactions_select ON dm_message_reactions FOR SELECT TO authenticated
  USING (EXISTS (
    SELECT 1 FROM dm_messages m
     WHERE m.id = dm_message_reactions.message_id
       AND auth.uid() IN (m.sender_id, m.recipient_id)
  ));

DROP POLICY IF EXISTS dm_reactions_insert ON dm_message_reactions;
CREATE POLICY dm_reactions_insert ON dm_message_reactions FOR INSERT TO authenticated
  WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
      SELECT 1 FROM dm_messages m
       WHERE m.id = dm_message_reactions.message_id
         AND auth.uid() IN (m.sender_id, m.recipient_id)
    )
  );

DROP POLICY IF EXISTS dm_reactions_delete_own ON dm_message_reactions;
CREATE POLICY dm_reactions_delete_own ON dm_message_reactions FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- ---------- read_state ----------
-- Own-row only, which is also what keeps it from becoming a read receipt: a
-- sender can never see whether their message was read.

DROP POLICY IF EXISTS read_state_own ON read_state;
CREATE POLICY read_state_own ON read_state FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- ============================================================
-- Rift central — 012: a read on one device reaches the others
-- ============================================================
-- Read cursors were always kept here (`read_state`), so a DM read on the phone
-- *was* read. But nothing told the desktop: it counted again only when it
-- refreshed its conversation list for some other reason, so its badge stayed
-- until the conversation was opened there too.
--
--   * A cursor that moves forward is told to its owner's own topic as `read`,
--     beside `prefs`. Every device of that person hears it and counts again;
--     one that already shows nothing unread there need not.
--
-- The same shape as a self-hosted server's (its 026), so the app hears both
-- tiers alike: one statement that moved one cursor names it (`scope`,
-- `scope_id`, `last_read_id`); one that moved several says `{}`; a write that
-- moved nothing — a conversation already read, opened again — says nothing.
-- ============================================================

CREATE OR REPLACE FUNCTION announce_read() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row RECORD;
BEGIN
  -- Two branches rather than one query: `old_rows` exists only for an UPDATE,
  -- and PL/pgSQL plans a statement only when it reaches it.
  IF TG_OP = 'INSERT' THEN
    FOR v_row IN
      SELECT n.user_id, count(*) AS moved,
             min(n.scope::TEXT) AS scope, min(n.scope_id::TEXT) AS scope_id,
             max(n.last_read_id) AS last_read_id
        FROM new_rows n
       WHERE n.last_read_id > 0
       GROUP BY n.user_id
    LOOP
      PERFORM tell_user(v_row.user_id, 'read',
        CASE WHEN v_row.moved = 1 THEN jsonb_build_object(
               'scope', v_row.scope, 'scope_id', v_row.scope_id,
               'last_read_id', v_row.last_read_id)
             ELSE '{}'::JSONB END);
    END LOOP;
  ELSE
    FOR v_row IN
      SELECT n.user_id, count(*) AS moved,
             min(n.scope::TEXT) AS scope, min(n.scope_id::TEXT) AS scope_id,
             max(n.last_read_id) AS last_read_id
        FROM new_rows n
        JOIN old_rows o USING (user_id, scope, scope_id)
       WHERE n.last_read_id > o.last_read_id
       GROUP BY n.user_id
    LOOP
      PERFORM tell_user(v_row.user_id, 'read',
        CASE WHEN v_row.moved = 1 THEN jsonb_build_object(
               'scope', v_row.scope, 'scope_id', v_row.scope_id,
               'last_read_id', v_row.last_read_id)
             ELSE '{}'::JSONB END);
    END LOOP;
  END IF;
  RETURN NULL;
END $$;

COMMENT ON FUNCTION announce_read() IS
  'Tells a person''s own topic that a read cursor of theirs moved forward, so '
  'their other devices clear the badge. One broadcast per statement and person: '
  'the cursor when one moved, {} when several did.';

-- Two triggers, because a trigger with transition tables may have one event.
-- `mark_read`'s upsert fires the INSERT one for a new cursor and the UPDATE one
-- for an existing cursor; each sees only its own rows.
DROP TRIGGER IF EXISTS read_state_announce_insert ON read_state;
CREATE TRIGGER read_state_announce_insert
  AFTER INSERT ON read_state
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION announce_read();

DROP TRIGGER IF EXISTS read_state_announce_update ON read_state;
CREATE TRIGGER read_state_announce_update
  AFTER UPDATE ON read_state
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION announce_read();

REVOKE ALL ON FUNCTION announce_read() FROM PUBLIC, anon, authenticated;

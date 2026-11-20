-- ============================================================
-- Rift central — 017: a moderator can switch a push relay off
-- ============================================================
-- From the Nov 18 review (finding 9). Any account with a handle may enrol a
-- push relay for a server it runs (`enroll_push_relay`), and a relay rings
-- whatever device tokens its server sends, up to its daily cap. That is the
-- design: central cannot know a self-hosted server's members, so it trusts
-- the server to ring its own. But `is_disabled`, which `claim_relay_push`
-- already honours, was set by nothing, so a relay being abused could not be
-- stopped short of deleting its owner's account.
--
-- So moderators can see every relay, how much it rang today, and switch one
-- off or on again (`moderation_push_relays`, `moderation_set_relay_disabled`).
-- Like every `moderation_*` function, each checks inside that the caller is
-- a moderator signed in with the second factor.
-- ============================================================

CREATE OR REPLACE FUNCTION moderation_push_relays() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_out JSONB;
BEGIN
  PERFORM assert_central_admin();
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', r.id, 'created_at', r.created_at,
           'owner_id', r.owner_id, 'owner_handle', u.handle,
           'supabase_url', r.supabase_url, 'server_id', r.server_id,
           'label', r.label, 'daily_cap', r.daily_cap,
           'rung_today', CASE WHEN r.window_date = current_date THEN r.rung_today ELSE 0 END,
           'is_disabled', r.is_disabled)
           -- The busiest first: a relay worth a look is one ringing a lot.
           ORDER BY r.is_disabled,
                    CASE WHEN r.window_date = current_date THEN r.rung_today ELSE 0 END DESC,
                    r.created_at DESC), '[]'::jsonb)
    INTO v_out
    FROM push_relays r
    LEFT JOIN users u ON u.id = r.owner_id;
  RETURN v_out;
END; $$;

CREATE OR REPLACE FUNCTION moderation_set_relay_disabled(p_relay UUID, p_disabled BOOLEAN)
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM assert_central_admin();
  UPDATE push_relays SET is_disabled = p_disabled WHERE id = p_relay;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'relay_not_found';
  END IF;
END; $$;

REVOKE ALL ON FUNCTION moderation_push_relays()                       FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_set_relay_disabled(UUID, BOOLEAN)   FROM PUBLIC, anon, authenticated;
-- To every signed-in account, as the other moderation functions are: the
-- check that matters is inside.
GRANT EXECUTE ON FUNCTION moderation_push_relays()                     TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_set_relay_disabled(UUID, BOOLEAN) TO authenticated;

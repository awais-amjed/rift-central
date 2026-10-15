-- ============================================================
-- Rift central — 009: the accounts list
-- ============================================================
-- How many people have a Rift account, and whether they still use it, was
-- answerable only with a shell on the database. GitHub's download counts
-- cannot answer it: they count updates and repeat downloads, and say nothing
-- about who. This gives the admin site a list of every Rift account, for a
-- moderator with a second factor, like everything else there.
--
-- What a row carries is what central already holds about an account and
-- nothing it learns for this: the handle, the sign-up email, when it signed
-- up and confirmed, when it was last active, and what it has in the
-- directory. "Last active" is the latest of a sign-in and a session refresh,
-- because the app signs in once and then only refreshes; a sign-in date alone
-- would call a daily user gone since the week they installed.
--
-- Moderator accounts are left out: they live in `auth.users` too, but are
-- not Rift accounts and can never become one (`central_admins`). An account
-- that signed up and never claimed a handle is listed, with none.
-- ============================================================

CREATE OR REPLACE FUNCTION moderation_accounts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_out JSONB;
BEGIN
  PERFORM assert_central_admin();

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', a.id, 'handle', u.handle, 'email', a.email,
           'created_at', a.created_at,
           'email_confirmed_at', a.email_confirmed_at,
           'last_active_at', GREATEST(a.last_sign_in_at, s.last_refresh),
           'sessions', COALESCE(s.sessions, 0),
           'servers_listed', (SELECT count(*) FROM public_servers p WHERE p.owner_id = a.id),
           'bots_listed', (SELECT count(*) FROM public_bots b WHERE b.owner_id = a.id),
           'banned', EXISTS (SELECT 1 FROM directory_bans d WHERE d.user_id = a.id))
           ORDER BY a.created_at DESC), '[]'::jsonb)
    INTO v_out
    FROM auth.users a
    LEFT JOIN users u ON u.id = a.id
    -- GoTrue keeps `refreshed_at` in UTC without a zone, and `updated_at`
    -- with one; either may be the later.
    LEFT JOIN LATERAL (
      SELECT count(*) AS sessions,
             GREATEST(max(x.updated_at), max(x.refreshed_at AT TIME ZONE 'UTC')) AS last_refresh
        FROM auth.sessions x
       WHERE x.user_id = a.id
    ) s ON TRUE
   WHERE NOT EXISTS (SELECT 1 FROM central_admins m WHERE m.user_id = a.id);
  RETURN v_out;
END; $$;

-- 007's blanket revoke ran before this existed.
REVOKE ALL ON FUNCTION moderation_accounts() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION moderation_accounts() TO authenticated;

-- ============================================================
-- Rift central — 027: the handle hold's last gap, a token Google refuses
-- ============================================================
-- From the pre-deploy review of Nov 27.
--
--   1. 022 checks a handle's hold after the write too, for a claim that
--      passed the check before it and then waited. But the check before it
--      (`refuse_held_handle`, 020) still ends by deleting any hold on the
--      handle, and that delete takes a fresh snapshot. So a claim racing a
--      rename could pass the check, then delete the hold the rename had just
--      committed, and the check after found nothing to refuse it with. Now
--      the delete takes only what the check let through: the claimer's own
--      hold, or one that has run out. A hold for anybody else that turns up
--      in between stays, and the check after the write refuses on it.
--   2. 025 keeps Google's access token for every push worker. A token
--      Google refuses (the key swapped for another project's, the service
--      account disabled) would then be handed out until it expired, an hour
--      of rings that went nowhere. A worker that is refused now forgets it,
--      here too, and mints another.
-- ============================================================

-- ---------- 1. the hold ----------
-- 020's function, with the delete narrowed to what the check above it lets
-- through. EvalPlanQual rechecks the condition on a row a concurrent rename
-- updated, so a hold that rename just wrote is not taken.
CREATE OR REPLACE FUNCTION refuse_held_handle() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.handle IS NOT DISTINCT FROM OLD.handle THEN
    RETURN NEW;
  END IF;
  IF EXISTS (SELECT 1 FROM released_handles r
              WHERE r.handle = NEW.handle
                AND r.released_at > now() - make_interval(days => handle_hold_days())
                AND r.previous_owner IS DISTINCT FROM NEW.id) THEN
    RAISE EXCEPTION 'handle_held' USING ERRCODE = 'unique_violation';
  END IF;
  DELETE FROM released_handles r
   WHERE r.handle = NEW.handle
     AND (r.previous_owner = NEW.id
          OR r.released_at <= now() - make_interval(days => handle_hold_days()));
  RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION refuse_held_handle() FROM PUBLIC, anon, authenticated;

-- ---------- 2. a refused token ----------
-- Forget the token, if it is still the one kept. A worker refused with an
-- old token must not delete a newer one another worker has kept since.
CREATE OR REPLACE FUNCTION forget_push_access_token(p_value TEXT) RETURNS VOID
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  DELETE FROM push_private.access_token WHERE value = p_value
$$;

REVOKE ALL ON FUNCTION forget_push_access_token(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION forget_push_access_token(TEXT) TO service_role;

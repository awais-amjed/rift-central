-- ============================================================
-- Rift central — 020: a dropped handle is held for 30 days
-- ============================================================
-- From the Nov 18 review (finding 22). A handle given up — changed for
-- another, or gone with its account — could be claimed by anybody the same
-- moment. Friends find each other by handle, so whoever took it could pass
-- for its old owner to everybody who knew them by it.
--
-- Now a handle given up is held for 30 days (`released_handles`):
--   * after a rename, only the account that gave it up may take it back;
--   * after the account is deleted, nobody may have it.
-- Then it is free again, and the nightly job forgets it. Claiming a held
-- handle fails as a taken one does (unique_violation), so a client already
-- says the right thing; `is_handle_available` says no to it as well, except
-- to the account it is held for.
--
-- A deleted account's id is not kept: its holds keep the handle and nothing
-- about who had it.
-- ============================================================

CREATE TABLE IF NOT EXISTS released_handles (
  handle         TEXT        PRIMARY KEY,
  -- Who may take it back. NULL once the account is gone: then nobody may.
  previous_owner UUID,
  released_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Read only by the functions below.
ALTER TABLE released_handles ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON released_handles FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION handle_hold_days() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 30 $$;

-- ---------- taking one ----------
-- Before a handle is set, on a new row or a changed one. A handle held for
-- this account is given back, and the hold goes; held for anyone else, or
-- for nobody, is taken.
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
  DELETE FROM released_handles WHERE handle = NEW.handle;
  RETURN NEW;
END; $$;

-- ---------- giving one up ----------
CREATE OR REPLACE FUNCTION hold_renamed_handle() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.handle IS DISTINCT FROM OLD.handle THEN
    INSERT INTO released_handles (handle, previous_owner, released_at)
         VALUES (OLD.handle, OLD.id, now())
    ON CONFLICT (handle) DO UPDATE
          SET previous_owner = EXCLUDED.previous_owner,
              released_at    = EXCLUDED.released_at;
  END IF;
  RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION hold_deleted_handle() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO released_handles (handle, previous_owner, released_at)
       VALUES (OLD.handle, NULL, now())
  ON CONFLICT (handle) DO UPDATE
        SET previous_owner = NULL, released_at = EXCLUDED.released_at;
  -- Handles this account gave up earlier stay held, for nobody now.
  UPDATE released_handles SET previous_owner = NULL WHERE previous_owner = OLD.id;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS users_refuse_held_handle ON users;
CREATE TRIGGER users_refuse_held_handle BEFORE INSERT OR UPDATE OF handle ON users
  FOR EACH ROW EXECUTE FUNCTION refuse_held_handle();

DROP TRIGGER IF EXISTS users_hold_renamed_handle ON users;
CREATE TRIGGER users_hold_renamed_handle AFTER UPDATE OF handle ON users
  FOR EACH ROW EXECUTE FUNCTION hold_renamed_handle();

DROP TRIGGER IF EXISTS users_hold_deleted_handle ON users;
CREATE TRIGGER users_hold_deleted_handle AFTER DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION hold_deleted_handle();

-- ---------- asking ----------
-- As before, plus the hold. `auth.uid()` is NULL for anon, and a hold for
-- NULL (a deleted account) must still answer no, hence the COALESCE.
CREATE OR REPLACE FUNCTION is_handle_available(p_handle TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT lower(trim(p_handle)) ~ '^[a-z0-9_]{3,20}$'
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.handle = lower(trim(p_handle)))
     AND NOT EXISTS (SELECT 1 FROM released_handles r
                      WHERE r.handle = lower(trim(p_handle))
                        AND r.released_at > now() - make_interval(days => handle_hold_days())
                        AND NOT COALESCE(r.previous_owner = auth.uid(), FALSE))
$$;

-- ---------- forgetting ----------
-- At 03:57, after the night's other jobs.
SELECT cron.unschedule('central-handle-hold-prune')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-handle-hold-prune');

SELECT cron.schedule(
  'central-handle-hold-prune',
  '57 3 * * *',
  $$ DELETE FROM public.released_handles
      WHERE released_at < now() - make_interval(days => public.handle_hold_days()); $$
);

REVOKE ALL ON FUNCTION handle_hold_days()     FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION refuse_held_handle()   FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION hold_renamed_handle()  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION hold_deleted_handle()  FROM PUBLIC, anon, authenticated;

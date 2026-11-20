-- ============================================================
-- Rift central — 018: no deleting an account the day its password changed
-- ============================================================
-- From the Nov 18 review (finding 15). `delete_account` asks for a password
-- sign-in in the last ten minutes, so a copied token alone cannot delete an
-- account. But Auth lets a session under a day old set a new password with
-- no emailed code (`user.go`: the reauthentication check is skipped while
-- the session is young), so a token copied soon after a sign-in could set a
-- password, sign in with it, and delete.
--
-- Requiring the current password for a change would close that too, and
-- break what it is for: a signed-in device whose owner forgot the password
-- proves the inbox instead. So the account remembers when its password last
-- changed, and `delete_account` refuses for a day after (`password_changed_
-- recently`). Auth emails the owner when the password changes
-- (GOTRUE_MAILER_NOTIFICATIONS_PASSWORD_CHANGED_ENABLED), and that day is
-- theirs to take the account back by resetting it from the email.
-- ============================================================

CREATE TABLE IF NOT EXISTS password_changes (
  user_id    UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Read by `delete_account` with the service key, and by nobody else.
ALTER TABLE password_changes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON password_changes FROM PUBLIC, anon, authenticated;
GRANT SELECT ON password_changes TO service_role;

-- A change, not the first password: sign-up sets it on insert, and an
-- account given its first password has nothing to have been taken from.
CREATE OR REPLACE FUNCTION note_password_change() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF COALESCE(OLD.encrypted_password, '') <> ''
     AND NEW.encrypted_password IS DISTINCT FROM OLD.encrypted_password THEN
    INSERT INTO password_changes (user_id, changed_at) VALUES (NEW.id, now())
    ON CONFLICT (user_id) DO UPDATE SET changed_at = now();
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS users_note_password_change ON auth.users;
CREATE TRIGGER users_note_password_change AFTER UPDATE OF encrypted_password ON auth.users
  FOR EACH ROW EXECUTE FUNCTION note_password_change();

REVOKE ALL ON FUNCTION note_password_change() FROM PUBLIC, anon, authenticated;

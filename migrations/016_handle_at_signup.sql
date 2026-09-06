-- ============================================================
-- Rift central server — 016: asking for a handle before there is an account
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

REVOKE ALL ON FUNCTION is_handle_available(TEXT) FROM public;
GRANT EXECUTE ON FUNCTION is_handle_available(TEXT) TO anon, authenticated;

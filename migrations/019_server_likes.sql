-- ============================================================
-- Rift central — 019: server listings are liked, and ranked by it
-- ============================================================
-- From the Nov 18 review (finding 21). The server browser was ordered by
-- `public_servers.member_count`, which the publishing admin's client reports
-- and central cannot check, so a listing could put itself first by claiming
-- a large number.
--
-- Bots are ranked by likes for the same reason (001, `bot_likes`), and
-- servers now are too: `server_likes`, one row per account and listing,
-- counted into `public_servers.like_count` by trigger so the browse can use
-- an index. The browser offers Top (likes) and New (newest listing), as the
-- bot browser does. `member_count` stays on the row as what the operator
-- claims, and orders nothing.
--
-- A like is keyed by the listing's own id, so withdrawing a listing and
-- publishing it again starts it from nothing, as it does for a bot.
-- ============================================================

ALTER TABLE public_servers
  ADD COLUMN IF NOT EXISTS like_count INTEGER NOT NULL DEFAULT 0
    CHECK (like_count >= 0);

-- `listing_id`, not `server_id`: on `public_servers` that name is the
-- server's own id inside its database, which is a different thing.
-- `user_id` references `users`, so liking needs a claimed handle, as it does
-- for a bot: a bare sign-up is not a vote.
CREATE TABLE IF NOT EXISTS server_likes (
  listing_id UUID        NOT NULL REFERENCES public_servers(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)          ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (listing_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_server_likes_user ON server_likes (user_id);

-- The two orders the browser offers. `created_at` breaks the tie rather than
-- `updated_at`, so publishing again does not lift an old listing.
DROP INDEX IF EXISTS idx_public_servers_browse;
CREATE INDEX IF NOT EXISTS idx_public_servers_top
  ON public_servers (is_listed, like_count DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_public_servers_new
  ON public_servers (is_listed, created_at DESC);

-- ---------- the count ----------
-- As `recount_bot_likes`: recounted from the table rather than adjusted, and
-- SECURITY DEFINER because nobody liking has an UPDATE grant on the listing.
CREATE OR REPLACE FUNCTION recount_server_likes() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_listing UUID := COALESCE(NEW.listing_id, OLD.listing_id);
BEGIN
  UPDATE public_servers
     SET like_count = (SELECT count(*) FROM server_likes WHERE listing_id = v_listing)
   WHERE id = v_listing;
  RETURN NULL;
END; $$;

-- A like is the caller's, whatever the insert said.
CREATE OR REPLACE FUNCTION stamp_server_like() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.created_at := now();
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS server_likes_stamp ON server_likes;
CREATE TRIGGER server_likes_stamp BEFORE INSERT ON server_likes
  FOR EACH ROW EXECUTE FUNCTION stamp_server_like();

DROP TRIGGER IF EXISTS server_likes_recount ON server_likes;
CREATE TRIGGER server_likes_recount AFTER INSERT OR DELETE ON server_likes
  FOR EACH ROW EXECUTE FUNCTION recount_server_likes();

-- ---------- who may like ----------
-- As `bot_likes`: public, because the count is the ranking; written only as
-- your own; and only on a listing the caller can see, so a delisted or
-- hidden one (not one's own) is the same as none.
ALTER TABLE server_likes ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON server_likes FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, DELETE ON server_likes TO authenticated;

DROP POLICY IF EXISTS server_likes_select ON server_likes;
CREATE POLICY server_likes_select ON server_likes FOR SELECT TO authenticated
  USING (TRUE);

DROP POLICY IF EXISTS server_likes_insert_own ON server_likes;
CREATE POLICY server_likes_insert_own ON server_likes FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid()
              AND EXISTS (SELECT 1 FROM public_servers p WHERE p.id = listing_id));

DROP POLICY IF EXISTS server_likes_delete_own ON server_likes;
CREATE POLICY server_likes_delete_own ON server_likes FOR DELETE TO authenticated
  USING (user_id = auth.uid());

REVOKE ALL ON FUNCTION recount_server_likes() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION stamp_server_like()    FROM PUBLIC, anon, authenticated;

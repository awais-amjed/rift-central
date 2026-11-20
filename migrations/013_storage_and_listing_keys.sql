-- ============================================================
-- Rift central — 013: who may read a DM file, what each bucket
-- holds, one listing per server however its address is spelled
-- ============================================================
-- Four fixes from the Nov 18 review, none of which changes what a client
-- sends or reads.
--
--   1. A DM attachment could be listed and downloaded by every account.
--      `central_dm_att_select` checked the bucket and nothing else. The bytes
--      are sealed under a key only the message carries, so nobody outside the
--      conversation could open one — but anybody could list who uploads what,
--      how much and when, and take a copy. Now only the uploader and the
--      people they have sent a DM to may read their folder.
--
--   2. Every bucket took any file type. Central's buckets are on the API's
--      own domain, so an `image/svg+xml` page uploaded as a "backup" was a
--      script served from api.joinrift.app to whoever opened its signed
--      link. Each bucket now takes only the type Rift itself uploads to it.
--      (The links themselves are closed for the two private buckets nobody
--      signs in Kong; see the stack's kong.yml.)
--
--   3. A moderator's hide, and a deleted ban's mark on a server, keyed the
--      listing by the address exactly as typed. `https://a.example.com/` is
--      the same server as `https://A.example.com` and as
--      `https://a.example.com:443`, and the server's own token verifies for
--      all of them, so republishing under a new spelling made a fresh row,
--      not hidden and not marked. A listing is now one per `server_url_key`
--      — the address's scheme and host, lower-cased, without a default port,
--      a trailing dot or a path — and a mark matches by the same key.
--
--   4. `authenticated` kept Supabase's default USAGE on public sequences,
--      which nothing granted on purpose. Members insert into no table with a
--      serial id, so they need none.
-- ============================================================

-- ============================================================
-- 1. Reading a DM attachment
-- ============================================================
-- An attachment lives in its uploader's folder (`<uid>/<random>.bin`), and the
-- recipient downloads it from there by the path in the message. The name
-- says nothing about the conversation, so "may this account read it" is
-- answered by the one thing central does know: whether the uploader has sent
-- this account a DM that is still kept. Messages go after 30 days and their
-- files after 31, so a file nobody can reach any more is one nobody has a key
-- for either.
--
-- That lets someone you have written to see your other files' sizes and
-- times in your folder, never their bytes' meaning. Putting the recipient in
-- the path would close that too, and needs every client updated first.
--
-- A definer function rather than the query inline: the policy runs per row
-- when a folder is listed, and here the pair index answers it in one probe
-- whichever of the two is asking. It reads only `auth.uid()`'s own messages.

CREATE OR REPLACE FUNCTION dm_attachment_readable(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_folder TEXT := NULLIF(split_part(p_name, '/', 1), p_name);
  v_owner  UUID;
BEGIN
  IF v_me IS NULL OR v_folder IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_folder = v_me::TEXT THEN
    RETURN TRUE;
  END IF;
  -- A folder that is not a lower-case uuid is nobody's: uploads only land
  -- under `auth.uid()::text`, which is always this shape.
  IF v_folder !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN FALSE;
  END IF;
  v_owner := v_folder::UUID;
  RETURN EXISTS (
    SELECT 1 FROM dm_messages m
     WHERE LEAST(m.sender_id, m.recipient_id)    = LEAST(v_owner, v_me)
       AND GREATEST(m.sender_id, m.recipient_id) = GREATEST(v_owner, v_me)
       AND m.sender_id = v_owner);
END $$;

REVOKE ALL ON FUNCTION dm_attachment_readable(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION dm_attachment_readable(TEXT) TO authenticated;

DROP POLICY IF EXISTS central_dm_att_select ON storage.objects;
CREATE POLICY central_dm_att_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'central-dm-attachments' AND dm_attachment_readable(name));

-- ============================================================
-- 2. What each bucket takes
-- ============================================================
-- Exactly what the app has uploaded to each since the bucket existed, and
-- nothing a browser would run. Storage checks the Content-Type of every
-- upload against this list and stores it with the file, which is what it
-- serves the file as.
--
--   backups                 the vault export, JSON that is ciphertext inside
--   central-dm-attachments  sealed bytes
--   directory-icons         a PNG the publisher's client drew at 48px
--   bug-reports             the app's log files, gzipped, or as plain text
--                           from the web, which has no gzip

UPDATE storage.buckets SET allowed_mime_types = ARRAY['application/json']
 WHERE id = 'backups';
UPDATE storage.buckets SET allowed_mime_types = ARRAY['application/octet-stream']
 WHERE id = 'central-dm-attachments';
UPDATE storage.buckets SET allowed_mime_types = ARRAY['image/png']
 WHERE id = 'directory-icons';
UPDATE storage.buckets SET allowed_mime_types = ARRAY['application/gzip', 'text/plain']
 WHERE id = 'bug-reports';

-- ============================================================
-- 3. One listing per server, however its address is spelled
-- ============================================================
-- The key is the address's origin as a browser would compare it, minus the
-- path. The path is dropped rather than kept because the listing proof
-- ignores it: `publish_server` asks `/functions/v1/verify_listing_token` at
-- the host's root, so any path verifies, and a key that kept it would let
-- each new one make a fresh listing. The edge function refuses a host in
-- anything but plain ASCII, since a URL parser reads percent-escapes and
-- Unicode as the same machine and this does not.
--
-- What is stored stays as the publisher typed it: clients look their own
-- listing up by the address they hold, and that must keep matching.

-- The SET is load-bearing. Without it Postgres inlines the body into the
-- queries that use it — but only for a role allowed to call it, and the index's
-- copy is inlined or not by whichever role first loaded the table. When the two
-- differ, the upserts below stop matching the index and raise "no unique or
-- exclusion constraint matching the ON CONFLICT specification". A function
-- with a SET is never inlined, so both sides always agree.
CREATE OR REPLACE FUNCTION server_url_key(p_url TEXT) RETURNS TEXT
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
  -- The trailing dot goes before or without a port: `host.:8443` is
  -- `host:8443`.
  SELECT regexp_replace(regexp_replace(lower(substring(p_url FROM '^[A-Za-z]+://[^/?#]+')),
                                       ':443$', ''),
                        '\.+(:[0-9]+)?$', '\1')
$$;

REVOKE ALL ON FUNCTION server_url_key(TEXT) FROM PUBLIC, anon, authenticated;

-- Fails, and stops the deploy, if two listings already share a key. Nothing
-- here picks which of them should survive; a moderator does.
CREATE UNIQUE INDEX IF NOT EXISTS public_servers_url_key
  ON public_servers (server_url_key(supabase_url), server_id);

-- The two writes, by the key. Each is 002's with two changes: the owner is
-- looked up by key, and the upsert lands on the key's row, taking the new
-- spelling with it — the publisher's client looks the listing up by the
-- address it just sent. `hidden_at` is still left alone, which is the point.

CREATE OR REPLACE FUNCTION publish_server(
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_path    TEXT    DEFAULT NULL,
  p_tags         TEXT[]  DEFAULT '{}',
  p_member_count INTEGER DEFAULT 0,
  p_is_listed    BOOLEAN DEFAULT TRUE
) RETURNS public_servers
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_owner UUID;
  v_count INTEGER;
  v_row   public_servers;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;
  IF EXISTS (SELECT 1 FROM directory_bans WHERE user_id = auth.uid()) THEN
    RAISE EXCEPTION 'publisher_banned';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE server_url_key(supabase_url) = server_url_key(p_supabase_url)
     AND server_id = p_server_id;

  IF v_owner IS NOT NULL AND v_owner <> auth.uid() THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = auth.uid();
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_path, tags,
                              member_count, is_listed)
       VALUES (auth.uid(), p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_path,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (server_url_key(supabase_url), server_id) DO UPDATE
          SET supabase_url = EXCLUDED.supabase_url,
              invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_path    = EXCLUDED.icon_path,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

CREATE OR REPLACE FUNCTION publish_server_as(
  p_owner        UUID,
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_path    TEXT    DEFAULT NULL,
  p_tags         TEXT[]  DEFAULT '{}',
  p_member_count INTEGER DEFAULT 0,
  p_is_listed    BOOLEAN DEFAULT TRUE
) RETURNS public_servers
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_owner UUID;
  v_count INTEGER;
  v_row   public_servers;
BEGIN
  IF p_owner IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_owner) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;
  IF EXISTS (SELECT 1 FROM directory_bans WHERE user_id = p_owner) THEN
    RAISE EXCEPTION 'publisher_banned';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE server_url_key(supabase_url) = server_url_key(p_supabase_url)
     AND server_id = p_server_id;

  IF v_owner IS NOT NULL AND v_owner <> p_owner THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = p_owner;
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_path, tags,
                              member_count, is_listed)
       VALUES (p_owner, p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_path,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (server_url_key(supabase_url), server_id) DO UPDATE
          SET supabase_url = EXCLUDED.supabase_url,
              invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_path    = EXCLUDED.icon_path,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

-- CREATE OR REPLACE keeps a function's grants, and these two had theirs set
-- in 007: the service role only. Said again so this file stands alone.
REVOKE ALL ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                      TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT,
                                         TEXT, TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT,
                                            TEXT, TEXT[], INTEGER, BOOLEAN)
  TO service_role;

-- A deleted ban's mark, by the same key.
CREATE OR REPLACE FUNCTION refuse_marked_server() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM directory_ban_marks
              WHERE kind = 'server'
                AND server_url_key(supabase_url) = server_url_key(NEW.supabase_url)
                AND server_id = NEW.server_id) THEN
    RAISE EXCEPTION 'server_banned';
  END IF;
  RETURN NEW;
END; $$;

CREATE INDEX IF NOT EXISTS directory_ban_marks_server_key
  ON directory_ban_marks (server_url_key(supabase_url), server_id)
  WHERE kind = 'server';

-- ============================================================
-- 4. Sequences
-- ============================================================

REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM authenticated;

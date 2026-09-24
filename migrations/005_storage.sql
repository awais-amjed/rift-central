-- ============================================================
-- Rift central — 005: buckets
-- ============================================================
-- Three: `central-dm-attachments`, which holds the same AES-256-GCM ciphertext
-- a DM body does; `backups`, which holds an encrypted vault export — central
-- can read neither; and `directory-icons`, which is the odd one out and holds
-- plaintext pictures central serves itself, on purpose.
-- ============================================================

-- ============================================================
-- Storage
-- ============================================================
-- Two private buckets, both own-folder on write so an object can only ever be
-- placed under the uploader's own uid.
--
--   backups                  the encrypted vault export. Sealed with a key
--                            derived from the user's own passphrase — central
--                            holds bytes it cannot open, which is the entire
--                            point of the backup feature.
--   central-dm-attachments   E2E attachment blobs, AES-256-GCM under a per-file
--                            key carried inside the encrypted message body.
--                            10 MB against the self-hosted 25 MB: central pays
--                            for this storage, a server operator pays for
--                            their own.

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('backups', 'backups', false, 5242880)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 5242880;

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('central-dm-attachments', 'central-dm-attachments', false, 10485760)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 10485760;

DROP POLICY IF EXISTS backups_select_own ON storage.objects;
CREATE POLICY backups_select_own ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'backups'
         AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS backups_insert_own ON storage.objects;
CREATE POLICY backups_insert_own ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'backups'
              AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS backups_update_own ON storage.objects;
CREATE POLICY backups_update_own ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'backups'
         AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS backups_delete_own ON storage.objects;
CREATE POLICY backups_delete_own ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'backups'
         AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS central_dm_att_select ON storage.objects;
CREATE POLICY central_dm_att_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'central-dm-attachments');

DROP POLICY IF EXISTS central_dm_att_insert ON storage.objects;
CREATE POLICY central_dm_att_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'central-dm-attachments'
              AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS central_dm_att_delete ON storage.objects;
CREATE POLICY central_dm_att_delete ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'central-dm-attachments'
         AND (storage.foldername(name))[1] = auth.uid()::text);

-- ============================================================
-- Directory icons
-- ============================================================
-- The picture beside a listing in the browser, held here rather than linked.
--
-- **Why it moved.** A listing used to carry an `icon_url`, and the directory
-- drew it straight from that address — which the *publisher* chose. Opening
-- the browser therefore fetched a picture from every listed party at once, so
-- each of them learned the IP and the minute of everyone who was merely
-- looking, including the listings nobody went on to join. For a server that
-- address was its own public `servers` bucket, which needs no session, so the
-- operator saw raw addresses. It is the same tracking `LinkPreview` exists to
-- refuse — bytes captured once by the person who chose them, rather than
-- fetched per reader — and the answer is the same one: copy the picture at
-- publish time and serve it from here.
--
-- Central learns who browsed, and already did: it served the rows.
--
-- **Plaintext, and private anyway.** Unlike every other bucket here these
-- bytes are not ciphertext — a picture shown to everyone browsing gains
-- nothing from being sealed, the same trade avatars make on a server. Private
-- rather than public-read so the open internet cannot enumerate it: browsing
-- the directory needs an account already, because `public_servers` and
-- `public_bots` are both `TO authenticated`.
--
-- 256 KB. An icon is drawn at 48px and the publisher's client downscales
-- before it uploads; the ceiling is what a modified one cannot talk past.

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('directory-icons', 'directory-icons', false, 262144)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 262144;

-- Anybody signed in may look, which is the whole job — everyone browsing the
-- directory draws every icon on the page.
DROP POLICY IF EXISTS directory_icons_select ON storage.objects;
CREATE POLICY directory_icons_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'directory-icons');

-- Own folder on write, like every other bucket here. A listing belongs to an
-- account, so the folder is that account's uid and nobody can place a picture
-- under anybody else's.
DROP POLICY IF EXISTS directory_icons_insert ON storage.objects;
CREATE POLICY directory_icons_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'directory-icons'
              AND (storage.foldername(name))[1] = auth.uid()::text);

-- No update policy. A path is minted once and never written twice: replacing
-- the bytes under a name every client has cached is how a directory ends up
-- showing last week's icon next to this week's name.
DROP POLICY IF EXISTS directory_icons_delete ON storage.objects;
CREATE POLICY directory_icons_delete ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'directory-icons'
         AND (storage.foldername(name))[1] = auth.uid()::text);

-- ============================================================
-- What stops one account filling the bucket
-- ============================================================
-- The lesson from the server schema's `avatars`, which had a write policy
-- scoped to the caller's own folder and nothing else: a per-folder rule says
-- where bytes may go, never how many. Publishing writes a fresh path each
-- time, so editing a listing's picture leaves the old object behind, and a
-- modified client can upload in a loop.
--
-- Two bounds, because one is a timer and the other is not. `expired_directory_icons`
-- below is swept nightly and takes away every object no listing names; this
-- refuses the upload that would take an account past its ceiling in between.

CREATE OR REPLACE FUNCTION icons_per_account() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 12 $$;

CREATE OR REPLACE FUNCTION refuse_excess_icons() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_owner TEXT;
BEGIN
  IF NEW.bucket_id <> 'directory-icons' THEN
    RETURN NEW;
  END IF;
  v_owner := (storage.foldername(NEW.name))[1];
  IF v_owner IS NOT NULL
     AND (SELECT count(*) FROM storage.objects o
           WHERE o.bucket_id = 'directory-icons'
             AND (storage.foldername(o.name))[1] = v_owner) >= icons_per_account() THEN
    RAISE EXCEPTION
      'Too many listing icons stored for this account — the unused ones are cleared up shortly'
      USING ERRCODE = 'disk_full';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS directory_icons_ceiling ON storage.objects;
CREATE TRIGGER directory_icons_ceiling BEFORE INSERT ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION refuse_excess_icons();

-- Everything in the bucket that no listing points at, for the nightly sweep.
-- The grace period is the same rail `orphaned_attachments` uses on a server:
-- the picture is uploaded before the row that names it, so without one a sweep
-- landing in that window deletes an icon whose listing is milliseconds away
-- from existing.
CREATE OR REPLACE FUNCTION expired_directory_icons(
  p_limit INTEGER  DEFAULT 1000,
  p_grace INTERVAL DEFAULT '1 hour'
) RETURNS SETOF TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'directory-icons'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM public_servers s WHERE s.icon_path = o.name)
     AND NOT EXISTS (SELECT 1 FROM public_bots    b WHERE b.icon_path = o.name)
   ORDER BY o.name
   LIMIT GREATEST(p_limit, 0)
$$;

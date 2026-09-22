-- ============================================================
-- Rift central — 005: buckets
-- ============================================================
-- Two: `central-dm-attachments`, which holds the same AES-256-GCM ciphertext a
-- DM body does, and `backups`, which holds an encrypted vault export. Central
-- can read neither.
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

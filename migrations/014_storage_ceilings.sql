-- ============================================================
-- Rift central — 014: how much one account may store
-- ============================================================
-- From the Nov 18 review (finding 3): only `directory-icons` had a bound per
-- account (`refuse_excess_icons`, 005). Every other bucket bounded a file and
-- not how many of them, so one confirmed account uploading in a loop could
-- fill central's disk, and a full disk stops Postgres and everything with it.
--
--   backups                 one file per account, the one the app writes:
--                           `<uid>/vault.json`, replaced on every backup. The
--                           bucket's 5 MB file limit is then the account's.
--   central-dm-attachments  1 GB and 5,000 files per account. The nightly
--                           sweep (006) takes every file older than 31 days,
--                           so this is a month's sending, and the space comes
--                           back as old files go.
--   bug-reports             100 MB per account. Ten reports a day of four
--                           10 MB files, kept 90 days, was 36 GB; a real
--                           report's logs are well under a megabyte.
--
-- Nothing a client sends changes. A refused upload answers 403 with the
-- message `account_storage_full`, which the app puts into words.
-- ============================================================

-- ============================================================
-- 1. Backups: the one file
-- ============================================================
-- The app has only ever written `<uid>/vault.json` (an upsert), so naming it
-- in the policy refuses nothing Rift does. Reading and deleting stay as 005
-- left them, so a file under any other name from before this still reads and
-- deletes.

DROP POLICY IF EXISTS backups_insert_own ON storage.objects;
CREATE POLICY backups_insert_own ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'backups'
              AND name = auth.uid()::text || '/vault.json');

DROP POLICY IF EXISTS backups_update_own ON storage.objects;
CREATE POLICY backups_update_own ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'backups'
         AND (storage.foldername(name))[1] = auth.uid()::text)
  WITH CHECK (bucket_id = 'backups'
              AND name = auth.uid()::text || '/vault.json');

-- ============================================================
-- 2. A ceiling per account on the buckets that have a sweep
-- ============================================================
-- What one account may hold in a bucket: bytes, and files where the count
-- is not already bounded some other way. NULL for a bucket this does not
-- govern. A function, as `icons_per_account` is, so the tests read the same
-- numbers the trigger does.

CREATE OR REPLACE FUNCTION account_storage_ceiling(
  p_bucket TEXT,
  OUT max_bytes BIGINT,
  OUT max_files INTEGER
) LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_bucket
           WHEN 'central-dm-attachments' THEN 1073741824::BIGINT
           WHEN 'bug-reports'            THEN  104857600::BIGINT
         END,
         CASE p_bucket
           WHEN 'central-dm-attachments' THEN 5000
         END
$$;

-- A file's size as Storage recorded it, or 0 when it did not. Storage writes
-- an object's row twice: once before the upload, in a transaction it rolls
-- back, to ask the policies — with the size the client declared as
-- `contentLength` — and once after, with the size it wrote as `size`. So the
-- trigger below refuses an upload before its bytes are sent, on the declared
-- size, and again after, on the real one; a refusal there makes Storage
-- delete the bytes it just wrote.
--
-- Never below 0 and never a cast that can fail: PostgREST publishes the
-- `storage` schema (review finding 17), so a member can insert a row of
-- their own, with whatever `metadata` they like. A row like that holds no
-- bytes on disk, and a negative size must not buy room for some that do.
CREATE OR REPLACE FUNCTION stored_object_size(p_metadata JSONB) RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
           WHEN p_metadata ->> 'size' ~ '^[0-9]{1,15}$'
             THEN (p_metadata ->> 'size')::BIGINT
           WHEN p_metadata ->> 'contentLength' ~ '^[0-9]{1,15}$'
             THEN (p_metadata ->> 'contentLength')::BIGINT
           ELSE 0
         END
$$;

CREATE OR REPLACE FUNCTION refuse_over_account_ceiling() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_ceiling RECORD;
  v_owner   TEXT;
  v_files   INTEGER;
  v_bytes   BIGINT;
BEGIN
  SELECT * INTO v_ceiling FROM account_storage_ceiling(NEW.bucket_id);
  IF v_ceiling.max_bytes IS NULL THEN
    RETURN NEW;
  END IF;
  -- The folder by `foldername`'s rule, as `refuse_excess_icons` takes it.
  -- A name with no folder is no account's, and each bucket's insert policy
  -- refuses it already.
  v_owner := NULLIF(split_part(NEW.name, '/', 1), NEW.name);
  IF v_owner IS NULL THEN
    RETURN NEW;
  END IF;
  -- The prefix range `refuse_excess_icons` explains, answered by Storage's
  -- (bucket_id, name COLLATE "C") index. The object being written is left
  -- out: an upsert replaces it rather than adding to it.
  SELECT count(*), COALESCE(sum(stored_object_size(o.metadata)), 0)
    INTO v_files, v_bytes
    FROM storage.objects o
   WHERE o.bucket_id = NEW.bucket_id
     AND o.name COLLATE "C" >= v_owner || '/'
     AND o.name COLLATE "C" <  v_owner || '0'
     AND o.name <> NEW.name;
  IF v_bytes + stored_object_size(NEW.metadata) > v_ceiling.max_bytes
     OR v_files >= v_ceiling.max_files THEN
    -- 42501 with no mention of row-level security: Storage passes the
    -- message through as a 403 (`DBError.fromDBError`), where any other code
    -- comes out as "database error" and a 500.
    RAISE EXCEPTION 'account_storage_full' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS account_storage_ceiling ON storage.objects;
CREATE TRIGGER account_storage_ceiling BEFORE INSERT ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION refuse_over_account_ceiling();

-- ============================================================
-- Privileges
-- ============================================================
-- None of the three is anything a member calls. The trigger runs as its
-- definer whoever inserts.

REVOKE ALL ON FUNCTION account_storage_ceiling(TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION stored_object_size(JSONB) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION refuse_over_account_ceiling() FROM PUBLIC, anon, authenticated;

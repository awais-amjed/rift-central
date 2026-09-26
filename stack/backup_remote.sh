# Sourced by backup.sh and restore.sh: the bucket, as rclone reaches it.
#
# Defines `rc` — rclone in a container, docker's options before `--` and
# rclone's after — with two remotes, both encrypted views of the one bucket:
#
#   db:     the dumps, under db/. Folder names readable (hourly, daily,
#           weekly) for the bucket's rules to match; file names encrypted.
#   files:  Storage's files, under files/. Every name encrypted, folders
#           included: they are user ids.
#
# Secrets reach the containers as `-e NAME` with the value in this process's
# environment, never as an argument, so none of them shows up in `ps`.

RCLONE_IMAGE=rclone/rclone:1.75.1
NETWORK=rift-central_default
STORAGE_VOLUME=rift-central_storage-data

env_value() { sed -n "s/^$1='\(.*\)'\$/\1/p" .env; }
for name in BACKUP_S3_ENDPOINT BACKUP_S3_ACCESS_KEY_ID BACKUP_S3_SECRET_ACCESS_KEY \
            BACKUP_BUCKET BACKUP_PASSWORD BACKUP_SALT; do
  [[ -n $(env_value "$name") ]] || { echo "$name is empty in .env — backups are not configured." >&2; exit 1; }
done

obscure() { printf '%s' "$1" | docker run --rm -i "$RCLONE_IMAGE" obscure -; }

export RCLONE_CONFIG_BUCKET_TYPE=s3
export RCLONE_CONFIG_BUCKET_PROVIDER; RCLONE_CONFIG_BUCKET_PROVIDER=$(env_value BACKUP_S3_PROVIDER)
export RCLONE_CONFIG_BUCKET_ENDPOINT; RCLONE_CONFIG_BUCKET_ENDPOINT=$(env_value BACKUP_S3_ENDPOINT)
export RCLONE_CONFIG_BUCKET_ACCESS_KEY_ID; RCLONE_CONFIG_BUCKET_ACCESS_KEY_ID=$(env_value BACKUP_S3_ACCESS_KEY_ID)
export RCLONE_CONFIG_BUCKET_SECRET_ACCESS_KEY; RCLONE_CONFIG_BUCKET_SECRET_ACCESS_KEY=$(env_value BACKUP_S3_SECRET_ACCESS_KEY)
export RCLONE_CONFIG_BUCKET_REGION=auto
# A token scoped to one bucket cannot list buckets, and rclone would ask.
export RCLONE_CONFIG_BUCKET_NO_CHECK_BUCKET=true

# Two encrypted views of the one bucket, differing only in whether folder
# names are encrypted too.
password=$(obscure "$(env_value BACKUP_PASSWORD)")
salt=$(obscure "$(env_value BACKUP_SALT)")
for remote in DB FILES; do
  export "RCLONE_CONFIG_${remote}_TYPE=crypt"
  export "RCLONE_CONFIG_${remote}_PASSWORD=$password"
  export "RCLONE_CONFIG_${remote}_PASSWORD2=$salt"
done
export RCLONE_CONFIG_DB_REMOTE; RCLONE_CONFIG_DB_REMOTE="bucket:$(env_value BACKUP_BUCKET)/db"
export RCLONE_CONFIG_DB_DIRECTORY_NAME_ENCRYPTION=false
export RCLONE_CONFIG_FILES_REMOTE; RCLONE_CONFIG_FILES_REMOTE="bucket:$(env_value BACKUP_BUCKET)/files"
unset password salt

rclone_env=()
for name in $(compgen -e | grep '^RCLONE_CONFIG_'); do rclone_env+=(-e "$name"); done
# Docker's options before `--`, rclone's after.
rc() {
  local docker_args=()
  while [[ $# -gt 0 && $1 != -- ]]; do docker_args+=("$1"); shift; done
  shift
  docker run --rm -i --network "$NETWORK" "${rclone_env[@]}" "${docker_args[@]}" \
    "$RCLONE_IMAGE" --retries 3 --log-level ERROR "$@"
}

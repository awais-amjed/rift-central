#!/usr/bin/env bash
# Create or remove a moderator account for the admin site (rift-admin).
#
#   scripts/add_admin.sh you@example.com "Your name"   # asks for a password
#   scripts/add_admin.sh --remove you@example.com
#
# A moderator is its own account, not a Rift account: an auth user with a
# password and no profile, listed in `central_admins` (001). This creates both
# halves. The site then makes the new account set up an authenticator app on
# its first sign-in, and central refuses every moderation call without it.
#
# The password is typed here and goes straight to Supabase Auth; nothing else
# sees it. Piped rather than typed when stdin is not a terminal, so it can be
# scripted — never pass it as an argument, where it would land in the shell's
# history and in `ps`.
#
# Needs the Supabase CLI to be logged in (its token is read from the system
# keyring) and `secret-tool`, `curl` and `python3`. CENTRAL_REF picks the
# project; it defaults to the one the app ships with.
set -euo pipefail

REF="${CENTRAL_REF:-fjkrobvftxqqapvhgtuw}"
URL="https://$REF.supabase.co"
API="https://api.supabase.com/v1/projects/$REF"

usage() {
  sed -n '4,6p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

remove=false
if [[ ${1:-} == --remove ]]; then
  remove=true
  shift
fi
email="${1:-}"
name="${2:-Moderator}"
[[ -n $email ]] || usage
[[ $email == *@* ]] || { echo "That does not look like an email address." >&2; exit 1; }

# ── Credentials, held in variables only ─────────────────────
token=$(secret-tool search --all service "Supabase CLI" 2>/dev/null |
  sed -n 's/^secret = //p' | head -1)
case "$token" in
  go-keyring-base64:*) token=$(printf %s "${token#go-keyring-base64:}" | base64 -d) ;;
esac
[[ -n $token ]] || { echo "No Supabase CLI token in the keyring — run 'supabase login'." >&2; exit 1; }

# The Management API refuses curl's default user agent (Cloudflare 1010).
#
# Keys go to curl as a header file on a pipe rather than as `-H` arguments: an
# argument is readable by anyone on the machine, in `ps`, for as long as the
# request runs. `printf` is a builtin, so it never becomes a process of its own.
mgmt() { curl -sS -A rift-admin-script/1.0 -H @<(printf 'Authorization: Bearer %s\n' "$token") "$@"; }

secret=$(mgmt "$API/api-keys?reveal=true" | python3 -c '
import json, sys
keys = [k for k in json.load(sys.stdin) if k.get("type") == "secret"]
print(keys[0]["api_key"] if keys else "")')
[[ -n $secret ]] || { echo "Could not read the project's secret key." >&2; exit 1; }

auth() { curl -sS -H @<(printf 'apikey: %s\n' "$secret") -H "Content-Type: application/json" "$@"; }

sql() {
  python3 -c 'import json, sys; print(json.dumps({"query": sys.stdin.read()}))' |
    mgmt -X POST "$API/database/query" -H "Content-Type: application/json" --data @-
}

# The one value that goes into SQL, quoted as a literal.
quote() { printf "'%s'" "${1//\'/\'\'}"; }

user_id() {
  printf 'SELECT id FROM auth.users WHERE lower(email) = lower(%s);' "$(quote "$email")" |
    sql | python3 -c '
import json, sys
rows = json.load(sys.stdin)
print(rows[0]["id"] if isinstance(rows, list) and rows else "")'
}

# ── Removing ────────────────────────────────────────────────
if $remove; then
  id=$(user_id)
  [[ -n $id ]] || { echo "No account with that email." >&2; exit 1; }
  printf 'DELETE FROM central_admins WHERE user_id = %s;' "$(quote "$id")" | sql >/dev/null
  auth -X DELETE "$URL/auth/v1/admin/users/$id" >/dev/null
  echo "Removed moderator $email."
  exit 0
fi

# ── Adding ──────────────────────────────────────────────────
if [[ -n $(user_id) ]]; then
  echo "An account with that email already exists. Moderator accounts are" >&2
  echo "separate from Rift accounts, so use an address with no Rift account." >&2
  exit 1
fi

if [[ -t 0 ]]; then
  read -rsp "Password for $email: " password; echo
  read -rsp "Again: " again; echo
  [[ $password == "$again" ]] || { echo "The two did not match." >&2; exit 1; }
else
  read -r password
fi
if (( ${#password} < 16 )); then
  echo "Use at least 16 characters — this account can take any listing down." >&2
  exit 1
fi

# Through stdin, so the password is never an argument of anything.
created=$(python3 -c '
import json, sys
print(json.dumps({"email": sys.argv[1],
                  "password": sys.stdin.read().rstrip("\n"),
                  "email_confirm": True}))' "$email" <<<"$password" |
  auth -X POST "$URL/auth/v1/admin/users" --data @-)
unset password again

id=$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("id", ""))' <<<"$created")
if [[ -z $id ]]; then
  echo "Supabase refused the account:" >&2
  python3 -c 'import json, sys; d = json.load(sys.stdin); print(d.get("msg") or d.get("message") or d)' \
    <<<"$created" >&2
  exit 1
fi

result=$(printf 'INSERT INTO central_admins (user_id, name) VALUES (%s, %s);' \
  "$(quote "$id")" "$(quote "$name")" | sql)
if [[ $result != "[]" ]]; then
  # Not a moderator after all, so do not leave a bare account behind.
  auth -X DELETE "$URL/auth/v1/admin/users/$id" >/dev/null
  echo "Could not make it a moderator: $result" >&2
  exit 1
fi

echo "Moderator $email ($name) created. Sign in on the admin site; it will ask"
echo "you to set up an authenticator app first."

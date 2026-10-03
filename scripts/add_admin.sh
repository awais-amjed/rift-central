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
# The password is typed here and goes straight to central's Auth; nothing else
# sees it. Piped rather than typed when stdin is not a terminal, so it can be
# scripted — never pass it as an argument, where it would land in the shell's
# history and in `ps`.
#
# Run on the machine that hosts the stack in `stack/`: the secret key comes
# from its `.env` and SQL goes to its database container. Needs `curl` and
# `python3`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  sed -n '4,5p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

remove=false
while [[ ${1:-} == --* ]]; do
  case $1 in
    --remove) remove=true ;;
    *) usage ;;
  esac
  shift
done
email="${1:-}"
name="${2:-Moderator}"
[[ -n $email ]] || usage
[[ $email == *@* ]] || { echo "That does not look like an email address." >&2; exit 1; }

# ── Credentials, held in variables only ─────────────────────
env_value() { sed -n "s/^$1='\(.*\)'\$/\1/p" "$ROOT/stack/.env"; }

[[ -r $ROOT/stack/.env ]] || { echo "No stack/.env here — run stack/setup.py first." >&2; exit 1; }
# Kong on loopback, not the public address: this runs on the same machine.
URL="http://127.0.0.1:$(env_value KONG_PORT)"
secret=$(env_value SECRET_KEY)
[[ -n $secret ]] || { echo "Could not read the stack's secret key." >&2; exit 1; }

auth() { curl -sS -H @<(printf 'apikey: %s\n' "$secret") -H "Content-Type: application/json" "$@"; }

# One statement in, and what comes back: a JSON array of rows, `[]` for a
# statement that returns none, or the error.
sql() {
  local query out
  query=$(cat)
  if [[ $query == SELECT* ]]; then
    query="SELECT coalesce(json_agg(r), '[]') FROM (${query%;}) r;"
  fi
  if out=$(printf '%s' "$query" |
             docker exec -i central-db psql -U postgres -tAq -v ON_ERROR_STOP=1 2>&1); then
    if [[ $query == SELECT* ]]; then printf '%s\n' "$out"; else echo "[]"; fi
  else
    printf '%s\n' "$out"
  fi
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
  echo "Auth refused the account:" >&2
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

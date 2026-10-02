#!/usr/bin/env bash
# Fail if a shipped migration was edited, or a new one is not locked yet.
#
# The numbered files under migrations/ ship: they run on real databases, each
# once, recorded by name and checksum. Editing one afterwards changes nothing on
# a database that already ran it, and stops the next deploy at the checksum.
# So a change to the schema is always a new numbered file, and
# migrations/locked.sha256 holds the checksum of every file as it shipped.
#
# A new file is locked in the commit that adds it:
#   (cd migrations && sha256sum 009_example.sql >> locked.sha256)
#
#   ./scripts/check_locked.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../migrations"

failed=0
while read -r sum name; do
  if [[ ! -f $name ]]; then
    echo "FAIL: $name is locked but gone. A shipped migration is never deleted." >&2
    failed=1
  elif [[ $(sha256sum "$name" | cut -d' ' -f1) != "$sum" ]]; then
    echo "FAIL: $name has changed since it was locked. Put the change in a new numbered file." >&2
    failed=1
  fi
done < locked.sha256
for f in [0-9][0-9][0-9]_*.sql; do
  if ! grep -q "  $f\$" locked.sha256; then
    echo "FAIL: $f is not locked. Add it: (cd migrations && sha256sum $f >> locked.sha256)" >&2
    failed=1
  fi
done
[[ $failed == 0 ]] || exit 1
echo "   ok  every shipped migration is as it shipped"

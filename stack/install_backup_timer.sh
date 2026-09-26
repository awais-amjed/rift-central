#!/usr/bin/env bash
# Install the hourly backup as a systemd timer. Run once, as root, after the
# BACKUP_S3_* keys are in .env and `./backup.sh` has worked by hand.
#
#   sudo ./install_backup_timer.sh
#
# Afterwards: `systemctl list-timers rift-central-backup` says when it runs
# next, `journalctl -u rift-central-backup` shows what each run did.
set -euo pipefail
stack="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID -eq 0 ]] || { echo "Run it with sudo." >&2; exit 1; }

sed "s|@STACK@|$stack|" "$stack/systemd/rift-central-backup.service" \
  > /etc/systemd/system/rift-central-backup.service
install -m 644 "$stack/systemd/rift-central-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rift-central-backup.timer
systemctl list-timers rift-central-backup.timer --no-pager

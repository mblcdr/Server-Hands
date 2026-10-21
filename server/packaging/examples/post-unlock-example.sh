#!/bin/sh
# Example Server Hands post-unlock script. Copy it, edit it, and register it in /etc/server-hands/config.toml:
#
#   [[script]]
#   name = "media"
#   label = "Media containers"
#   path = "/etc/server-hands/scripts/media.sh"
#   mode = "manual"        # or "auto" to run as soon as every drive is unlocked
#
# Requirements: owned by root, not writable by group/others, directory too (handsd checks this before every run).
# It runs as root in a transient unit named server-hands-script-<name>; output is in the journal:
#   journalctl -u server-hands-script-media
# $SERVER_HANDS_TRIGGER is "auto" or "manual". A non-zero exit shows as "failed" in the app.
set -eu

docker compose -f /srv/dev-disk-by-uuid-XXXX/appdata/media/compose.yml up -d

#!/bin/sh
# Phase 2 exit check, run on the server after installing the .deb:
#   sudo ./check-security.sh
# Fails if systemd's exposure score for handsd.service is above 3.0 ("OK" band is <= 4.0; we aim tighter).
# Needs systemd >= 250 for --threshold (Debian 13 ships 257).
set -eu
systemd-analyze security handsd.service --no-pager
exec systemd-analyze security handsd.service --no-pager --threshold=30 >/dev/null

#!/bin/bash
# Rotate xray access.log daily, keep 7 days
#
# Config via environment variables:
#   XTP_AGSBX_DIR - agsbx install dir (default /root/agsbx)
#   XTP_API_PORT  - xray API port for logger restart (default 10085)

AGSBX="${XTP_AGSBX_DIR:-/root/agsbx}"
API_PORT="${XTP_API_PORT:-10085}"
cd "$AGSBX" || exit 1

for i in 6 5 4 3 2 1; do
    n=$((i + 1))
    [ -f "access.log.$i" ] && mv "access.log.$i" "access.log.$n" 2>/dev/null
done
[ -f access.log ] && mv access.log access.log.1 2>/dev/null

# ask xray to reopen its log file
pkill -USR1 -f 'xray run' 2>/dev/null || true
sleep 1
"$AGSBX/xray" api restartlogger --server="127.0.0.1:$API_PORT" 2>/dev/null || true

echo "rotated at $(date '+%F %T')"

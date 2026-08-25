#!/bin/bash
# Watchdog: ensure tcpdump capture is running. Called by cron every minute.
# If tcpdump died (crash, file limit, OOM...), restart it and rotate old pcaps.

CAPTURE_SCRIPT=/root/agsbx/panel/capture.sh
PCAP_DIR=/root/agsbx/pcap
LOG=/root/agsbx/pcap/watchdog.log

if pgrep -f 'tcpdump -i eth0' > /dev/null 2>&1; then
  exit 0
fi

# tcpdump not running -> restart
# clean old pcaps (keep last ~10 files) to free space before restart
cd "$PCAP_DIR" 2>/dev/null || exit 0
ls -1t cap_*.pcap 2>/dev/null | tail -n +11 | xargs -r rm -f

nohup "$CAPTURE_SCRIPT" > "$PCAP_DIR/capture.log" 2>&1 &
echo "$(date '+%F %T') watchdog: tcpdump was down, restarted" >> "$LOG"

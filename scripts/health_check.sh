#!/bin/bash
# Data health sentinel for traffic panel.
# Checks: pcap freshness, dumpcap process, systemd service, disk, panel data.
# Logs issues; auto-restarts capture (throttled 5min) if pcap is stale/down.
#
# Config via env: XTP_PCAP_DIR, XTP_WEB_ROOT, XTP_AGSBX_DIR
# Cron: * * * * * /root/agsbx/panel/health_check.sh

AGSBX="${XTP_AGSBX_DIR:-/root/agsbx}"
PCAP_DIR="${XTP_PCAP_DIR:-/root/agsbx/pcap}"
WEB_ROOT="${XTP_WEB_ROOT:-/root/websbx}"
LOG="$AGSBX/panel/health.log"
STAMP="$AGSBX/panel/.health_restart"

now=$(date +%s)
issues=()

# 1. pcap freshness: newest file must be < 10 min old (data flowing)
latest_pcap=$(ls -1t "$PCAP_DIR"/cap_*.pcap 2>/dev/null | head -1)
if [ -z "$latest_pcap" ]; then
  issues+=("no_pcap")
elif [ $(( now - $(stat -c %Y "$latest_pcap") )) -gt 600 ]; then
  issues+=("pcap_stale_$(stat -c %Y "$latest_pcap")")
fi

# 2. dumpcap process alive
pgrep -f 'dumpcap -i eth0' > /dev/null 2>&1 || issues+=("dumpcap_down")

# 3. systemd service active
systemctl is-active --quiet traffic-capture.service 2>/dev/null || issues+=("service_down")

# 4. disk usage < 85%
disk=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
[ -n "$disk" ] && [ "$disk" -gt 85 ] && issues+=("disk_${disk}pct")

# 5. panel data fresh (< 3 min, panel_gen cron is producing)
TOKEN=""
[ -f "$AGSBX/panel/panel_token.log" ] && TOKEN=$(cat "$AGSBX/panel/panel_token.log" 2>/dev/null)
if [ -n "$TOKEN" ] && [ -f "$WEB_ROOT/$TOKEN/panel_data.json" ]; then
  age=$(( now - $(stat -c %Y "$WEB_ROOT/$TOKEN/panel_data.json") ))
  [ "$age" -gt 180 ] && issues+=("panel_stale_${age}s")
fi

# all good -> silent exit (watchdog pattern: quiet when healthy)
if [ ${#issues[@]} -eq 0 ]; then
  exit 0
fi

echo "$(date '+%F %T') ISSUES: ${issues[*]}" >> "$LOG"

# auto-heal: restart capture if pcap stale or process down (throttle 5 min)
if [[ " ${issues[*]} " == *"pcap_stale"* || " ${issues[*]} " == *"no_pcap"* || " ${issues[*]} " == *"dumpcap_down"* ]]; then
  last_restart=0
  [ -f "$STAMP" ] && last_restart=$(cat "$STAMP" 2>/dev/null || echo 0)
  if [ $(( now - last_restart )) -gt 300 ]; then
    systemctl restart traffic-capture.service 2>/dev/null
    date +%s > "$STAMP"
    echo "$(date '+%F %T') ACTION: restarted traffic-capture.service (heal)" >> "$LOG"
  else
    echo "$(date '+%F %T') ACTION: restart throttled (last was ${last_restart})" >> "$LOG"
  fi
fi

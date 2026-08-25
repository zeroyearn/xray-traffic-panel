#!/bin/bash
# Capture xray outbound traffic (server -> internet) using dumpcap ring buffer.
# Excludes inbound proxy ports, SSH, httpd subscription port, cloudflared tunnel.
#
# Ring buffer: rotate at 5min OR 100MB, keep 144 files (~12h / max ~14.4GB disk).
# dumpcap -b files:N forms a true ring buffer (oldest overwritten), never exits
# on file-count, unlike tcpdump -G/-W.
#
# Config via environment variables:
#   XTP_PCAP_DIR      - pcap directory (default /root/agsbx/pcap)
#   XTP_EXCLUDE_PORTS - comma list of ports to exclude (default 52269,52459,10222,62153,22,7844)
#   XTP_ROTATE_SEC    - ring buffer time rotation (default 300)
#   XTP_MAX_MB        - ring buffer size rotation, MB (default 100)
#   XTP_MAX_FILES     - ring buffer file count (default 144)

PCAP_DIR="${XTP_PCAP_DIR:-/root/agsbx/pcap}"
EXCLUDE="${XTP_EXCLUDE_PORTS:-52269,52459,10222,62153,22,7844}"
ROTATE_SEC="${XTP_ROTATE_SEC:-300}"
MAX_MB="${XTP_MAX_MB:-100}"
MAX_FILES="${XTP_MAX_FILES:-144}"
mkdir -p "$PCAP_DIR"

# build BPF: (tcp or udp) and not port A and not port B ...
FILTER="(tcp or udp)"
IFS=',' read -ra PORTS <<< "$EXCLUDE"
for p in "${PORTS[@]}"; do
  FILTER="$FILTER and not port $p"
done

# dumpcap needs root; drop privileges if started as root via setcap-less binary
exec dumpcap -i eth0 -s 256 -f "$FILTER" \
  -w "$PCAP_DIR/cap.pcap" \
  -b duration:"$ROTATE_SEC" \
  -b filesize:"$((MAX_MB * 1024))" \
  -b files:"$MAX_FILES" \
  -q

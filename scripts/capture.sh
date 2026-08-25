#!/bin/bash
# Capture xray outbound traffic (server -> internet), excluding inbound proxy ports,
# SSH, httpd subscription port, and cloudflared tunnel.
# Rotates pcap every 5 minutes, keeps 72 files (6 hours).
#
# Config via environment variables:
#   XTP_PCAP_DIR      - pcap directory (default /root/agsbx/pcap)
#   XTP_EXCLUDE_PORTS - comma list of ports to exclude (default 52269,52459,10222,62153,22,7844)

PCAP_DIR="${XTP_PCAP_DIR:-/root/agsbx/pcap}"
EXCLUDE="${XTP_EXCLUDE_PORTS:-52269,52459,10222,62153,22,7844}"
mkdir -p "$PCAP_DIR"
# ensure the capture dir is writable by the tcpdump user, and owned correctly
chown root:tcpdump "$PCAP_DIR" 2>/dev/null || true
chmod 775 "$PCAP_DIR" 2>/dev/null || true

# build BPF: (tcp or udp) and not port A and not port B ...
FILTER="(tcp or udp)"
IFS=',' read -ra PORTS <<< "$EXCLUDE"
for p in "${PORTS[@]}"; do
  FILTER="$FILTER and not port $p"
done

exec tcpdump -i eth0 -nn -s 256 -w "$PCAP_DIR/cap_%Y%m%d_%H%M%S.pcap" -G 300 -W 72 -Z root "$FILTER"

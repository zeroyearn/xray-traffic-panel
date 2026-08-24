#!/usr/bin/env python3
"""
Analyze recent pcap files: per-domain bytes (SNI from TLS ClientHello) + per-IP fallback.
Outputs panel_net.json consumed by the dashboard.

Config via environment variables:
  XTP_PCAP_DIR - pcap directory (default /root/agsbx/pcap)
  XTP_NET_JSON - output path    (default <pcap dir>/../websbx/panel_net.json — set explicitly)
  XTP_WINDOW_MIN - rolling window in minutes (default 15)
"""
import json
import subprocess
import glob
import os
import tempfile
from collections import defaultdict
from datetime import datetime

PCAP_DIR = os.environ.get('XTP_PCAP_DIR', '/root/agsbx/pcap')
OUT = os.environ.get('XTP_NET_JSON', '/root/websbx/panel_net.json')
WINDOW_MIN = int(os.environ.get('XTP_WINDOW_MIN', '15'))


def analyze():
    now = datetime.now().timestamp()
    files = []
    for fn in glob.glob(os.path.join(PCAP_DIR, 'cap.pcap*')):
        if os.path.isfile(fn):
            age = (now - os.path.getmtime(fn)) / 60
            if age <= WINDOW_MIN * 2:
                files.append(fn)
    if not files:
        print('no pcap files yet')
        return None

    tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    tmp.close()
    try:
        subprocess.run(['mergecap', '-w', tmp.name] + files, capture_output=True, text=True, timeout=30)
        cmd = ['tshark', '-r', tmp.name, '-T', 'fields',
               '-e', 'tcp.stream', '-e', 'tls.handshake.extensions_server_name',
               '-e', 'ip.dst', '-e', 'frame.len',
               '-E', 'separator=|', '-E', 'occurrence=a']
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=90).stdout
    finally:
        os.unlink(tmp.name)

    streams = {}
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        stream, sni, dst, flen = parts[0], parts[1], parts[2], parts[3]
        try:
            flen = int(flen)
        except ValueError:
            continue
        s = streams.setdefault(stream, {'sni': None, 'dst': None, 'bytes': 0, 'count': 0})
        if sni and not s['sni']:
            s['sni'] = sni
        if dst and not s['dst']:
            s['dst'] = dst
        s['bytes'] += flen
        s['count'] += 1

    dom = defaultdict(lambda: {'bytes': 0, 'conns': 0})
    for s in streams.values():
        key = s['sni'] if s['sni'] else ('IP:' + s['dst'] if s['dst'] else 'unknown')
        # skip noise: own server IP / broadcast
        if s['dst'] in ('255.255.255.255',) or (s['dst'] and s['dst'].startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))):
            continue
        dom[key]['bytes'] += s['bytes']
        dom[key]['conns'] += 1

    total_bytes = sum(v['bytes'] for v in dom.values())
    top = sorted(dom.items(), key=lambda kv: -kv[1]['bytes'])[:30]
    result = {
        'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'window_min': WINDOW_MIN,
        'total_bytes': total_bytes,
        'domains': [{'d': d, 'bytes': v['bytes'], 'conns': v['conns']} for d, v in top],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        json.dump(result, f)
    print(f'net analysis: {len(streams)} streams, {len(dom)} domains, {total_bytes} bytes in window')


if __name__ == '__main__':
    analyze()

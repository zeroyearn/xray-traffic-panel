#!/usr/bin/env python3
"""
Incremental long-term archive of per-domain traffic from rotated pcap files.
tcpdump -G 300 produces cap.pcap (current), cap.pcap1, ... each covering a
disjoint 5-minute window. This script analyzes only files not yet processed
(state in .processed) and appends one JSONL record per file to the day archive.
No double counting.

Config via environment variables:
  XTP_PCAP_DIR   - pcap directory (default /root/agsbx/pcap)
  XTP_ARCHIVE_DIR - archive directory (default /root/agsbx/panel/archive)
"""
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime

PCAP_DIR = os.environ.get('XTP_PCAP_DIR', '/root/agsbx/pcap')
ARCHIVE_DIR = os.environ.get('XTP_ARCHIVE_DIR', '/root/agsbx/panel/archive')
STATE = os.path.join(ARCHIVE_DIR, '.processed')
os.makedirs(ARCHIVE_DIR, exist_ok=True)


def load_state():
    if os.path.exists(STATE):
        with open(STATE) as f:
            return set(f.read().split())
    return set()


def save_state(state):
    with open(STATE, 'w') as f:
        f.write('\n'.join(sorted(state)))


def analyze_file(fn):
    """Return {domain: bytes} for one pcap file."""
    cmd = ['tshark', '-r', fn, '-T', 'fields',
           '-e', 'tcp.stream', '-e', 'tls.handshake.extensions_server_name',
           '-e', 'ip.dst', '-e', 'frame.len',
           '-E', 'separator=|', '-E', 'occurrence=a']
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=90).stdout

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
        s = streams.setdefault(stream, {'sni': None, 'dst': None, 'bytes': 0})
        if sni and not s['sni']:
            s['sni'] = sni
        if dst and not s['dst']:
            s['dst'] = dst
        s['bytes'] += flen

    dom = defaultdict(int)
    for s in streams.values():
        key = s['sni'] if s['sni'] else ('IP:' + s['dst'] if s['dst'] else 'unknown')
        if s['dst'] in ('255.255.255.255',):
            continue
        dom[key] += s['bytes']
    return dom


def main():
    state = load_state()
    now = datetime.now()

    candidates = []
    for fn in os.listdir(PCAP_DIR):
        if not fn.startswith('cap') or not fn.endswith('.pcap'):
            continue
        path = os.path.join(PCAP_DIR, fn)
        age = (now.timestamp() - os.path.getmtime(path)) / 60
        if age > 2:  # only files that stopped being written
            candidates.append((path, os.path.getmtime(path)))
    candidates.sort(key=lambda x: x[1])

    processed_any = False
    for path, mtime in candidates:
        if path in state:
            continue
        dom = analyze_file(path)
        if not dom:
            state.add(path)
            continue
        # window start: prefer filename timestamp (cap_YYYYMMDD_HHMMSS.pcap), else mtime-5min
        base = os.path.basename(path)
        m = re.match(r'cap_(\d{8})_(\d{6})\.pcap', base)
        if m:
            ts = datetime.strptime(m.group(1) + m.group(2), '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
        else:
            ts = datetime.fromtimestamp(mtime - 300).strftime('%Y-%m-%d %H:%M:%S')
        day_key = ts[:10].replace('-', '')
        rec = {
            'ts': ts,
            'total_bytes': sum(dom.values()),
            'domains': [{'d': d, 'bytes': b} for d, b in
                        sorted(dom.items(), key=lambda kv: -kv[1])[:50]],
        }
        with open(os.path.join(ARCHIVE_DIR, f'domains_{day_key}.jsonl'), 'a') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        state.add(path)
        processed_any = True
        print(f'archived {path}: {len(dom)} domains, {rec["total_bytes"]} bytes @ {ts}')

    save_state(state)
    if not processed_any:
        print('nothing new to archive')


if __name__ == '__main__':
    main()

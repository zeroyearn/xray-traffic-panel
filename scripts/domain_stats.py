#!/usr/bin/env python3
"""Parse xray access.log -> per-domain connection stats + per-node stats.

Config via environment variables:
  XTP_AGSBX_DIR - agsbx install dir (default /root/agsbx)
"""
import re
import sys
from collections import Counter
from datetime import datetime
import os

LOG = os.path.join(os.environ.get('XTP_AGSBX_DIR', '/root/agsbx'), 'access.log')

# format: 2026/08/24 08:58:15.029291 from 1.2.3.4:50653 accepted tcp:api.github.com:443 [reality-vision -> direct]
pat = re.compile(
    r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+ from (\S+):\d+ accepted (tcp|udp):([^:]+):(\d+) \[(\S+) -> (\S+)\]'
)


def parse(fn):
    domains = Counter()
    nodes = Counter()
    hours = Counter()
    ips = Counter()
    first = last = None
    for line in open(fn, errors='replace'):
        m = pat.match(line.strip())
        if not m:
            continue
        ts, ip, proto, target, port, inbound, outbound = m.groups()
        t = datetime.strptime(ts, '%Y/%m/%d %H:%M:%S')
        if first is None or t < first:
            first = t
        if last is None or t > last:
            last = t
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target) or ':' in target:
            domains[f'IP:{target}'] += 1
        else:
            domains[target] += 1
        nodes[inbound] += 1
        ips[ip] += 1
        hours[t.strftime('%m-%d %H')] += 1
    return domains, nodes, ips, hours, first, last


def human(n):
    if n >= 1e9:
        return f'{n/1e9:.1f}G'
    if n >= 1e6:
        return f'{n/1e6:.1f}M'
    if n >= 1e3:
        return f'{n/1e3:.1f}K'
    return str(n)


def main():
    fn = sys.argv[1] if len(sys.argv) > 1 else LOG
    try:
        domains, nodes, ips, hours, first, last = parse(fn)
    except FileNotFoundError:
        print(f'no access log: {fn}')
        return
    total = sum(domains.values())
    print('== xray access log 统计 ==')
    print(f'文件: {fn}')
    print(f'窗口: {first} ~ {last}  总连接: {human(total)}')
    print()
    print('== 按节点 ==')
    for node, n in nodes.most_common():
        print(f'  {node:<20} {human(n)}')
    print()
    print('== 按来源 IP (Top 10) ==')
    for ip, n in ips.most_common(10):
        print(f'  {ip:<20} {human(n)}')
    print()
    print('== 按目标域名 (Top 30) ==')
    for d, n in domains.most_common(30):
        print(f'  {d:<45} {human(n)}')
    print()
    print('== 按小时活动 (Top 12) ==')
    for h, n in hours.most_common(12):
        print(f'  {h}:00  {human(n)}')


if __name__ == '__main__':
    main()

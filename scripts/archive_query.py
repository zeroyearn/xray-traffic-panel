#!/usr/bin/env python3
"""
Query long-term domain traffic archive.

Usage:
  archive_query.py                        # today summary (top domains)
  archive_query.py YYYYMMDD               # specific day
  archive_query.py YYYYMMDD YYYYMMDD      # range summary
  archive_query.py --json                 # machine-readable output

Config via environment variable:
  XTP_ARCHIVE_DIR - archive directory (default /root/agsbx/panel/archive)
"""
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

ARCHIVE_DIR = os.environ.get('XTP_ARCHIVE_DIR', '/root/agsbx/panel/archive')


def load_day(day):
    samples = []
    prefix = day
    for fn in sorted(os.listdir(ARCHIVE_DIR)):
        if not fn.startswith('domains_') or not fn.endswith('.jsonl'):
            continue
        hkey = fn.replace('domains_', '').replace('.jsonl', '')
        if hkey.startswith(prefix):
            with open(os.path.join(ARCHIVE_DIR, fn)) as f:
                for line in f:
                    try:
                        samples.append(json.loads(line))
                    except Exception:
                        pass
    return samples


def summarize(samples):
    dom = defaultdict(lambda: {'bytes': 0, 'samples': 0})
    total = 0
    for s in samples:
        for d in s.get('domains', []):
            dom[d['d']]['bytes'] += d['bytes']
            dom[d['d']]['samples'] += 1
            total += d['bytes']
    return dom, total


def human(n):
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024 or u == 'TB':
            return f'{n:.1f} {u}' if u != 'B' else f'{int(n)} {u}'
        n /= 1024


def main():
    args = sys.argv[1:]
    json_out = '--json' in args
    args = [a for a in args if not a.startswith('--')]

    if not args:
        days = [datetime.now().strftime('%Y%m%d')]
    elif len(args) == 1:
        days = [args[0]]
    else:
        start = datetime.strptime(args[0], '%Y%m%d')
        end = datetime.strptime(args[1], '%Y%m%d')
        days = []
        d = start
        while d <= end:
            days.append(d.strftime('%Y%m%d'))
            d += timedelta(days=1)

    all_samples = []
    for day in days:
        all_samples.extend(load_day(day))

    dom, total = summarize(all_samples)
    top = sorted(dom.items(), key=lambda kv: -kv[1]['bytes'])[:40]

    if json_out:
        print(json.dumps({
            'days': days,
            'total_bytes': total,
            'domains': [{'d': d, 'bytes': v['bytes'], 'samples': v['samples']} for d, v in top],
        }, ensure_ascii=False))
        return

    print('== 长期域名流量统计 ==')
    print(f'范围: {days[0]} ~ {days[-1]}  采样数: {len(all_samples)}')
    print(f'总流量: {human(total)}')
    print()
    print(f'{"域名":<45} {"流量":>10} {"采样":>6}')
    print('-' * 65)
    for d, v in top:
        print(f'{d:<45} {human(v["bytes"]):>10} {v["samples"]:>6}')


if __name__ == '__main__':
    main()

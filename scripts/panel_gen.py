#!/usr/bin/env python3
"""
Generate realtime panel data (v2: + per-domain bytes from pcap analysis).
Reads xray access.log + vnstat + ss, writes panel_data.json for the web panel.

Config via environment variables (see README):
  XTP_AGSBX_DIR   - agsbx install dir   (default /root/agsbx)
  XTP_WEB_DIR     - web root            (default /root/websbx)
  XTP_NET_JSON    - path to pcap analysis JSON (default <WEB_DIR>/panel_net.json)
  XTP_INBOUND_PORTS - comma list of inbound proxy ports (default 52269,52459,10222)
"""
import json
import os
import re
import sys
import subprocess
from collections import Counter
from datetime import datetime

AGSBX = os.environ.get('XTP_AGSBX_DIR', '/root/agsbx')
WEB = os.environ.get('XTP_WEB_DIR', '/root/websbx')
LOG = os.path.join(AGSBX, 'access.log')
OUT = os.path.join(WEB, 'panel_data.json')
NET = os.environ.get('XTP_NET_JSON', os.path.join(WEB, 'panel_net.json'))
INBOUND_PORTS = set((os.environ.get('XTP_INBOUND_PORTS', '52269,52459,10222')).split(','))

pat = re.compile(
    r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+ from (\S+):\d+ accepted (tcp|udp):([^:]+):(\d+) \[(\S+) -> (\S+)\]'
)


def parse_log():
    domains, nodes, ips, hours = Counter(), Counter(), Counter(), Counter()
    first = last = None
    try:
        for line in open(LOG, errors='replace'):
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
    except FileNotFoundError:
        pass
    return domains, nodes, ips, hours, first, last


def vnstat_daily():
    try:
        out = subprocess.run(['vnstat', '--json'], capture_output=True, text=True, timeout=10).stdout
        data = json.loads(out)
        for iface in data.get('interfaces', []):
            for d in iface.get('traffic', {}).get('day', []):
                rx, tx = d.get('rx'), d.get('tx')
                if rx is not None and tx is not None:
                    return rx, tx
    except Exception:
        pass
    return None, None


def current_conns():
    try:
        out = subprocess.run(['ss', '-tnp'], capture_output=True, text=True, timeout=10).stdout
        lines = [l for l in out.splitlines() if 'xray' in l and 'ESTAB' in l]
        targets = Counter()
        inbounds = Counter()
        for l in lines:
            parts = l.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            local = parts[3]
            port = local.rsplit(':', 1)[-1]
            if port in INBOUND_PORTS:
                inbounds[port] += 1
            else:
                targets[peer] += 1
        return len(lines), inbounds, targets
    except Exception:
        return 0, Counter(), Counter()


def load_net():
    try:
        with open(NET) as f:
            return json.load(f)
    except Exception:
        return None


def load_archive(prefix=''):
    """Aggregate per-domain bytes from archive JSONL for a time span.

    prefix=''        -> ALL time (full history)
    prefix='YYYYMM'  -> one month
    prefix='YYYYMMDD'-> one day
    Samples are disjoint 5-minute windows, so summing gives total bytes.
    Also aggregates per-service (IP->service classifier + domain suffix).
    """
    arch = os.environ.get('XTP_ARCHIVE_DIR', '/root/agsbx/panel/archive')
    dom = Counter()
    total = 0
    samples = 0
    try:
        for fn in os.listdir(arch):
            if not (fn.startswith('domains_') and fn.endswith('.jsonl')):
                continue
            key = fn.replace('domains_', '').replace('.jsonl', '')
            if prefix and not key.startswith(prefix):
                continue
            with open(os.path.join(arch, fn)) as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    samples += 1
                    total += rec.get('total_bytes', 0)
                    for d in rec.get('domains', []):
                        dom[d['d']] += d.get('bytes', 0)
    except FileNotFoundError:
        return None

    # service classification of archived entries
    svc_bytes = Counter()
    classifier = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ip_classify import Classifier
        classifier = Classifier(os.environ.get('XTP_RULES', '/root/agsbx/panel/svc_rules.json'))
    except Exception:
        classifier = None

    for target, b in dom.items():
        svc = None
        if target.startswith('IP:'):
            ip = target[3:]
            if classifier:
                svc, _ = classifier.classify(ip)
        else:
            if classifier:
                svc = classify_domain(target, classifier)
        if svc:
            svc_bytes[svc] += b
        else:
            svc_bytes['其他/未知'] += b

    return {
        'prefix': prefix or 'all',
        'samples': samples,
        'total_bytes': total,
        'domains': [{'d': d, 'bytes': b} for d, b in dom.most_common(40)],
        'services': [{'d': d, 'bytes': b} for d, b in svc_bytes.most_common()],
    }


def classify_domain(domain, classifier):
    """Map a domain to a service using rule library domain suffixes."""
    if not classifier:
        return None
    try:
        svcs = classifier.services
    except AttributeError:
        return None
    d = domain.lower()
    best = None
    best_len = -1
    for svc, v in svcs.items():
        for suf in v.get('domains', []):
            suf = suf.lower()
            if d == suf or d.endswith('.' + suf):
                if len(suf) > best_len:
                    best, best_len = svc, len(suf)
    return best


def main():
    domains, nodes, ips, hours, first, last = parse_log()
    rx, tx = vnstat_daily()
    total_conn, inbounds, targets = current_conns()
    net = load_net()
    now = datetime.now()
    day_net = load_archive(now.strftime('%Y%m%d'))
    month_net = load_archive(now.strftime('%Y%m'))
    all_net = load_archive('')

    top_domains = [{'d': d, 'n': n} for d, n in domains.most_common(25)]
    top_nodes = [{'d': d, 'n': n} for d, n in nodes.most_common()]
    top_ips = [{'d': d, 'n': n} for d, n in ips.most_common(10)]
    hours_list = [{'d': d, 'n': n} for d, n in sorted(hours.items())]
    inbounds_list = [{'d': d, 'n': n} for d, n in inbounds.most_common()]

    data = {
        'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_conn': sum(domains.values()),
        'window_start': first.strftime('%m-%d %H:%M') if first else '-',
        'window_end': last.strftime('%m-%d %H:%M') if last else '-',
        'active_conns': total_conn,
        'rx_today': rx,
        'tx_today': tx,
        'top_domains': top_domains,
        'top_nodes': top_nodes,
        'top_ips': top_ips,
        'hours': hours_list,
        'inbounds': inbounds_list,
        'net': net,
        'day_net': day_net,
        'month_net': month_net,
        'all_net': all_net,
    }
    with open(OUT, 'w') as f:
        json.dump(data, f)
    print(f'panel data written: {len(top_domains)} domains, {total_conn} active conns, net={bool(net)}, day={bool(day_net)}, month={bool(month_net)}, all={bool(all_net)}')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Build service classification rules from blackmatrix7 (IP-CIDR) + ipverse ASN.

Outputs /root/agsbx/panel/svc_rules.json:
{
  "services": {
    "Steam": {"cidrs": ["146.66.152.0/24", ...], "asns": [32590], "domains": ["steampowered.com", ...]},
    ...
  },
  "updated": "..."
}
"""
import json
import os
import urllib.request
import ssl

OUT = '/root/agsbx/panel/svc_rules.json'
BASE = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash'
IPVERSE = 'https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as'

# service -> (blackmatrix7 list name, ipverse ASNs)
SERVICES = {
    'Apple':      ('Apple',      [714, 6185]),
    'Google':     ('Google',     [15169, 36040, 41264, 19425]),
    'Microsoft':  ('Microsoft',  [8075, 8068, 8069]),
    'Steam':      ('Steam',      [32590]),
    'Telegram':   ('Telegram',   [62041, 62014, 44949, 59930]),
    'Netflix':    ('Netflix',    [2906, 40027, 55095]),
    'YouTube':    ('YouTube',    []),
    'TikTok':     ('TikTok',     []),
    'OpenAI':     ('OpenAI',     [28709]),
    'Cloudflare': ('Cloudflare', [13335, 209242]),
    'Amazon':     ('Amazon',     [16509, 14618, 9059]),
    'Facebook':   ('Facebook',   [32934, 63293]),
    'Twitter':    ('Twitter',    [13414, 35995]),
    'Discord':    ('Discord',    []),
    'Spotify':    ('Spotify',    []),
    'Epic':       ('Epic',       []),
    'Riot':       ('Riot',       []),
    'GitHub':     ('GitHub',     [36459]),
    'DigitalOcean': ('DigitalOcean', [14061]),
    'Oracle':     ('Oracle',     [31898]),
    'Akamai':     ('Akamai',     [20940, 16625, 21342]),
    'Fastly':     ('Fastly',     [54113]),
}

CTX = ssl.create_default_context()


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.0'})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read().decode('utf-8', errors='replace')


def fetch_blackmatrix(name):
    """Fetch Clash yaml rules; return (cidrs, domains)"""
    cidrs, domains = [], []
    url = f'{BASE}/{name}/{name}.yaml'
    try:
        text = fetch(url)
        for line in text.splitlines():
            line = line.strip().strip('-').strip()
            if line.startswith('IP-CIDR,'):
                cidr = line.split(',')[1].strip()
                if '/' in cidr:
                    cidrs.append(cidr)
            elif line.startswith('DOMAIN-SUFFIX,'):
                domains.append(line.split(',')[1].strip())
            elif line.startswith('DOMAIN,'):
                domains.append(line.split(',')[1].strip())
    except Exception as e:
        print(f'  ! blackmatrix {name}: {e}')
    return cidrs, domains


def fetch_ipverse(asn):
    url = f'{IPVERSE}/{asn}/aggregated.json'
    try:
        data = json.loads(fetch(url))
        return data.get('prefixes', {}).get('ipv4', []), data.get('metadata', {}).get('description', f'AS{asn}')
    except Exception as e:
        print(f'  ! ipverse AS{asn}: {e}')
        return [], f'AS{asn}'


def main():
    result = {'services': {}, 'updated': ''}
    import datetime
    result['updated'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for svc, (bm_name, asns) in SERVICES.items():
        cidrs, domains = fetch_blackmatrix(bm_name)
        asn_cidrs = []
        for asn in asns:
            ac, _ = fetch_ipverse(asn)
            asn_cidrs.extend(ac)
        # dedupe
        cidrs = sorted(set(cidrs))
        result['services'][svc] = {
            'cidrs': cidrs,
            'asn_cidrs': sorted(set(asn_cidrs)),
            'domains': sorted(set(domains))[:500],
        }
        print(f'{svc}: {len(cidrs)} cidrs, {len(asn_cidrs)} asn-cidrs, {len(domains)} domains')

    with open(OUT, 'w') as f:
        json.dump(result, f, ensure_ascii=False)
    print(f'written {OUT}')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""IP -> service classifier.

Loads svc_rules.json (built by build_rules.py from blackmatrix7 IP-CIDR +
ipverse ASN prefixes) and classifies an IP to a named service with confidence.

Confidence levels:
  100  exact CIDR from service rule list (blackmatrix)
   90  ASN prefix (ipverse, authoritative)
   70  ASN prefix from a hosting/CDN provider
    0  unknown

Usage:
  python3 ip_classify.py 45.121.184.43        # -> Steam
  python3 ip_classify.py --batch ip1 ip2 ...  # table output
"""
import json
import os
import sys
import ipaddress

RULES = os.environ.get('XTP_RULES', '/root/agsbx/panel/svc_rules.json')


class Classifier:
    def __init__(self, path=RULES):
        with open(path) as f:
            data = json.load(f)
        self.services = data['services']
        # build sorted prefix lists: (network, service, source)
        self.exact = []   # blackmatrix IP-CIDR: high confidence
        self.asn = []     # ipverse ASN prefixes
        for svc, v in self.services.items():
            for cidr in v.get('cidrs', []):
                try:
                    self.exact.append((ipaddress.ip_network(cidr, strict=False), svc))
                except ValueError:
                    pass
            for cidr in v.get('asn_cidrs', []):
                try:
                    self.asn.append((ipaddress.ip_network(cidr, strict=False), svc))
                except ValueError:
                    pass
        self.exact.sort(key=lambda x: x[0].prefixlen, reverse=True)
        self.asn.sort(key=lambda x: x[0].prefixlen, reverse=True)

    def classify(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, 0
        # exact CIDR rules first (longest prefix match)
        for net, svc in self.exact:
            if ip in net:
                return svc, 100
        # ASN prefixes (authoritative org)
        for net, svc in self.asn:
            if ip in net:
                return svc, 90
        return None, 0


def main():
    args = sys.argv[1:]
    clf = Classifier()
    if not args:
        print('usage: ip_classify.py <ip> [ip...]')
        return
    if args[0] == '--batch':
        ips = args[1:]
    else:
        ips = args
    for ip in ips:
        svc, conf = clf.classify(ip)
        if svc:
            print(f'{ip:<20} {svc:<14} conf={conf}')
        else:
            print(f'{ip:<20} {"未知":<14} conf=0')


if __name__ == '__main__':
    main()

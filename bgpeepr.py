#!/usr/bin/env python3
"""
bgpeepr.py - ASN and IP Prefix Lookup by Company Name
-----------------------------------------------------

Description:
    This script searches the public IPtoASN database for ASNs associated with a
    company or organization name using a fuzzy match. It can also extract the
    associated IP prefix ranges and export results to JSON or CSV formats.

Usage:
    python3 bgpeepr.py <company> [options]

Examples:
    python3 bgpeepr.py microsoft
    python3 bgpeepr.py oracle -p
    python3 bgpeepr.py amazon -p -oJ amazon.json -oC amazon.csv

Arguments:
    company               The company or organization name to search for
                          (case-insensitive, fuzzy match).

Options:
    -p, --prefixes        Display associated IP prefix ranges in CIDR format
    -oJ FILE, --json FILE Output results to a JSON file
    -oC FILE, --csv FILE  Output results to a CSV file

Output:
    - A list of matching ASNs with organization names
    - Optionally, the CIDR prefixes associated with each ASN
    - Optional structured output in JSON or CSV for further automation

Requirements:
    - Python 3
    - Modules: requests, netaddr
"""
import argparse
import csv
import json
import os
import re
import sys
import tempfile
import requests
import gzip
from netaddr import IPSet, IPRange

# ANSI color codes
YELLOW = '\033[1;33m'
GREEN = '\033[1;32m'
RED = '\033[1;31m'
NC = '\033[0m'  # No color

# Original IPTOASN_V4_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
# Original IPTOASN_V6_URL = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
IPTOASN_V4_URL = "https://github.com/pl-strflt/iptoasn/raw/main/data/ip2asn-v4.tsv.gz"
IPTOASN_V6_URL = "https://github.com/pl-strflt/iptoasn/raw/main/data/ip2asn-v6.tsv.gz"

def download_iptoasn(ipv6=False):
    url = IPTOASN_V6_URL if ipv6 else IPTOASN_V4_URL
    print(f"{YELLOW}Downloading IPtoASN {'IPv6' if ipv6 else 'IPv4'} data...{NC}")
    try:
        r = requests.get(url, stream=True)
        r.raise_for_status()
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_file.write(gzip.decompress(r.content))
        tmp_file.close()
        return tmp_file.name
    except Exception as e:
        print(f"{RED}Error downloading IPtoASN data: {e}{NC}")
        sys.exit(1)

def load_iptoasn_file(path):
    # Return path to decompressed file contents
    if path.endswith('.gz'):
        try:
            with gzip.open(path, 'rb') as f_in:
                tmpfile = tempfile. NamedTemporaryFile(delete=False)
                tmpfile.write(f_in.read())
                tmpfile.close()
                return tmpfile.name
        except Exception as e:
            print(f"{RED}Error reading gzipped local file {e}{NC}")
            sys.exit(1)
    else:
        return path

def parse_iptoasn(filename, company_regex):
    asns = {}
    regex = re.compile(company_regex, re.I)

    with open(filename, 'rt', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 5:
                continue
            asn = parts[2]
            org = parts[4]
            if regex.search(org):
                asns[asn] = org
    return asns

def get_prefixes(filename, asns):
    prefixes = {asn: set() for asn in asns}
    with open(filename, 'rt', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 5:
                continue
            asn = parts[2]
            if asn in prefixes:
                start_ip = parts[0]
                end_ip = parts[1]
                try:
                    ip_range = IPRange(start_ip, end_ip)
                    for cidr in IPSet(ip_range).iter_cidrs():
                        prefixes[asn].add(str(cidr))
                except Exception:
                    pass
    return prefixes

def print_banner(title, width=65):
    padding = width - len(title) - 4
    pad_left = padding // 2
    pad_right = padding - pad_left

    print(f"\n{YELLOW}{'*' * width}")
    print(f"**{' ' * pad_left}{title}{' ' * pad_right}**")
    print(f"{'*' * width}{NC}")

def save_json(filename, asns, prefixes=None, v6_prefixes=None):
    out = []
    for asn, org in asns.items():
        entry = {"asn": asn, "organization": org}
        if prefixes:
            entry["ipv4_prefixes"] = sorted(prefixes.get(asn, []))
        if v6_prefixes:
            entry["ipv6_prefixes"] = sorted(v6_prefixes.get(asn, []))
        out.append(entry)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)

def save_csv(filename, asns, prefixes=None, v6_prefixes=None):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        headers = ["ASN", "Organization", "Prefix", "IP Version"]
        writer.writerow(headers)

        for asn, org in asns.items():
            written = False
            if prefixes and prefixes.get(asn):
                for prefix in sorted(prefixes[asn]):
                    writer.writerow([asn, org, prefix, "IPv4"])
                    written = True
            if v6_prefixes and v6_prefixes.get(asn):
                for prefix in sorted(v6_prefixes[asn]):
                    writer.writerow([asn, org, prefix, "IPv6"])
                    written = True
            if not written:
                writer.writerow([asn, org, "", ""])

def main():
    parser = argparse.ArgumentParser(description="Search IPtoASN database for ASNs by company name")
    parser.add_argument("company", help="Company name (fuzzy match)")
    parser.add_argument("-l", "--local", metavar="FILE", help="Use local IPtoASN  file")
    parser.add_argument("-p", "--prefixes", action="store_true", help="Display IPv4 prefix ranges")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Include IPv6 prefixes")
    parser.add_argument("-oJ", "--json", metavar="FILE", help="Output JSON file")
    parser.add_argument("-oC", "--csv", metavar="FILE", help="Output CSV file")

    args = parser.parse_args()

    if args.local:
        if not os.path.isfile(args.local):
            print(f"{RED}Local file '{args.local}' does not exist.{NC}")
            sys.exit(1)
        iptoasn_v4 = load_iptoasn_file(args.local)
    else:
        iptoasn_v4 = download_iptoasn()
    
    asns = parse_iptoasn(iptoasn_v4, args.company)
    if not asns:
        print(f"{RED}No ASNs found for company '{args.company}'.{NC}")
        os.unlink(iptoasn_v4)
        sys.exit(1)

    print_banner(f"Matched ASNs for '{args.company}'")
    for asn, org in asns.items():
        print(f"  {GREEN}{asn}:{NC} {org}")

    prefixes = None
    if args.prefixes:
        prefixes = get_prefixes(iptoasn_v4, asns)
        print_banner(f"Matched IPv4 Prefixes for '{args.company}'")
        for asn, pset in prefixes.items():
            if pset:
                print(f"\n  {GREEN}IPv4 Prefixes announced by AS{asn}:{NC}")
                for prefix in sorted(pset):
                    print(f"    {prefix}")
            else:
                print(f"\n  {RED}No IPv4 prefixes found for AS{asn}.{NC}")

    v6_prefixes = None
    if args.prefixes and args.ipv6:
        iptoasn_v6 = download_iptoasn(ipv6=True)
        v6_prefixes = get_prefixes(iptoasn_v6, asns)
        print_banner(f"Matched IPv6 Prefixes for '{args.company}'")
        for asn, pset in v6_prefixes.items():
            if pset:
                print(f"\n  {GREEN}IPv6 Prefixes announced by AS{asn}:{NC}")
                for prefix in sorted(pset):
                    print(f"    {prefix}")
            else:
                print(f"\n  {RED}No IPv6 prefixes found for AS{asn}.{NC}")
        os.unlink(iptoasn_v6)

    if args.json:
        save_json(args.json, asns, prefixes, v6_prefixes)
        print(f"\n{YELLOW}JSON output saved to {args.json}{NC}")

    if args.csv:
        save_csv(args.csv, asns, prefixes, v6_prefixes)
        print(f"\n{YELLOW}CSV output saved to {args.csv}{NC}")

    if not args.local or (args.local and args.local.endswith('.gz')):
        try:
            os.unlink(iptoasn_v4)
        except Exception as e:
            print(f"{RED}Warning: Failed to delete temp file: {e}{NC}")

if __name__ == "__main__":
    main()

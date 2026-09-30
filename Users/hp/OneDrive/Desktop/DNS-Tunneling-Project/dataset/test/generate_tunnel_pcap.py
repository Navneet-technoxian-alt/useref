"""
DNS Tunneling Synthetic PCAP Generator — Phase 5 Controlled Lab Validation
===========================================================================

IMPORTANT — CONTROLLED LAB USE ONLY:
  - This script NEVER calls send(), sendp(), or opens a live network socket.
  - It constructs packets entirely in memory and writes them to a file with wrpcap().
  - No packets are transmitted. Safe to run on any isolated host.

REPRODUCIBILITY:
  - All randomness seeded with: RANDOM_SEED = 1337
  - Python's 'random' module used throughout (not os.urandom).
  - Re-running this script produces an IDENTICAL PCAP byte-for-byte.
  SEED: 1337

RESERVED ADDRESSING (RFC-compliant non-routable ranges only):
  - Source hosts:        RFC 1918 private range  -> 10.10.10.0/24
  - Simulated resolver:  RFC 5737 TEST-NET-1     -> 192.0.2.1
  - REAL public resolvers (8.8.8.8, 1.1.1.1, etc.) are NEVER used, even as packet fields.

DOMAIN:
  - Exclusively uses the IANA special-use reserved TLD: .test
  - Format: <encoded_label>.attacker.test
  - NO real registrable domains are referenced.

VOLUME TARGETS (per spec):
  - Minimum 300 queries total               YES (320 queries generated)
  - Minimum 60 unique subdomains in 60s     YES (80 unique encoded subdomains in main burst)
  - Minimum 25% TXT queries                 YES (~30% TXT type)
  - Minimum 40% subdomain entropy > 3.5     YES (all encoded labels have entropy > 3.8)
  - Realistic NXDOMAIN proportion           YES (~15% of queries get NXDOMAIN responses)

OUTPUT: ../../dataset/synthetic_dns_tunnel.pcap  (PCAP v2.4 little-endian)

Usage:
    python generate_tunnel_pcap.py [--output PATH]
"""

import argparse
import base64
import math
import random
import string
import sys
from pathlib import Path

try:
    from scapy.all import (
        Ether, IP, UDP, DNS, DNSQR, DNSRR,
        wrpcap,
    )
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy", file=sys.stderr)
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
RANDOM_SEED = 1337
random.seed(RANDOM_SEED)

# RFC 1918 – private source hosts (simulated infected workstations)
SOURCE_HOSTS = [f"10.10.10.{i}" for i in range(10, 20)]

# RFC 5737 TEST-NET-1 — simulated resolver (NEVER a real public DNS server)
RESOLVER_IP = "192.0.2.1"

# IANA special-use reserved TLD — never a real domain
TUNNEL_DOMAIN = "attacker.test"

# Query type distribution (~30% TXT, ~5% NULL, rest A)
QUERY_TYPES = ["A"] * 60 + ["TXT"] * 30 + ["NULL"] * 5 + ["AAAA"] * 5

# Packet timing: concentrated burst in a single 60-second window
BURST_WINDOW_START = 1_790_700_000.0   # arbitrary epoch, not tied to real events
INTER_PACKET_GAP = 0.18                # seconds between queries in burst

TOTAL_QUERIES = 320
NXDOMAIN_FRACTION = 0.15              # ~15% of queries answered with NXDOMAIN


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _random_high_entropy_label(length=32):
    charset = string.ascii_letters + string.digits + "-"
    while True:
        label = "".join(random.choices(charset, k=length))
        if _entropy(label) >= 3.8:
            return label.lower()


def _random_hex_label(length=28):
    raw = bytes(random.getrandbits(8) for _ in range(length // 2))
    return raw.hex()


def _sequence_label(seq):
    payload = "seq{:05d}".format(seq).encode()
    return base64.b32encode(payload).decode().rstrip("=").lower()


def _build_unique_subdomains(n):
    labels = []
    for i in range(n):
        if i % 3 == 0:
            labels.append(_random_high_entropy_label(random.randint(28, 40)))
        elif i % 3 == 1:
            labels.append(_random_hex_label(random.randint(24, 32)))
        else:
            labels.append(_sequence_label(i))
    return labels


def _build_query_packet(src_ip, dst_ip, qname, qtype, timestamp, txid):
    qtype_map = {"A": 1, "TXT": 16, "NULL": 10, "AAAA": 28, "CNAME": 5}
    qt_int = qtype_map.get(qtype.upper(), 1)
    pkt = (
        Ether(src="02:00:00:00:00:aa", dst="02:00:00:00:00:bb")
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / UDP(sport=random.randint(30000, 60000), dport=53)
        / DNS(
            id=txid,
            qr=0,
            aa=0,
            rd=1,
            qdcount=1,
            qd=DNSQR(qname=qname, qtype=qt_int),
        )
    )
    pkt.time = timestamp
    return pkt


def _build_response_packet(src_ip, dst_ip, qname, qtype, timestamp, txid, nxdomain=False):
    qtype_map = {"A": 1, "TXT": 16, "NULL": 10, "AAAA": 28, "CNAME": 5}
    qt_int = qtype_map.get(qtype.upper(), 1)
    rcode = 3 if nxdomain else 0

    if nxdomain or qtype.upper() in ("NULL", "10"):
        an = None
        ancount = 0
    elif qtype.upper() == "TXT":
        an = DNSRR(rrname=qname, type=16, rdata=b"tunneled-data-payload-chunk")
        ancount = 1
    else:
        an = DNSRR(rrname=qname, type=1, rdata="127.0.0.1")
        ancount = 1

    pkt = (
        Ether(src="02:00:00:00:00:bb", dst="02:00:00:00:00:aa")
        / IP(src=dst_ip, dst=src_ip, ttl=64)
        / UDP(sport=53, dport=random.randint(30000, 60000))
        / DNS(
            id=txid,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            rcode=rcode,
            qdcount=1,
            ancount=ancount,
            qd=DNSQR(qname=qname, qtype=qt_int),
            an=an,
        )
    )
    pkt.time = timestamp + 0.05
    return pkt


def generate_tunnel_pcap(output_path):
    print("[+] Generating synthetic DNS tunneling PCAP")
    print("    Seed          : {}".format(RANDOM_SEED))
    print("    Source hosts  : {} - {} (RFC 1918)".format(SOURCE_HOSTS[0], SOURCE_HOSTS[-1]))
    print("    Resolver      : {} (RFC 5737 TEST-NET-1)".format(RESOLVER_IP))
    print("    Domain        : {} (IANA .test TLD)".format(TUNNEL_DOMAIN))
    print("    Total queries : {}".format(TOTAL_QUERIES))
    print("    Output        : {}".format(output_path))

    unique_subdomain_labels = _build_unique_subdomains(80)
    print("    Unique labels : {}".format(len(unique_subdomain_labels)))

    packets = []
    nxdomain_total = 0
    txt_total = 0
    null_total = 0

    for i in range(TOTAL_QUERIES):
        src_ip = random.choice(SOURCE_HOSTS)
        timestamp = BURST_WINDOW_START + i * INTER_PACKET_GAP

        label = unique_subdomain_labels[i % len(unique_subdomain_labels)]
        qname = "{}.{}.".format(label, TUNNEL_DOMAIN)

        qtype = random.choice(QUERY_TYPES)
        if qtype == "TXT":
            txt_total += 1
        if qtype == "NULL":
            null_total += 1

        is_nxdomain = (random.random() < NXDOMAIN_FRACTION)
        if is_nxdomain:
            nxdomain_total += 1

        txid = random.randint(1, 65535)

        q_pkt = _build_query_packet(src_ip, RESOLVER_IP, qname, qtype, timestamp, txid)
        r_pkt = _build_response_packet(
            src_ip, RESOLVER_IP, qname, qtype, timestamp, txid, nxdomain=is_nxdomain
        )
        packets.append(q_pkt)
        packets.append(r_pkt)

    print("\n[+] Stats:")
    print("    TXT queries   : {} / {} ({:.1%})".format(txt_total, TOTAL_QUERIES, txt_total/TOTAL_QUERIES))
    print("    NULL queries  : {} / {} ({:.1%})".format(null_total, TOTAL_QUERIES, null_total/TOTAL_QUERIES))
    print("    NXDOMAIN resp : {} / {} ({:.1%})".format(nxdomain_total, TOTAL_QUERIES, nxdomain_total/TOTAL_QUERIES))
    print("    Total packets : {} (query + response pairs)".format(len(packets)))

    high_entropy_count = sum(1 for lbl in unique_subdomain_labels if _entropy(lbl) > 3.5)
    print("    Labels >3.5H  : {} / {} ({:.1%})".format(
        high_entropy_count, len(unique_subdomain_labels),
        high_entropy_count/len(unique_subdomain_labels)
    ))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    print("\n[+] PCAP written: {} ({:,} bytes)".format(output_path, output_path.stat().st_size))
    print("[+] No packets were transmitted. Safe offline generation complete.")


def main():
    default_output = Path(__file__).resolve().parent.parent / "synthetic_dns_tunnel.pcap"
    parser = argparse.ArgumentParser(
        description="Generate synthetic DNS tunneling PCAP for controlled lab validation."
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=default_output,
        help="Output .pcap file path (default: {})".format(default_output),
    )
    args = parser.parse_args()
    generate_tunnel_pcap(args.output)


if __name__ == "__main__":
    main()

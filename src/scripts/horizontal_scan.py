#!/usr/bin/env python3
"""Run a horizontal TCP scan from a Mininet host namespace.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/horizontal_scan.py -P 22 10.0.3.10 10.0.3.20 10.0.3.30
"""

from __future__ import annotations

import argparse
import random
import time
from ipaddress import IPv4Address, IPv4Network

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default horizontal scan profile for demo traffic generation.
DEFAULT_SCAN_PORT = 22
DEFAULT_PROBE_INTERVAL_SECONDS = 0.01


def horizontal_scan(
    targets: list[IPv4Address],
    *,
    destination_port: int = DEFAULT_SCAN_PORT,
    probe_interval_seconds: float = DEFAULT_PROBE_INTERVAL_SECONDS,
) -> None:
    """Send one TCP SYN packet per host to the same destination port.

    Args:
        targets: List of destination IPv4 addresses to probe.
        destination_port: Destination TCP port used across all hosts.
        probe_interval_seconds: Delay between probes in seconds.
    """
    if not targets:
        msg = "At least one target must be provided"
        raise ValueError(msg)
    if not 1 <= destination_port <= 65535:
        msg = "Destination port must be between 1 and 65535"
        raise ValueError(msg)
    if probe_interval_seconds < 0:
        msg = "Probe interval must be greater than or equal to 0"
        raise ValueError(msg)

    print(
        f"[{FILE_NAME}] hosts={len(targets)} dport={destination_port} "
        f"probe_interval_seconds={probe_interval_seconds}"
    )

    for target in targets:
        packet = scapy.IP(dst=str(target)) / scapy.TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=destination_port,
            flags="S",
        )
        scapy.send(packet, verbose=False)
        time.sleep(probe_interval_seconds)

    print(f"[{FILE_NAME}] done - {len(targets)} hosts scanned")


def _parse_target_network(network: str) -> list[IPv4Address]:
    parsed_network = IPv4Network(network, strict=False)
    return [IPv4Address(host) for host in parsed_network.hosts()]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate horizontal scan traffic for SDN threat detection demo."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        type=IPv4Address,
        help="Target IPv4 addresses (space-separated)",
    )
    parser.add_argument(
        "-n",
        "--network",
        type=str,
        default=None,
        help="Optional CIDR network to expand into targets (e.g. 10.0.3.0/24)",
    )
    parser.add_argument(
        "-P",
        "--destination-port",
        type=int,
        default=DEFAULT_SCAN_PORT,
        help="Destination TCP port (default: %(default)s)",
    )
    parser.add_argument(
        "-i",
        "--probe-interval",
        type=float,
        default=DEFAULT_PROBE_INTERVAL_SECONDS,
        help="Delay between probes in seconds (default: %(default)s)",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    target_list = list(args.targets)
    if args.network is not None:
        target_list.extend(_parse_target_network(args.network))

    # Preserve order while deduplicating host targets.
    unique_targets = list(dict.fromkeys(target_list))
    horizontal_scan(
        unique_targets,
        destination_port=args.destination_port,
        probe_interval_seconds=args.probe_interval,
    )


if __name__ == "__main__":
    main()

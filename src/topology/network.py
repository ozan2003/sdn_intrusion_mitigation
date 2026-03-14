"""
Mininet implementation of the enterprise WAN topology.

Its comprised of 4 OVS switches (OpenFlow 1.3), 8 hosts, VLAN-tagged zones on the
backbone switch (s1_omurga), and an OVS mirror port for Suricata.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from shutil import which
from typing import IO

import matplotlib.pyplot as plt
import networkx as nx
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo

# DPID expected by controller.app for backbone specific forwarding logic.
OMURGA_DPID = "0000000000000001"

# Project-level paths used by topology bootstrap and Suricata startup.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SURICATA_CFG = PROJECT_ROOT / "ids" / "suricata.yaml"
SURICATA_RULES = PROJECT_ROOT / "ids" / "rules" / "custom.rules"
LOG_DIR = PROJECT_ROOT / "logs"
SURICATA_STDERR_LOG = LOG_DIR / "suricata_stderr.log"
SURICATA_BIN = which("suricata")


class EnterpriseWanTopo(Topo):
    """Simplified enterprise WAN topology.

    Switches:
        s1_omurga  - backbone SDN switch (choke point)
        s2_sube    - branch L2 switch
        s3_dc      - data-center access switch
        s4_merkez  - headquarters L2 switch

    VLAN zones on s1_omurga:
        5  - BRANCH  (s2_sube uplink)
        10 - HQ      (s4_merkez uplink)
        15 - INTERNET (hacker uplink)
        untagged - DC trunk (s3_dc uplink)
    """

    def build(self) -> None:
        """
        Build the topology as stated in the documentation.
        """
        s1 = self.addSwitch(
            "s1_omurga",
            dpid=OMURGA_DPID,
            protocols="OpenFlow13",
        )
        s2 = self.addSwitch("s2_sube", protocols="OpenFlow13")
        s3 = self.addSwitch("s3_dc", protocols="OpenFlow13")
        s4 = self.addSwitch("s4_merkez", protocols="OpenFlow13")

        hacker = self.addHost("hacker", ip="10.0.1.10/16")
        sube_pc = self.addHost("sube_pc", ip="10.0.2.10/16")

        intra = self.addHost("intra", ip="10.0.3.10/16")
        siem = self.addHost("siem", ip="10.0.3.20/16")
        radius = self.addHost("radius", ip="10.0.3.30/16")
        nac = self.addHost("nac", ip="10.0.3.40/16")
        dr_host = self.addHost("dr_host", ip="10.0.4.10/16")
        paas = self.addHost("paas", ip="10.0.5.10/16")

        self.addLink(hacker, s1)

        self.addLink(sube_pc, s2)
        self.addLink(s2, s1)
        self.addLink(s4, s1)
        self.addLink(s1, s3)

        self.addLink(s3, intra)
        self.addLink(s3, siem)
        self.addLink(s3, radius)
        self.addLink(s3, nac)
        self.addLink(s3, dr_host)
        self.addLink(s3, paas)

    def to_graph(self) -> nx.Graph:
        """
        Convert the topology to a NetworkX graph.

        This is not used for topology construction, but can be useful for visualization, testing, or other analyses.
        """
        graph = nx.Graph()

        # hosts
        for h in self.hosts():
            graph.add_node(h, type="host")

        # switches
        for s in self.switches():
            graph.add_node(s, type="switch")

        # links
        for n1, n2 in self.links():
            graph.add_edge(n1, n2)

        return graph


def _run(cmd: str) -> str:
    """Run a shell command and return stripped stdout."""
    try:
        return subprocess.check_output(  # noqa: S603
            cmd.split(), text=True, stderr=subprocess.PIPE
        ).strip()
    except subprocess.CalledProcessError as e:
        msg = f"Command failed: {cmd!r}\n{e.stderr}"
        raise RuntimeError(msg) from e


def _get_ofport(interface: str) -> str:
    """Get the ofport of an interface."""
    return _run(f"ovs-vsctl get Interface {interface} ofport")


def _peer_port_name(
    net: Mininet, bridge: str, peer_bridge_or_host: str
) -> str:
    """Return interface name on *bridge* connected to *peer_bridge_or_host*."""
    switch_node = net.get(bridge)
    peer_node = net.get(peer_bridge_or_host)
    links = switch_node.connectionsTo(peer_node)
    if links:
        switch_intf, _ = links[0]
        return str(switch_intf)
    msg = (
        f"No link between {bridge} and {peer_bridge_or_host}; "
        "cannot configure VLAN access tag"
    )
    raise RuntimeError(msg)


def display_network_topo(graph: nx.Graph) -> None:
    """
    Display the network topology graph using Matplotlib.

    Nodes are colored based on their type (host or switch) for better visualization.
    """
    # Hosts are light green, switches are light blue.
    colors = [
        "lightgreen" if graph.nodes[n].get("type") == "host" else "lightblue"
        for n in graph.nodes
    ]

    pos = nx.spring_layout(graph)

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_color=colors,
        node_size=2000,
    )

    plt.show()


def setup_mirror_and_vlans(net: Mininet) -> None:
    """Configure OVS port mirroring and VLAN access tags on s1_omurga."""
    _run(
        "ovs-vsctl add-port s1_omurga mirror0 "
        "-- set Interface mirror0 type=internal"
    )
    mirror0_ofport = _get_ofport("mirror0")
    _run(
        "ovs-vsctl "
        "-- --id=@p get Port mirror0 "
        "-- --id=@m create Mirror name=m0 "
        "select_all=true output-port=@p "
        "-- set Bridge s1_omurga mirrors=@m"
    )
    _run("ip link set mirror0 up")

    vlan_map: dict[str, int] = {
        "hacker": 15,
        "s2_sube": 5,
        "s4_merkez": 10,
    }
    for peer, vlan_id in vlan_map.items():
        port_name = _peer_port_name(net, "s1_omurga", peer)
        _run(f"ovs-vsctl set Port {port_name} tag={vlan_id}")

    print(
        f"[topology] mirror0 (ofport {mirror0_ofport}) active, "
        "VLANs configured on s1_omurga"
    )


class SuricataProcess:
    """Manage Suricata process lifecycle with context-manager semantics."""

    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._log_fh: IO[str] | None = None

    def start(self) -> subprocess.Popen[str]:
        """Launch Suricata in foreground mode on the mirror0 interface."""
        if self._process is not None and self._process.poll() is None:
            msg = "Suricata process is already running"
            raise RuntimeError(msg)

        LOG_DIR.mkdir(parents=True, exist_ok=True)

        if SURICATA_BIN is None:
            msg = "suricata executable not found in PATH"
            raise FileNotFoundError(msg)

        if not SURICATA_RULES.exists():
            msg = f"Suricata rule file not found: {SURICATA_RULES}"
            raise FileNotFoundError(msg)

        self._log_fh = SURICATA_STDERR_LOG.open("a")

        process = subprocess.Popen(  # noqa: S603
            [
                SURICATA_BIN,
                "-c",
                str(SURICATA_CFG),
                "-i",
                "mirror0",
                "-l",
                str(LOG_DIR),
                "-S",
                str(SURICATA_RULES),
            ],
            stdout=subprocess.DEVNULL,
            stderr=self._log_fh,
            text=True,
        )

        self._process = process

        # Give Suricata a moment to initialize and fail fast if startup breaks.
        time.sleep(1)
        if process.poll() is not None:
            self._log_fh.flush()
            diag = SURICATA_STDERR_LOG.read_text().strip()[-2000:]
            msg = (
                f"Suricata exited during startup with code {process.returncode}"
                f"\n--- console log tail ---\n{diag}"
            )
            raise RuntimeError(msg)

        print(f"[topology] Suricata started on mirror0 (log dir: {LOG_DIR})")
        return process

    def _close_log(self) -> None:
        """Close the console log file handle if open."""
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None

    def stop(self) -> None:
        """Stop Suricata process started by this manager."""
        if self._process is None:
            self._close_log()
            return

        process = self._process

        if process.poll() is not None:
            self._process = None
            self._close_log()
            return

        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)  # let this raise if it fails
        finally:
            self._process = None
            self._close_log()

        print("[topology] Suricata stopped")

    def __enter__(self) -> subprocess.Popen[str]:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()


def main() -> None:
    """Start the Mininet topology, configure mirroring, and open CLI."""
    setLogLevel("info")
    topo = EnterpriseWanTopo()
    net = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=RemoteController("ryu", ip="127.0.0.1", port=6633),
        autoSetMacs=True,
    )

    net.start()

    try:
        setup_mirror_and_vlans(net)
        with SuricataProcess() as _suricata:
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()

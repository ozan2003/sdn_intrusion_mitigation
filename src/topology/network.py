"""
Mininet implementation of the enterprise WAN topology.

Its comprised of 4 OVS switches (OpenFlow 1.3), 8 hosts, VLAN-tagged zones on the
backbone switch (s1_omurga), and an OVS mirror port for Suricata.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

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


def _run(cmd: str) -> str:
    """Run a shell command and return stripped stdout."""
    return subprocess.check_output(  # noqa: S603
        cmd.split(), text=True
    ).strip()


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


def start_suricata() -> None:
    """Launch Suricata in daemon mode on the mirror0 interface.

    Stopping of suricata process is handled by start.sh script.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not SURICATA_RULES.exists():
        msg = f"Suricata rule file not found: {SURICATA_RULES}"
        raise FileNotFoundError(msg)

    _run(
        f"suricata -c {SURICATA_CFG} -i mirror0 -D -l {LOG_DIR} "
        f"-S {SURICATA_RULES} "
        "--pidfile /var/run/suricata.pid"
    )
    print(f"[topology] Suricata started on mirror0 (log dir: {LOG_DIR})")


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

    setup_mirror_and_vlans(net)
    start_suricata()

    CLI(net)

    net.stop()


if __name__ == "__main__":
    main()

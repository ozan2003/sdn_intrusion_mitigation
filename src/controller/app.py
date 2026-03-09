"""Ryu SDN controller with VLAN-aware L2 learning and Suricata alert mitigation."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, packet, vlan
from ryu.ofproto import ofproto_v1_3

from controller.alert_parser import AlertParser, MitigationAction
from controller.flow_manager import DEFAULT_HARD_TIMEOUT, FlowManager

if TYPE_CHECKING:
    from ryu.controller.controller import Datapath

    from controller.alert_parser import Alert

# Global logger for the entire module.
LOG = logging.getLogger(__name__)

OMURGA_DPID = 1
# Suricata EVE log consumed by the alert watcher greenthread.
EVE_JSON_PATH = Path("logs/eve.json")

# VLAN IDs for the different zones.
VLAN_INTERNET = 15
VLAN_BRANCH = 5
VLAN_HQ = 10

_ofp_event = cast(Any, ofp_event)
_hub = cast(Any, hub)
# Aliases keep decorators/type-checking cleaner with Ryu's dynamic event types.
EVENT_SWITCH_FEATURES = _ofp_event.EventOFPSwitchFeatures
EVENT_PACKET_IN = _ofp_event.EventOFPPacketIn
EVENT_STATE_CHANGE = _ofp_event.EventOFPStateChange
HUB_SPAWN = _hub.spawn
HUB_SPAWN_AFTER = _hub.spawn_after


class ThreatMitigationApp(app_manager.RyuApp):
    """VLAN-aware L2 switch with automated Suricata alert response."""

    OFP_VERSIONS: ClassVar[list[int]] = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.mac_table: dict[int, dict[tuple[str, int], int]] = {}
        self.datapaths: dict[int, Datapath] = {}
        self.flow_manager = FlowManager()
        self.alert_parser = AlertParser(EVE_JSON_PATH)
        self._mitigated: set[IPv4Address] = set()
        self._alert_thread = HUB_SPAWN(self._watch_alerts)

    @set_ev_cls(EVENT_SWITCH_FEATURES, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: Any) -> None:
        """Install table-miss flow and register the datapath."""
        datapath = cast("Datapath", ev.msg.datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if datapath.id is None:
            LOG.error("Connected switch has no datapath id; skipping setup")
            return

        self.datapaths[datapath.id] = datapath
        LOG.info("Switch connected: dpid=%s", datapath.id)

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.flow_manager.add_flow(
            datapath,
            priority=0,
            match=match,
            instructions=[
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ],
        )

    @set_ev_cls(EVENT_STATE_CHANGE, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev: Any) -> None:
        """Track switch connect/disconnect to keep datapath registry current.

        Without this, a disconnected switch leaves a stale entry in
        ``self.datapaths`` and ``self.mac_table``, causing mitigation
        attempts to write to a dead connection.
        """
        datapath = cast("Datapath", ev.datapath)
        if datapath.id is None:
            return

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            LOG.info("Switch registered: dpid=%s", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id)
            self.mac_table.pop(datapath.id)
            LOG.warning("Switch disconnected: dpid=%s", datapath.id)

    @set_ev_cls(EVENT_PACKET_IN, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: Any) -> None:
        """L2 learning switch with VLAN awareness on the backbone."""
        msg = ev.msg
        datapath = cast("Datapath", msg.datapath)
        if datapath.id is None:
            LOG.error("PacketIn received from datapath without id")
            return
        dpid = datapath.id
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        vlan_hdr = pkt.get_protocol(vlan.vlan)
        vlan_vid = vlan_hdr.vid if vlan_hdr else 0

        if dpid == OMURGA_DPID:
            self._handle_omurga(msg, datapath, ofproto, in_port, eth, vlan_vid)
        else:
            self._handle_simple_switch(msg, datapath, ofproto, in_port, eth)

    def _handle_omurga(
        self,
        msg: Any,
        datapath: Datapath,
        ofproto: Any,
        in_port: int,
        eth: ethernet.ethernet,
        vlan_vid: int,
    ) -> None:
        """VLAN-aware forwarding on the backbone switch."""
        parser = datapath.ofproto_parser
        if datapath.id is None:
            LOG.error("Backbone handler received datapath without id")
            return
        dpid = datapath.id

        table = self.mac_table.setdefault(dpid, {})
        table[(eth.src, vlan_vid)] = in_port

        dst_key_same_vlan = (eth.dst, vlan_vid)
        dst_key_untagged = (eth.dst, 0)

        # Case 1: destination was learned in the same VLAN context.
        if dst_key_same_vlan in table:
            out_port = table[dst_key_same_vlan]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth.dst,
                eth_src=eth.src,
            )
            if vlan_vid:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=eth.dst,
                    eth_src=eth.src,
                    vlan_vid=vlan_vid | ofproto_v1_3.OFPVID_PRESENT,
                )
        # Case 2: ingress is tagged but destination is known untagged;
        # remove VLAN tag before forwarding to the access-side host.
        elif dst_key_untagged in table and vlan_vid != 0:
            out_port = table[dst_key_untagged]
            actions = [
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth.dst,
                eth_src=eth.src,
                vlan_vid=vlan_vid | ofproto_v1_3.OFPVID_PRESENT,
            )
        # Case 3: ingress is untagged but destination was learned in a VLAN;
        # push that VLAN tag to traverse the backbone segment correctly.
        elif vlan_vid == 0:
            found = self._find_dst_in_vlan(dpid, eth.dst)
            if found is not None:
                out_port, dst_vlan = found
                actions = [
                    parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                    parser.OFPActionSetField(
                        vlan_vid=dst_vlan | ofproto_v1_3.OFPVID_PRESENT
                    ),
                    parser.OFPActionOutput(out_port),
                ]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=eth.dst,
                    eth_src=eth.src,
                )
            else:
                self._flood(datapath, ofproto, parser, msg)
                return
        else:
            # Unknown/unsupported VLAN transition; use flooding fallback.
            self._flood(datapath, ofproto, parser, msg)
            return

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        self.flow_manager.add_flow(
            datapath,
            priority=1,
            match=match,
            instructions=inst,
            idle_timeout=300,
        )
        self._send_packet(datapath, ofproto, parser, msg, actions)

    def _handle_simple_switch(
        self,
        msg: Any,
        datapath: Datapath,
        ofproto: Any,
        in_port: int,
        eth: ethernet.ethernet,
    ) -> None:
        """Plain L2 learning for non-backbone switches."""
        parser = datapath.ofproto_parser
        if datapath.id is None:
            LOG.error("Switch handler received datapath without id")
            return
        dpid = datapath.id

        table = self.mac_table.setdefault(dpid, {})
        table[(eth.src, 0)] = in_port

        dst_key = (eth.dst, 0)
        out_port = table.get(dst_key, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=eth.dst, eth_src=eth.src
            )
            inst = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]
            self.flow_manager.add_flow(
                datapath,
                priority=1,
                match=match,
                instructions=inst,
                idle_timeout=300,
            )

        self._send_packet(datapath, ofproto, parser, msg, actions)

    def _find_dst_in_vlan(
        self, dpid: int, dst_mac: str
    ) -> tuple[int, int] | None:
        """Look up *dst_mac* across all VLANs on *dpid*."""
        table = self.mac_table.get(dpid, {})
        for (mac, vid), port in table.items():
            if mac == dst_mac and vid != 0:
                return port, vid
        return None

    @staticmethod
    def _flood(
        datapath: Datapath,
        ofproto: Any,
        parser: Any,
        msg: Any,
    ) -> None:
        """Flood a packet when destination learning has not converged yet."""
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        ThreatMitigationApp._send_packet(
            datapath, ofproto, parser, msg, actions
        )

    @staticmethod
    def _send_packet(
        datapath: Datapath,
        ofproto: Any,
        parser: Any,
        msg: Any,
        actions: list[Any],
    ) -> None:
        """Send PacketOut using buffer when available to avoid data copy."""
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _watch_alerts(self) -> None:
        """Greenthread: tail Suricata EVE JSON and dispatch mitigations."""
        LOG.info("Alert watcher starting (eve=%s) ...", EVE_JSON_PATH)
        self.alert_parser.watch(self._handle_alert)

    def _handle_alert(self, alert: Alert) -> None:
        """Install mitigation on backbone according to Suricata alert action.

        Duplicate alerts for an already-mitigated source are ignored until
        the mitigation timeout elapses and `_clear_mitigation` runs.
        """
        if alert.src_ip in self._mitigated:
            return

        dp = self.datapaths.get(OMURGA_DPID)
        if dp is None:
            LOG.error(
                "s1_omurga (dpid=%d) not connected; cannot install mitigation",
                OMURGA_DPID,
            )
            return

        LOG.warning(
            "ALERT: %s from %s -> %s (sid=%d)",
            alert.signature,
            alert.src_ip,
            alert.dst_ip,
            alert.signature_id,
        )

        if alert.action == MitigationAction.DROP:
            self.flow_manager.install_drop_rule(
                dp, alert.src_ip, vlan_vid=VLAN_INTERNET
            )
        elif alert.action == MitigationAction.RATE_LIMIT:
            self.flow_manager.install_rate_limit(
                dp, alert.src_ip, vlan_vid=VLAN_INTERNET
            )

        self._mitigated.add(alert.src_ip)
        # Schedule cleanup aligned with the flow's hard_timeout so the
        # IP becomes eligible for re-mitigation once the OVS rule expires.
        HUB_SPAWN_AFTER(
            DEFAULT_HARD_TIMEOUT, self._clear_mitigation, alert.src_ip
        )

    def _clear_mitigation(self, src_ip: IPv4Address) -> None:
        """Remove *src_ip* from the mitigated set after the rule expires.

        If the attacker is still active, Suricata will fire a new alert
        and a fresh rule will be installed on the next callback cycle.
        """
        self._mitigated.discard(src_ip)
        LOG.info(
            "Mitigation expired for %s; will re-trigger on new alert", src_ip
        )

"""
Ryu fast-path controller for PAD-ONAP testbed.

Usage:
    ryu-manager --observe-links \
        pipeline.s5_fastpath.ryu_app \
        --wsapi-host 0.0.0.0 --wsapi-port 8080 \
        --ofp-tcp-listen-port 6633

Provides:
    OpenFlow 1.3 layer-2 learning switch (so packets flow even before
    M3 makes a decision).

    REST endpoints (consumed by pipeline M4 + frontend backend):
        GET  /pad/topology        — switches + links + hosts (for viz)
        GET  /pad/flows           — installed flow rules
        GET  /pad/stats           — port + meter counters
        POST /pad/tier            — push tier decision → install Flow-Mod
            body: {"src_ip": "10.0.0.1", "dst_ip": "10.0.3.4",
                   "tier": 3, "attack_type": "SYN",
                   "redirect_to": "10.244.5.42" }
        DELETE /pad/tier          — clear all fast-path rules (back to baseline)

Notes:
    - Tier→action mapping in pipeline/s5_fastpath/tier_to_flowmod.py
    - Designed to run inside the mn-sandbox netns alongside Mininet,
      so OVS switches connect to 127.0.0.1:6633.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import dpset, ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event as topo_event
from ryu.topology.api import get_host, get_link, get_switch
from webob import Response

from pipeline.s5_fastpath.tier_to_flowmod import FlowDirective, directive_for

log = logging.getLogger("pad.fastpath.ryu")
log.setLevel(logging.INFO)


# ─────────────────────────────────────────────────────────────────────────────
# Controller
# ─────────────────────────────────────────────────────────────────────────────
class PadFastPath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication, "dpset": dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi: WSGIApplication = kwargs["wsgi"]
        self.dpset: dpset.DPSet = kwargs["dpset"]

        # mac_to_port[dpid][mac] = out_port  (L2 learning)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.fat_tree_k = int(os.environ.get("PAD_FATTREE_K", "4"))

        # Track installed fast-path rules so we can clear them on request
        # Key = (dpid, src_ip, dst_ip)  →  cookie
        self.installed: dict[tuple[int, str, str], int] = {}

        # Stats snapshot polled every 2 s for the frontend
        self.stats: dict[str, Any] = {
            "ts": 0.0,
            "switches": {},
            "tier_history": [],
        }

        wsgi.register(PadFastPathAPI, {"app": self})
        self.poll_thread = hub.spawn(self._stats_loop)

        log.info("[ryu-fastpath] online — REST :8080  OF :6633")

    # ── Switch features handshake ──────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _on_switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser

        # Default: send unknown packets to controller (table-miss)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._install(dp, priority=0, match=match, actions=actions)
        self._install_fat_tree_base_routes(dp)
        log.info("[ryu-fastpath] switch dpid=%016x joined", dp.id)

    # ── Packet-In: learn MACs, forward ─────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:  # ignore LLDP
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)

        if out_port == ofp.OFPP_FLOOD:
            # Fat-tree is a loopy L2 graph; controller flooding creates storms.
            # Base IPv4/ARP rules below handle the known Mininet host space.
            return

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
        self._install(dp, priority=10, match=match, actions=actions,
                      idle_timeout=60)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    def _known_host_ips(self) -> list[str]:
        half = self.fat_tree_k // 2
        return [
            f"10.{pod}.{edge}.{host}"
            for pod in range(self.fat_tree_k)
            for edge in range(half)
            for host in range(1, half + 1)
        ]

    def _host_location(self, ip: str) -> tuple[int, int, int] | None:
        parts = ip.split(".")
        if len(parts) != 4 or parts[0] != "10":
            return None
        try:
            pod, edge, host = (int(parts[1]), int(parts[2]), int(parts[3]))
        except ValueError:
            return None
        half = self.fat_tree_k // 2
        if not (0 <= pod < self.fat_tree_k and 0 <= edge < half and 1 <= host <= half):
            return None
        return pod, edge, host

    def _out_port_for_dst(self, dpid: int, dst_ip: str) -> int | None:
        loc = self._host_location(dst_ip)
        if loc is None:
            return None
        dst_pod, dst_edge, dst_host = loc
        half = self.fat_tree_k // 2
        dpid_hex = f"{dpid:016x}"
        role = int(dpid_hex[0:2], 16)
        pod = int(dpid_hex[2:4], 16)
        edge = int(dpid_hex[4:6], 16)

        if role == 0x10:          # core: one downlink per pod
            return dst_pod + 1
        if role == 0x20:          # aggregation: edge downlinks, then core uplinks
            if pod == dst_pod:
                return dst_edge + 1
            return half + 1       # deterministic first core uplink
        if role == 0x30:          # edge: host downlinks, then aggregation uplinks
            if pod == dst_pod and edge == dst_edge:
                return dst_host
            return half + 1       # deterministic first aggregation uplink
        return None

    def _install_fat_tree_base_routes(self, dp) -> None:
        """Install deterministic IPv4/ARP forwarding for the Mininet fat-tree.

        L2 flooding is unsafe in a fat-tree because the graph contains many
        loops. These low-priority routes provide a stable baseline path; tier
        rules installed by /pad/tier use priority 1000 and override them.
        """
        parser = dp.ofproto_parser
        for ip in self._known_host_ips():
            out_port = self._out_port_for_dst(dp.id, ip)
            if out_port is None:
                continue
            actions = [parser.OFPActionOutput(out_port)]
            self._install(
                dp, priority=50,
                match=parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip),
                actions=actions)
            self._install(
                dp, priority=45,
                match=parser.OFPMatch(eth_type=0x0806, arp_tpa=ip),
                actions=actions)

    # ── Helper: install a flow ─────────────────────────────────────────────
    def _install(self, dp, priority, match, actions, idle_timeout=0,
                 hard_timeout=0, cookie=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout, cookie=cookie)
        dp.send_msg(mod)

    # ── Tier → Flow-Mod installation ───────────────────────────────────────
    def apply_tier(self, src_ip: str, dst_ip: str, tier: int,
                   attack_type: str = "", redirect_to: str = "") -> dict:
        """
        Push the tier decision to ALL switches (edge layer is enough but for
        simplicity we hit every connected dp). Returns a summary dict.
        """
        d: FlowDirective = directive_for(tier, attack_type)
        if redirect_to:
            d.redirect_to = redirect_to

        cookie = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
        installed_on: list[int] = []
        for dp in self.dpset.get_all():
            dp = dp[1]
            ofp, parser = dp.ofproto, dp.ofproto_parser
            match = parser.OFPMatch(
                eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)

            if d.action == "pass":
                continue  # nothing to install — keep baseline L2 learning
            if d.action == "monitor":
                # priority bump but pass — counts hits via stats poll
                actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            elif d.action == "drop":
                actions = []  # empty action list = drop
            elif d.action == "ratelimit":
                # Use meter-band if supported; fall back to drop on overflow.
                # For simplicity install a high-priority forward + we rely on
                # OVS rate-limit qdisc set by Mininet TCLink.
                out_port = self._out_port_for_dst(dp.id, dst_ip)
                actions = ([parser.OFPActionOutput(out_port)]
                           if out_port is not None else [parser.OFPActionOutput(ofp.OFPP_NORMAL)])
            elif d.action == "redirect":
                # Rewrite dst IP to scrubber pod and forward normally
                out_port = self._out_port_for_dst(dp.id, d.redirect_to) if d.redirect_to else None
                if d.redirect_to and out_port is not None:
                    actions = [
                        parser.OFPActionSetField(ipv4_dst=d.redirect_to),
                        parser.OFPActionOutput(out_port),
                    ]
                elif d.redirect_to:
                    # External scrubber is outside the Mininet host space in
                    # local runs; dropping the attack flow is safer than NORMAL.
                    actions = []
                else:
                    out_port = self._out_port_for_dst(dp.id, dst_ip)
                    actions = ([parser.OFPActionOutput(out_port)]
                               if out_port is not None else [parser.OFPActionOutput(ofp.OFPP_NORMAL)])
            else:
                out_port = self._out_port_for_dst(dp.id, dst_ip)
                actions = ([parser.OFPActionOutput(out_port)]
                           if out_port is not None else [parser.OFPActionOutput(ofp.OFPP_NORMAL)])

            self._install(
                dp, priority=1000, match=match, actions=actions,
                idle_timeout=d.idle_timeout, hard_timeout=d.hard_timeout,
                cookie=cookie)
            self.installed[(dp.id, src_ip, dst_ip)] = cookie
            installed_on.append(dp.id)

        summary = {
            "ts": time.time(),
            "tier": tier,
            "action": d.action,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "rate_pps": d.rate_pps,
            "redirect_to": d.redirect_to,
            "installed_on_dpids": [f"{x:016x}" for x in installed_on],
        }
        self.stats["tier_history"].append(summary)
        # Keep only the last 200 events for the frontend
        self.stats["tier_history"] = self.stats["tier_history"][-200:]
        log.info("[ryu-fastpath] tier=%d action=%s src=%s dst=%s on %d switches",
                 tier, d.action, src_ip, dst_ip, len(installed_on))
        return summary

    def clear_all_tier_rules(self) -> int:
        """Remove every fast-path rule we installed."""
        removed = 0
        for (dpid, _src, _dst), cookie in list(self.installed.items()):
            dp = self.dpset.get(dpid)
            if dp is None:
                continue
            ofp, parser = dp.ofproto, dp.ofproto_parser
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF)
            dp.send_msg(mod)
            removed += 1
        self.installed.clear()
        log.info("[ryu-fastpath] cleared %d fast-path rules", removed)
        return removed

    # ── Periodic snapshot for the frontend ─────────────────────────────────
    def _stats_loop(self):
        while True:
            snap = {"ts": time.time(), "switches": {}}
            for dpid, dp in self.dpset.get_all():
                snap["switches"][f"{dpid:016x}"] = {
                    "mac_learned": len(self.mac_to_port.get(dpid, {})),
                    "rules": sum(
                        1 for k in self.installed if k[0] == dpid),
                }
            snap["tier_history"] = self.stats["tier_history"]
            self.stats = snap
            hub.sleep(2)

    # ── Topology snapshot for viz ──────────────────────────────────────────
    def topology_snapshot(self) -> dict:
        switches = [s.to_dict() for s in get_switch(self, None)]
        links = [l.to_dict() for l in get_link(self, None)]
        try:
            hosts = [h.to_dict() for h in get_host(self, None)]
        except Exception:
            hosts = []
        return {"switches": switches, "links": links, "hosts": hosts}


# ─────────────────────────────────────────────────────────────────────────────
# REST controller
# ─────────────────────────────────────────────────────────────────────────────
class PadFastPathAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: PadFastPath = data["app"]

    def _json(self, body, status=200):
        return Response(content_type="application/json",
                        body=json.dumps(body).encode(), status=status)

    @route("pad", "/pad/topology", methods=["GET"])
    def topology(self, req, **_):
        return self._json(self.app.topology_snapshot())

    @route("pad", "/pad/flows", methods=["GET"])
    def flows(self, req, **_):
        rules = [
            {"dpid": f"{dpid:016x}", "src_ip": src, "dst_ip": dst,
             "cookie": cookie}
            for (dpid, src, dst), cookie in self.app.installed.items()
        ]
        return self._json({"installed": rules, "count": len(rules)})

    @route("pad", "/pad/stats", methods=["GET"])
    def stats(self, req, **_):
        return self._json(self.app.stats)

    @route("pad", "/pad/tier", methods=["POST"])
    def post_tier(self, req, **_):
        try:
            body = json.loads(req.body or b"{}")
            src = body["src_ip"]
            dst = body["dst_ip"]
            tier = int(body["tier"])
            attack = body.get("attack_type", "")
            redirect_to = body.get("redirect_to", "")
        except (KeyError, ValueError) as e:
            return self._json({"error": f"bad request: {e}"}, status=400)
        return self._json(self.app.apply_tier(
            src, dst, tier, attack, redirect_to))

    @route("pad", "/pad/tier", methods=["DELETE"])
    def clear_tier(self, req, **_):
        n = self.app.clear_all_tier_rules()
        return self._json({"cleared": n})

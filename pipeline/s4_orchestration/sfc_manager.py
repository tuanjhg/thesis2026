"""
M4 — SFC Manager: OpenFlow / OVS rule injection (Spec-aligned §6.2)

Steers attack traffic through the active VNF chain by inserting OVS flow rules.

Stub mode (PAD_ONAP_STUB=true):
  - Logs intended rules, records timestamps in LatencyRecord
  - No actual OVS interaction — safe to run without Mininet/OVS

Real mode (PAD_ONAP_STUB=false):
  - Calls `ovs-ofctl add-flow` / `ovs-ofctl del-flows` via subprocess
  - Uses REST SDN controller if PAD_SDN_URL is set (ONAP SDNR / ODL)

Environment variables:
  PAD_ONAP_STUB     : true / false
  PAD_OVS_BRIDGE    : br-pad  (OVS bridge name)
  PAD_SDN_URL       : http://sdnr.onap.svc:8282  (optional — use REST instead of CLI)
  PAD_SDN_USER / PAD_SDN_PASS
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_STUB_MODE  = os.environ.get('PAD_ONAP_STUB', 'true').lower() != 'false'
_OVS_BRIDGE = os.environ.get('PAD_OVS_BRIDGE', 'br-pad')
_SDN_URL    = os.environ.get('PAD_SDN_URL', '')
_SDN_USER   = os.environ.get('PAD_SDN_USER', 'admin')
_SDN_PASS   = os.environ.get('PAD_SDN_PASS', 'admin')

# OpenFlow priorities
PRIO_SFC   = 200   # SFC steering rules
PRIO_PASS  = 100   # normal forwarding


@dataclass
class SFCRule:
    rule_id:      str
    device_id:    str     # traffic source IP to match
    vnf_ip:       str     # redirect destination (VNF container IP)
    vnf_port:     int
    tier:         int
    ovs_flow:     str     # raw OVS flow spec (for audit)
    installed:    bool = False
    t_installed:  float = 0.0


class SFCManager:
    """
    Manages SFC steering rules per device.

    Usage:
        sfc = SFCManager()
        rule = sfc.install(device_id='10.0.0.5', vnf_inst=inst, tier=3)
        t_sfc = rule.t_installed
        # ...
        sfc.remove(device_id='10.0.0.5')
    """

    def __init__(self):
        self.stub_mode = _STUB_MODE
        self._rules: Dict[str, List[SFCRule]] = {}   # device_id → rules
        if self.stub_mode:
            logger.info(f"SFCManager: STUB mode (no real OVS calls) "
                        f"— set PAD_ONAP_STUB=false for real OVS")
        else:
            logger.info(f"SFCManager: REAL mode  OVS bridge={_OVS_BRIDGE}"
                        + (f"  SDN={_SDN_URL}" if _SDN_URL else "  (ovs-ofctl CLI)"))

    def install(self, device_id: str, vnf_inst, tier: int) -> SFCRule:
        """
        Install SFC steering rule: traffic from device_id → VNF.

        Args:
            device_id: source IP of attack traffic
            vnf_inst:  VNFInstance with container_ip + health_port
            tier:      current tier (used for logging / metrics)

        Returns:
            SFCRule with t_installed set
        """
        rule_id  = str(uuid.uuid4())
        ovs_flow = (
            f"priority={PRIO_SFC},ip,nw_src={device_id},"
            f"actions=mod_nw_dst:{vnf_inst.container_ip},output:1"
        )

        rule = SFCRule(
            rule_id    = rule_id,
            device_id  = device_id,
            vnf_ip     = vnf_inst.container_ip,
            vnf_port   = vnf_inst.health_port,
            tier       = tier,
            ovs_flow   = ovs_flow,
        )

        if self.stub_mode:
            self._stub_install(rule)
        elif _SDN_URL:
            self._sdn_install(rule)
        else:
            self._ovs_install(rule)

        self._rules.setdefault(device_id, []).append(rule)
        return rule

    def remove(self, device_id: str) -> bool:
        """Remove all SFC rules for a device (called on tier de-escalation)."""
        rules = self._rules.pop(device_id, [])
        if not rules:
            return True
        ok = True
        for rule in rules:
            if self.stub_mode:
                logger.info(f"[SFC/stub] Remove rule for {device_id}: {rule.ovs_flow}")
            elif _SDN_URL:
                ok &= self._sdn_remove(rule)
            else:
                ok &= self._ovs_remove(rule)
        return ok

    def active_devices(self) -> List[str]:
        return list(self._rules.keys())

    # ── Stub ───────────────────────────────────────────────────────────────────

    def _stub_install(self, rule: SFCRule):
        logger.info(
            f"[SFC/stub] Install rule  device={rule.device_id} "
            f"→ vnf={rule.vnf_ip}:{rule.vnf_port}  tier=T{rule.tier}"
        )
        logger.debug(f"[SFC/stub] OVS flow: {rule.ovs_flow}")
        rule.installed   = True
        rule.t_installed = time.time()

    # ── OVS CLI ────────────────────────────────────────────────────────────────

    def _ovs_install(self, rule: SFCRule):
        try:
            cmd = ['ovs-ofctl', 'add-flow', _OVS_BRIDGE, rule.ovs_flow]
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            rule.installed   = True
            rule.t_installed = time.time()
            logger.info(f"[SFC/OVS] Installed flow for {rule.device_id}")
        except Exception as e:
            logger.error(f"[SFC/OVS] install failed: {e}")
            rule.installed = False

    def _ovs_remove(self, rule: SFCRule) -> bool:
        try:
            del_flow = f"priority={PRIO_SFC},ip,nw_src={rule.device_id}"
            cmd = ['ovs-ofctl', 'del-flows', _OVS_BRIDGE, del_flow]
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            return True
        except Exception as e:
            logger.error(f"[SFC/OVS] remove failed: {e}")
            return False

    # ── SDN REST (ONAP SDNR / ODL) ────────────────────────────────────────────

    def _sdn_install(self, rule: SFCRule):
        import urllib.request, base64, json as _json
        url   = f'{_SDN_URL}/restconf/operations/sal-flow:add-flow'
        body  = _json.dumps({
            'input': {
                'node': f'/inv:nodes/inv:node[inv:id="{_OVS_BRIDGE}"]',
                'match': {'ip-match': {'ip-proto': 4},
                          'ipv4-source': f'{rule.device_id}/32'},
                'instructions': {'instruction': [{
                    'order': 0,
                    'apply-actions': {'action': [{
                        'order': 0,
                        'set-nw-dest-action': {'address': rule.vnf_ip},
                    }, {
                        'order': 1,
                        'output-action': {'output-node-connector': '1'},
                    }]}
                }]},
                'priority': PRIO_SFC,
                'table_id': 0,
            }
        }).encode()
        auth = base64.b64encode(f'{_SDN_USER}:{_SDN_PASS}'.encode()).decode()
        hdrs = {'Content-Type': 'application/json', 'Authorization': f'Basic {auth}'}
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method='POST')
            urllib.request.urlopen(req, timeout=5)
            rule.installed   = True
            rule.t_installed = time.time()
            logger.info(f"[SFC/SDN] Rule installed for {rule.device_id}")
        except Exception as e:
            logger.error(f"[SFC/SDN] install failed: {e}")

    def _sdn_remove(self, rule: SFCRule) -> bool:
        import urllib.request, base64
        url  = (f'{_SDN_URL}/restconf/config/opendaylight-inventory:nodes/'
                f'node/{_OVS_BRIDGE}/table/0/flow/{rule.rule_id}')
        auth = base64.b64encode(f'{_SDN_USER}:{_SDN_PASS}'.encode()).decode()
        hdrs = {'Authorization': f'Basic {auth}'}
        try:
            req = urllib.request.Request(url, headers=hdrs, method='DELETE')
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.error(f"[SFC/SDN] remove failed: {e}")
            return False

"""
M3 — CLAMP / Policy Framework Client (Spec-aligned §5.6)

CLAMP (Closed-Loop Automation Management Platform) translates tier decisions
into ONAP Policy Framework rules that are pushed to PDP-X (Drools).

Modes:
  Real ONAP: POST to /policy/pap/v1/pdps/policies  (PAP API)
             Requires PAD_ONAP_POLICY_URL, PAD_ONAP_POLICY_USER/PASS
  Stub mode: writes policy JSON to local file + REST stub endpoint

Policy generated per event:
  - Tier 1 : monitoring_sampling_rate → 2x (ALERT)
  - Tier 2 : pre_position_vnf with VNF profile  (PREEMPT)
  - Tier 3 : activate_sfc with VNF chain descriptor (MITIGATE)
  - Tier 4 : blackhole + scrubber chain (ISOLATE)
  - Tier 0 : revoke all active policies (NORMAL)

SO request builder:
  build_so_request() generates ONAP SO instantiation request body
  from a PolicyDecision — used by ONAPSOClient._onap_so_create()
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_POLICY_URL   = os.environ.get('PAD_ONAP_POLICY_URL',  'http://policy-pap.onap.svc:6969')
_POLICY_USER  = os.environ.get('PAD_ONAP_POLICY_USER', 'healthcheck')
_POLICY_PASS  = os.environ.get('PAD_ONAP_POLICY_PASS', 'zb!XztG34')
_STUB_MODE    = os.environ.get('PAD_ONAP_STUB', 'true').lower() != 'false'
_STUB_DIR     = Path(os.environ.get('PAD_CLAMP_STUB_DIR', '/tmp/pad_policies'))


@dataclass
class PolicyRequest:
    policy_id:    str
    tier:         int
    attack_type:  str
    vnf_profile:  Optional[str]
    device_id:    str
    timestamp:    str
    drools_spec:  dict   # ONAP policy spec body


class CLAMPClient:
    """
    CLAMP / Policy Framework client.

    Usage:
        clamp  = CLAMPClient()
        policy = clamp.build_policy(pdec, device_id='10.0.0.1')
        clamp.push(policy)
    """

    def __init__(self):
        self.stub_mode = _STUB_MODE
        if self.stub_mode:
            _STUB_DIR.mkdir(parents=True, exist_ok=True)
            logger.info(f"CLAMPClient: STUB mode → {_STUB_DIR}  "
                        f"(set PAD_ONAP_STUB=false for real ONAP Policy)")
        else:
            logger.info(f"CLAMPClient: REAL mode → {_POLICY_URL}")

    def build_policy(self, pdec, device_id: str = 'unknown') -> PolicyRequest:
        """
        Build an ONAP Policy Framework request from a PolicyDecision.

        Args:
            pdec:      PolicyDecision from PolicyEngine.evaluate()
            device_id: source IP / ONAP service instance UUID

        Returns:
            PolicyRequest with drools_spec ready to push
        """
        td        = pdec.tier_decision
        tier      = int(pdec.new_tier)
        policy_id = f'pad.orchestration.tier{tier}.{uuid.uuid4().hex[:8]}'
        ts        = datetime.now(timezone.utc).isoformat()

        drools_spec = self._tier_to_drools(
            tier        = tier,
            attack_type = td.attack_type,
            vnf_profile = td.vnf_profile,
            device_id   = device_id,
            policy_id   = policy_id,
        )

        return PolicyRequest(
            policy_id   = policy_id,
            tier        = tier,
            attack_type = td.attack_type,
            vnf_profile = td.vnf_profile,
            device_id   = device_id,
            timestamp   = ts,
            drools_spec = drools_spec,
        )

    def push(self, policy: PolicyRequest) -> bool:
        """
        Push policy to ONAP PAP / write stub.
        Returns True if successful.
        """
        if self.stub_mode:
            return self._write_stub(policy)
        else:
            return self._push_real(policy)

    def revoke_all(self, device_id: str) -> bool:
        """Revoke all active policies for a device (called on Tier 0 / NORMAL)."""
        logger.info(f"[CLAMP] Revoke all policies for device={device_id}")
        if self.stub_mode:
            # Mark existing stubs as revoked
            try:
                for f in _STUB_DIR.glob(f'*.json'):
                    data = json.loads(f.read_text())
                    if data.get('device_id') == device_id:
                        data['status'] = 'REVOKED'
                        f.write_text(json.dumps(data, indent=2))
            except Exception:
                pass
            return True
        else:
            return self._revoke_real(device_id)

    # ── Drools spec builder ────────────────────────────────────────────────────

    def _tier_to_drools(
        self, tier: int, attack_type: str,
        vnf_profile: Optional[str], device_id: str, policy_id: str
    ) -> dict:
        """Generate ONAP Policy Framework Drools spec for each tier."""

        base = {
            'tosca_definitions_version': 'tosca_simple_yaml_1_1_0',
            'topology_template': {
                'policies': [{
                    policy_id: {
                        'type':    'onap.policies.controlloop.operational.common.Drools',
                        'type_version': '1.0.0',
                        'metadata': {
                            'policy-id':      policy_id,
                            'policy-version': '1',
                        },
                        'properties': {
                            'id':             policy_id,
                            'timeout':        60,
                            'abatement':      True,
                            'trigger':        f'pad.orchestration.tier{tier}',
                            'operations':     self._build_operations(
                                tier, attack_type, vnf_profile, device_id
                            ),
                        }
                    }
                }]
            }
        }
        return base

    def _build_operations(
        self, tier: int, attack_type: str,
        vnf_profile: Optional[str], device_id: str
    ) -> list:
        if tier == 0:
            return [{'id': 'op1', 'description': 'No action', 'operation': {'actor': 'SDNC', 'operation': 'NOOP'}}]
        elif tier == 1:
            return [{
                'id': 'op1',
                'description': f'Increase telemetry sampling — {attack_type}',
                'operation': {
                    'actor': 'SDNR',
                    'operation': 'ModifyConfig',
                    'target': {'targetType': 'VNF', 'entityIds': {'deviceId': device_id}},
                    'payload': {'samplingRate': '2x', 'reason': attack_type},
                }
            }]
        elif tier == 2:
            return [{
                'id': 'op1',
                'description': f'Pre-position VNF {vnf_profile}',
                'operation': {
                    'actor': 'SO',
                    'operation': 'VF Module Create',
                    'target': {'targetType': 'VF Module'},
                    'payload': {
                        'requestParameters': json.dumps({
                            'vnfProfile': vnf_profile,
                            'mode':       'preposition',
                            'deviceId':   device_id,
                        })
                    },
                }
            }]
        elif tier == 3:
            return [{
                'id': 'op1',
                'description': f'Insert VNF {vnf_profile} into SFC',
                'operation': {
                    'actor': 'SO',
                    'operation': 'VF Module Create',
                    'target': {'targetType': 'VF Module'},
                    'payload': {
                        'requestParameters': json.dumps({
                            'vnfProfile': vnf_profile,
                            'mode':       'active_sfc',
                            'attackType': attack_type,
                            'deviceId':   device_id,
                        })
                    },
                }
            }]
        else:  # tier == 4
            return [
                {
                    'id': 'op1',
                    'description': 'Activate scrubber',
                    'operation': {
                        'actor': 'SO', 'operation': 'VF Module Create',
                        'payload': {'requestParameters': json.dumps({
                            'vnfProfile': 'vnfd-scrubber-v1', 'mode': 'active_sfc',
                            'deviceId': device_id,
                        })},
                    }
                },
                {
                    'id': 'op2',
                    'description': 'Activate blackhole',
                    'operation': {
                        'actor': 'SO', 'operation': 'VF Module Create',
                        'payload': {'requestParameters': json.dumps({
                            'vnfProfile': 'vnfd-blackhole-v1', 'mode': 'active',
                            'deviceId': device_id,
                        })},
                    }
                },
            ]

    # ── Stub ───────────────────────────────────────────────────────────────────

    def _write_stub(self, policy: PolicyRequest) -> bool:
        try:
            out = _STUB_DIR / f'{policy.policy_id}.json'
            data = {
                'policy_id':   policy.policy_id,
                'tier':        policy.tier,
                'attack_type': policy.attack_type,
                'vnf_profile': policy.vnf_profile,
                'device_id':   policy.device_id,
                'timestamp':   policy.timestamp,
                'status':      'ACTIVE',
                'drools_spec': policy.drools_spec,
            }
            out.write_text(json.dumps(data, indent=2))
            logger.debug(f"[CLAMP/stub] Written {out}")
            return True
        except Exception as e:
            logger.error(f"[CLAMP/stub] Write failed: {e}")
            return False

    # ── Real ONAP PAP ──────────────────────────────────────────────────────────

    def _push_real(self, policy: PolicyRequest) -> bool:
        import urllib.request, base64
        body  = json.dumps(policy.drools_spec).encode()
        auth  = base64.b64encode(f'{_POLICY_USER}:{_POLICY_PASS}'.encode()).decode()
        hdrs  = {
            'Content-Type':  'application/json',
            'Accept':        'application/json',
            'Authorization': f'Basic {auth}',
        }
        url = f'{_POLICY_URL}/policy/pap/v1/pdps/policies'
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method='POST')
            with urllib.request.urlopen(req, timeout=10) as r:
                logger.info(f"[CLAMP/real] Pushed {policy.policy_id} → {r.status}")
                return r.status in (200, 201, 202)
        except Exception as e:
            logger.error(f"[CLAMP/real] Push failed: {e}")
            return False

    def _revoke_real(self, device_id: str) -> bool:
        import urllib.request, base64
        auth = base64.b64encode(f'{_POLICY_USER}:{_POLICY_PASS}'.encode()).decode()
        hdrs = {'Authorization': f'Basic {auth}'}
        url  = f'{_POLICY_URL}/policy/pap/v1/pdps/policies?deviceId={device_id}'
        try:
            req = urllib.request.Request(url, headers=hdrs, method='DELETE')
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as e:
            logger.error(f"[CLAMP/real] Revoke failed: {e}")
            return False


# ── SO request builder (standalone utility) ───────────────────────────────────

def build_so_request(pdec, device_id: str = 'unknown') -> dict:
    """
    Build ONAP SO instantiation request body from a PolicyDecision.
    Convenience function — same logic as CLAMPClient._build_operations().
    """
    td = pdec.tier_decision
    return {
        'requestDetails': {
            'modelInfo': {
                'modelType':      'vnf',
                'modelName':      td.vnf_profile or 'noop',
                'modelVersionId': '1.0',
            },
            'requestInfo': {
                'instanceName': f'pad-{td.vnf_profile}-{uuid.uuid4().hex[:8]}',
                'source':       'pad-orchestrator',
            },
            'requestParameters': {
                'userParams': [
                    {'name': 'attackType', 'value': td.attack_type},
                    {'name': 'tier',       'value': str(int(pdec.new_tier))},
                    {'name': 'deviceId',   'value': device_id},
                ]
            }
        }
    }

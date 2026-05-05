"""
onap_e2e_lib.py — Shared ONAP REST helpers for PAD-ONAP real E2E scenarios
===========================================================================
Dùng chung cho run_s2_real.py và run_s8_real.py.

Cung cấp:
  - ONAPSOReal      : gọi SO v7 REST (instantiate / terminate VNF)
  - CLAMPReal       : gọi Policy PAP REST (push / revoke Drools policy)
  - OVSSFCReal      : gọi ovs-ofctl qua SSH/subprocess (install / remove SFC rule)
  - LatencyCollector: thu thập và in bảng latency cuối kịch bản
  - wait_vnf_active : poll SO instance status đến ACTIVE hoặc timeout

Biến môi trường cần set trước khi chạy:
  ONAP_HOST              IP/hostname của K8s node (kubectl get nodes -o wide)
  ONAP_SO_PORT           NodePort của SO (mặc định 30080)
  ONAP_POLICY_PORT       NodePort của Policy PAP (mặc định 30969)
  ONAP_DMAAP_PORT        NodePort của DMaaP (mặc định 30904)
  PAD_ONAP_SO_USER       so_admin
  PAD_ONAP_SO_PASS       demo123456!
  PAD_ONAP_POLICY_USER   healthcheck
  PAD_ONAP_POLICY_PASS   zb!XztG34
  PAD_ONAP_STUB          false   ← bắt buộc
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger("onap_e2e")

# ── Env config ────────────────────────────────────────────────────────────────
ONAP_HOST     = os.environ.get("ONAP_HOST",           "localhost")
SO_PORT       = int(os.environ.get("ONAP_SO_PORT",    "30080"))
POLICY_PORT   = int(os.environ.get("ONAP_POLICY_PORT","30969"))
DMAAP_PORT    = int(os.environ.get("ONAP_DMAAP_PORT", "30904"))
SO_USER       = os.environ.get("PAD_ONAP_SO_USER",    "so_admin")
SO_PASS       = os.environ.get("PAD_ONAP_SO_PASS",    "demo123456!")
POLICY_USER   = os.environ.get("PAD_ONAP_POLICY_USER","healthcheck")
POLICY_PASS   = os.environ.get("PAD_ONAP_POLICY_PASS","zb!XztG34")
DMAAP_TOPIC   = os.environ.get("PAD_DMAAP_TOPIC",     "PAD_ONAP_AI_SIGNALS")

SO_BASE    = f"http://{ONAP_HOST}:{SO_PORT}/onap/so/infra"
POLICY_BASE= f"http://{ONAP_HOST}:{POLICY_PORT}"
DMAAP_BASE = f"http://{ONAP_HOST}:{DMAAP_PORT}"

REQUESTS_TIMEOUT = 30   # seconds per HTTP call

# Service / subscriber info (must match SDC onboarding)
GLOBAL_CUSTOMER_ID   = "pad-onap-customer"
SUBSCRIPTION_TYPE    = "pad-onap-service"
SERVICE_MODEL_UUID   = os.environ.get("PAD_SERVICE_MODEL_UUID",  "REPLACE_WITH_SDC_UUID")
SERVICE_INSTANCE_ID  = os.environ.get("PAD_SERVICE_INSTANCE_ID", "REPLACE_OR_CREATE_LIVE")

HEADERS = {
    "Content-Type":      "application/json",
    "Accept":            "application/json",
    "X-TransactionId":   "pad-onap-e2e",
    "X-FromAppId":       "pad-onap-pipeline",
}


# ── Latency tracker ───────────────────────────────────────────────────────────
@dataclass
class E2ERecord:
    scenario:     str
    vnf_profile:  str
    detector:     str   = "ai"   # "ai" | "rule_based"
    t_attack_start: float = 0.0  # wall-clock when flood injection begins
    t_trigger:    float = 0.0   # detector fires (AI tier ≥ 3 or rule trip)
    t_policy_push:float = 0.0   # CLAMP/Policy PAP accepted
    t_so_request: float = 0.0   # SO POST sent
    t_vnf_active: float = 0.0   # SO instance ACTIVE
    t_sfc_rule:   float = 0.0   # OVS rule installed
    detector_label:    str   = ""    # e.g. "UDP_Flood conf=0.92" or "pkt_rate>10k"
    detector_evidence: dict  = field(default_factory=dict)
    error:        Optional[str] = None

    @property
    def detection_lat_ms(self):
        if self.t_attack_start == 0.0: return 0.0
        return (self.t_trigger - self.t_attack_start) * 1000
    @property
    def detection_to_policy_ms(self): return (self.t_policy_push - self.t_trigger) * 1000
    @property
    def policy_to_so_ms(self):        return (self.t_so_request  - self.t_policy_push) * 1000
    @property
    def so_to_vnf_ms(self):           return (self.t_vnf_active  - self.t_so_request)  * 1000
    @property
    def vnf_to_sfc_ms(self):          return (self.t_sfc_rule    - self.t_vnf_active)  * 1000
    @property
    def pipeline_e2e_ms(self):        return (self.t_sfc_rule    - self.t_trigger)      * 1000
    @property
    def time_to_mitigation_ms(self):
        if self.t_attack_start == 0.0: return 0.0
        return (self.t_sfc_rule - self.t_attack_start) * 1000
    # Backwards compat
    @property
    def end_to_end_ms(self):          return self.pipeline_e2e_ms

    def print_table(self):
        rows = [
            ("Attack start → Detect",     self.detection_lat_ms),
            ("Detect → Policy push",      self.detection_to_policy_ms),
            ("Policy push → SO request",  self.policy_to_so_ms),
            ("SO request → VNF ACTIVE",   self.so_to_vnf_ms),
            ("VNF ACTIVE → SFC rule",     self.vnf_to_sfc_ms),
            ("Pipeline (Detect → SFC)",   self.pipeline_e2e_ms),
            ("Time-to-mitigation total",  self.time_to_mitigation_ms),
        ]
        w = 36
        print(f"\n{'─'*55}")
        print(f"  Latency breakdown — {self.scenario} ({self.vnf_profile})")
        print(f"{'─'*55}")
        for label, ms in rows:
            bar = "█" * min(int(ms / 200), 30)
            print(f"  {label:<{w}} {ms:>8.0f} ms  {bar}")
        print(f"{'─'*55}")
        if self.error:
            print(f"  ERROR: {self.error}")


# ── SO Client ────────────────────────────────────────────────────────────────
class ONAPSOReal:
    """Calls ONAP SO v7 REST API to instantiate / terminate VNF."""

    def __init__(self):
        self.auth = HTTPBasicAuth(SO_USER, SO_PASS)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(HEADERS)
        self.session.verify = False

    def health(self) -> bool:
        try:
            r = self.session.get(
                f"{SO_BASE.replace('/onap/so/infra','')}/manage/health",
                timeout=REQUESTS_TIMEOUT
            )
            return r.status_code == 200
        except Exception:
            return False

    def instantiate(self, vnf_profile: str, device_id: str) -> Optional[str]:
        """
        POST to SO serviceInstantiation v7.
        Returns instance_id or None on failure.
        Mapping vnf_profile → SO request body per VNFD names.
        """
        body = _build_so_request(vnf_profile, device_id)
        url  = f"{SO_BASE}/serviceInstantiation/v7/serviceInstances"
        logger.info(f"[SO] POST {url}")
        try:
            r = self.session.post(url, json=body, timeout=REQUESTS_TIMEOUT)
            r.raise_for_status()
            data        = r.json()
            instance_id = (data.get("requestReferences", {}).get("instanceId")
                           or data.get("serviceInstanceId"))
            req_id      = data.get("requestReferences", {}).get("requestId", "?")
            logger.info(f"[SO] instance_id={instance_id}  requestId={req_id}")
            return instance_id
        except Exception as e:
            logger.error(f"[SO] instantiate failed: {e}")
            return None

    def poll_status(self, instance_id: str) -> str:
        """Returns ACTIVE | IN_PROGRESS | FAILED | UNKNOWN."""
        url = f"{SO_BASE}/orchestrationRequests/v7?filter=serviceInstanceId:EQUALS:{instance_id}"
        try:
            r = self.session.get(url, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return "UNKNOWN"
            data     = r.json()
            requests_list = data.get("requestList", [])
            if not requests_list:
                return "UNKNOWN"
            latest   = requests_list[-1].get("request", {})
            status   = latest.get("requestStatus", {}).get("requestState", "UNKNOWN")
            # SO states: IN_PROGRESS, COMPLETE, FAILED
            if status == "COMPLETE":
                return "ACTIVE"
            if status == "FAILED":
                return "FAILED"
            return "IN_PROGRESS"
        except Exception as e:
            logger.warning(f"[SO] poll_status error: {e}")
            return "UNKNOWN"

    def terminate(self, instance_id: str) -> bool:
        url  = (f"{SO_BASE}/serviceInstantiation/v7/serviceInstances"
                f"/{instance_id}/terminate")
        body = {
            "requestDetails": {
                "requestInfo": {
                    "source": "pad-onap-pipeline",
                    "requestorId": "pad-onap"
                },
                "requestParameters": {"aLaCarte": True}
            }
        }
        try:
            r = self.session.delete(url, json=body, timeout=REQUESTS_TIMEOUT)
            ok = r.status_code in (200, 202, 204)
            logger.info(f"[SO] terminate {instance_id}: HTTP {r.status_code}")
            return ok
        except Exception as e:
            logger.error(f"[SO] terminate failed: {e}")
            return False


def wait_vnf_active(so: ONAPSOReal, instance_id: str,
                    timeout_s: float = 120.0,
                    poll_interval_s: float = 3.0) -> float:
    """
    Poll SO until instance ACTIVE or timeout.
    Returns epoch timestamp when ACTIVE, or raises TimeoutError.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = so.poll_status(instance_id)
        logger.info(f"[SO] poll {instance_id}: {status}")
        if status == "ACTIVE":
            return time.time()
        if status == "FAILED":
            raise RuntimeError(f"SO instance {instance_id} FAILED")
        time.sleep(poll_interval_s)
    raise TimeoutError(f"VNF {instance_id} not ACTIVE after {timeout_s}s")


# ── CLAMP / Policy Client ────────────────────────────────────────────────────
class CLAMPReal:
    """Pushes Drools operational policy to ONAP Policy PAP."""

    def __init__(self):
        self.auth    = HTTPBasicAuth(POLICY_USER, POLICY_PASS)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(HEADERS)
        self.session.verify = False

    def health(self) -> bool:
        try:
            r = self.session.get(
                f"{POLICY_BASE}/policy/pap/v1/healthcheck",
                timeout=REQUESTS_TIMEOUT
            )
            return r.status_code == 200
        except Exception:
            return False

    def push_policy(self, tier: int, attack_type: str,
                    device_id: str, confidence: float) -> bool:
        """
        Deploy operational policy to PDP group via Policy PAP.
        """
        policy_id   = f"pad-policy-tier{tier}-{device_id}"
        policy_body = _build_policy_body(
            policy_id, tier, attack_type, device_id, confidence
        )
        # 1. Create policy type instance
        create_url  = f"{POLICY_BASE}/policy/api/v1/policytypes/onap.policies.controlloop.operational.drools/versions/1.0.0/policies"
        try:
            r = self.session.post(create_url, json=policy_body,
                                  timeout=REQUESTS_TIMEOUT)
            if r.status_code not in (200, 201):
                logger.warning(f"[CLAMP] create policy HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"[CLAMP] create policy error: {e}")
            return False

        # 2. Deploy to default PDP group
        deploy_url  = f"{POLICY_BASE}/policy/pap/v1/pdps/policies"
        deploy_body = {
            "policies": [{"policy-id": policy_id, "policy-version": "1.0.0"}]
        }
        try:
            r = self.session.post(deploy_url, json=deploy_body,
                                  timeout=REQUESTS_TIMEOUT)
            ok = r.status_code in (200, 202)
            logger.info(f"[CLAMP] deploy policy {policy_id}: HTTP {r.status_code}")
            return ok
        except Exception as e:
            logger.error(f"[CLAMP] deploy policy error: {e}")
            return False

    def revoke_policy(self, tier: int, device_id: str) -> bool:
        policy_id  = f"pad-policy-tier{tier}-{device_id}"
        url        = (f"{POLICY_BASE}/policy/pap/v1/pdps/policies"
                      f"/{policy_id}/versions/1.0.0")
        try:
            r = self.session.delete(url, timeout=REQUESTS_TIMEOUT)
            logger.info(f"[CLAMP] revoke {policy_id}: HTTP {r.status_code}")
            return r.status_code in (200, 204)
        except Exception as e:
            logger.error(f"[CLAMP] revoke error: {e}")
            return False


# ── OVS / SFC ────────────────────────────────────────────────────────────────
class OVSSFCReal:
    """
    Installs / removes OpenFlow steering rules via ovs-ofctl.
    Runs subprocess locally (requires ovs-ofctl in PATH, or via SSH to Mininet host).

    If SSH_HOST is set → runs commands remotely:
      SSH_HOST  : IP of Mininet/K8s node
      SSH_USER  : default 'ubuntu'
    """

    def __init__(self):
        self.ssh_host = os.environ.get("OVS_SSH_HOST")
        self.ssh_user = os.environ.get("OVS_SSH_USER", "ubuntu")
        self._installed_rules: dict = {}   # device_id → cookie

    def _run(self, cmd: str) -> tuple[int, str]:
        if self.ssh_host:
            full = f"ssh {self.ssh_user}@{self.ssh_host} '{cmd}'"
        else:
            full = cmd
        logger.info(f"[OVS] {full}")
        result = subprocess.run(full, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"[OVS] stderr: {result.stderr.strip()}")
        return result.returncode, result.stdout.strip()

    def install(self, bridge: str, src_ip: str,
                vnf_port: int, tier: int, device_id: str,
                cookie: int = 0xADD0) -> bool:
        """
        Install OpenFlow rule: match src_ip → output to vnf_port.
        Priority = 200 + tier (higher tier = higher priority).
        """
        priority = 200 + tier
        rule     = (f"cookie={cookie:#x},priority={priority},"
                    f"ip,nw_src={src_ip},"
                    f"actions=output:{vnf_port}")
        rc, _    = self._run(f"ovs-ofctl add-flow {bridge} '{rule}'")
        if rc == 0:
            self._installed_rules[device_id] = (bridge, cookie)
            logger.info(f"[OVS] rule installed: {src_ip} → port {vnf_port} (T{tier})")
        return rc == 0

    def remove(self, device_id: str) -> bool:
        if device_id not in self._installed_rules:
            return True
        bridge, cookie = self._installed_rules.pop(device_id)
        rc, _  = self._run(
            f"ovs-ofctl del-flows {bridge} 'cookie={cookie:#x}/-1'"
        )
        logger.info(f"[OVS] rule removed for {device_id}")
        return rc == 0

    def dump_flows(self, bridge: str) -> str:
        _, out = self._run(f"ovs-ofctl dump-flows {bridge}")
        return out


# ── DMaaP helpers ────────────────────────────────────────────────────────────
def publish_to_dmaap(payload: dict) -> bool:
    """Publish AIOutputPayload to DMaaP topic (used by CLAMP trigger)."""
    url  = f"{DMAAP_BASE}/events/{DMAAP_TOPIC}"
    try:
        r = requests.post(url, json=[payload],
                          headers={"Content-Type": "application/json"},
                          timeout=REQUESTS_TIMEOUT)
        ok = r.status_code in (200, 207)
        logger.info(f"[DMaaP] publish: HTTP {r.status_code}")
        return ok
    except Exception as e:
        logger.error(f"[DMaaP] publish error: {e}")
        return False


# ── Request body builders ────────────────────────────────────────────────────
def _build_so_request(vnf_profile: str, device_id: str) -> dict:
    """Build ONAP SO v7 serviceInstantiation request body from VNF profile name."""
    _vnf_map = {
        "vnfd-ratelimiter-v1": {
            "modelName":    "pad-onap-ratelimiter",
            "modelVersion": "1.0.0",
            "modelType":    "service",
        },
        "vnfd-scrubber-v1": {
            "modelName":    "pad-onap-scrubber",
            "modelVersion": "1.0.0",
            "modelType":    "service",
        },
        "vnfd-blackhole-v1": {
            "modelName":    "pad-onap-blackhole",
            "modelVersion": "1.0.0",
            "modelType":    "service",
        },
    }
    model = _vnf_map.get(vnf_profile, {
        "modelName": vnf_profile, "modelVersion": "1.0.0", "modelType": "service"
    })
    return {
        "requestDetails": {
            "subscriberInfo": {
                "globalSubscriberId": GLOBAL_CUSTOMER_ID,
            },
            "requestInfo": {
                "instanceName":    f"{vnf_profile}-{device_id}-{int(time.time())}",
                "source":          "pad-onap-pipeline",
                "suppressRollback": False,
                "requestorId":     "pad-onap",
            },
            "modelInfo": {
                "modelType":              model["modelType"],
                "modelName":              model["modelName"],
                "modelVersion":           model["modelVersion"],
                "modelVersionId":         SERVICE_MODEL_UUID,
            },
            "requestParameters": {
                "subscriptionServiceType": SUBSCRIPTION_TYPE,
                "aLaCarte":                True,
                "userParams": [
                    {"name": "device_id", "value": device_id},
                    {"name": "vnf_profile", "value": vnf_profile},
                ],
            },
            "cloudConfiguration": {
                "lcpCloudRegionId": "RegionOne",
                "tenantId":         "pad-onap-tenant",
            },
        }
    }


def _build_policy_body(policy_id: str, tier: int,
                       attack_type: str, device_id: str,
                       confidence: float) -> dict:
    """Build ONAP Policy API body for Drools operational policy."""
    return {
        "tosca_definitions_version": "tosca_simple_yaml_1_1_0",
        "topology_template": {
            "policies": [{
                policy_id: {
                    "type": "onap.policies.controlloop.operational.drools",
                    "version": "1.0.0",
                    "metadata": {"policy-id": policy_id},
                    "properties": {
                        "controllerName": "pad-onap-controller",
                        "controlLoop": {
                            "version": "2.0.0",
                            "controlLoopName": f"PAD-ONAP-T{tier}-{device_id}",
                            "trigger_policy": f"pad-policy-tier{tier}",
                            "timeout": 60,
                            "abatement": True,
                        },
                        "policies": [{
                            "id":           f"pad-policy-tier{tier}",
                            "name":         f"PAD Tier {tier} Response",
                            "description":  f"Activate T{tier} VNF for {attack_type}",
                            "actor":        "SO",
                            "operation":    "VF Module Create",
                            "target": {
                                "type":       "VNF",
                                "resourceID": f"vnfd-{'ratelimiter' if tier<=2 else 'scrubber'}-v1",
                            },
                            "retries":  1,
                            "timeout":  90,
                            "success":  "final_success",
                            "failure":  "final_failure",
                            "userParams": {
                                "device_id":    device_id,
                                "attack_type":  attack_type,
                                "confidence":   confidence,
                                "tier":         tier,
                            },
                        }],
                    }
                }
            }]
        }
    }

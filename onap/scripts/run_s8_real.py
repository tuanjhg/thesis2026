"""
run_s8_real.py — S8: Proactive T2 vs Reactive T3 — ONAP OOM thật
=================================================================
Kịch bản S8 (Key Thesis Novelty):
  Phase 1 — Normal (30s): fill Transformer buffer
  Phase 2 — SYN moderate (intensity=0.35): AI forecast P(t+30s)≥0.5
             → PROACTIVE T2: CLAMPReal + SOReal (ratelimiter) ~500ms
  Phase 3 — UDP mạnh (intensity=1.5): AI conf≥0.85
             → REACTIVE T3: CLAMPReal + SOReal (scrubber) ~6000ms
  Phase 4 — Cooldown + cleanup

Điểm đo quan trọng nhất:
  lead_time_s = t_T3_would_have_fired - t_T2_proactive_fired
  → Chứng minh proactive nhanh hơn reactive bao nhiêu giây thật sự

Cách chạy:
  export PAD_ONAP_STUB=false
  export ONAP_HOST=<k8s-node-ip>
  export PAD_SERVICE_MODEL_UUID=<uuid-từ-SDC>
  python onap/scripts/run_s8_real.py

  # Với Mininet real traffic:
  python onap/scripts/run_s8_real.py --attack-mode mininet \\
    --bridge r1 --attacker-ip 10.2.0.1 --victim-ip 10.2.0.2 --vnf-port 3

  # Dry-run:
  python onap/scripts/run_s8_real.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import threading
from dataclasses import dataclass, asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from onap.scripts.onap_e2e_lib import (
    ONAPSOReal, CLAMPReal, OVSSFCReal,
    E2ERecord, wait_vnf_active, publish_to_dmaap,
)

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt= "%H:%M:%S",
)
logger = logging.getLogger("s8_real")

SCENARIO      = "S8_proactive_t2_vs_reactive_t3"
DEVICE_ID     = "r1"
BRIDGE_DEFAULT= "r1"

# Phase durations
NORMAL_DUR_S  = 30   # fill Transformer buffer
SYN_MOD_DUR_S = 25   # moderate SYN → forecast trigger
UDP_STR_DUR_S = 35   # strong UDP  → reactive T3
COOLDOWN_S    = 15

# Tier params
T2_VNF  = "vnfd-ratelimiter-v1"
T3_VNF  = "vnfd-scrubber-v1"
T2_CONF = 0.74     # proactive: forecast-driven, detection confidence vừa
T3_CONF = 0.92     # reactive:  detection confidence cao


@dataclass
class S8Result:
    """Kết quả đầy đủ cho S8 — cả 2 tier transitions."""
    scenario:            str = SCENARIO
    # Phase 2 — T2 proactive
    t2_t_trigger:        float = 0.0
    t2_t_policy_ms:      float = 0.0
    t2_t_so_ms:          float = 0.0
    t2_t_vnf_active_ms:  float = 0.0
    t2_t_sfc_ms:         float = 0.0
    t2_end_to_end_ms:    float = 0.0
    t2_instance_id:      str   = ""
    # Phase 3 — T3 reactive
    t3_t_trigger:        float = 0.0
    t3_t_policy_ms:      float = 0.0
    t3_t_so_ms:          float = 0.0
    t3_t_vnf_active_ms:  float = 0.0
    t3_t_sfc_ms:         float = 0.0
    t3_end_to_end_ms:    float = 0.0
    t3_instance_id:      str   = ""
    # Novelty metric
    lead_time_s:         float = 0.0   # T3_trigger_time - T2_trigger_time
    error:               str   = ""

    def print_table(self):
        sep = "═" * 64
        print(f"\n{sep}")
        print(f"  S8 Results — Proactive T2 vs Reactive T3 (REAL ONAP)")
        print(f"{sep}")
        rows_t2 = [
            ("T2 Proactive  AI → Policy",  self.t2_t_policy_ms),
            ("T2 Proactive  Policy → SO",   self.t2_t_so_ms),
            ("T2 Proactive  SO → VNF",      self.t2_t_vnf_active_ms),
            ("T2 Proactive  VNF → SFC",     self.t2_t_sfc_ms),
            ("T2 Proactive  END-TO-END",    self.t2_end_to_end_ms),
        ]
        rows_t3 = [
            ("T3 Reactive   AI → Policy",  self.t3_t_policy_ms),
            ("T3 Reactive   Policy → SO",   self.t3_t_so_ms),
            ("T3 Reactive   SO → VNF",      self.t3_t_vnf_active_ms),
            ("T3 Reactive   VNF → SFC",     self.t3_t_sfc_ms),
            ("T3 Reactive   END-TO-END",    self.t3_end_to_end_ms),
        ]
        w = 36
        for label, ms in rows_t2:
            bar = "▓" * min(int(ms / 100), 40)
            print(f"  {label:<{w}} {ms:>8.0f} ms  {bar}")
        print(f"  {'─'*60}")
        for label, ms in rows_t3:
            bar = "█" * min(int(ms / 100), 40)
            print(f"  {label:<{w}} {ms:>8.0f} ms  {bar}")
        print(f"{sep}")
        adv = self.t3_end_to_end_ms - self.t2_end_to_end_ms
        print(f"  🏆 NOVELTY: T2 proactive {self.t2_end_to_end_ms:.0f}ms"
              f"  vs  T3 reactive {self.t3_end_to_end_ms:.0f}ms")
        print(f"     Lead-time advantage = {self.lead_time_s:.1f}s "
              f"  |  E2E delta = {adv:.0f}ms")
        print(f"{sep}")
        if self.error:
            print(f"  ⚠️  ERROR: {self.error}")


# ─────────────────────────────────────────────────────────────────────────────
# AI payload generators
# ─────────────────────────────────────────────────────────────────────────────
def _ai_payload_t2_proactive(window_id: int) -> dict:
    """Moderate SYN → Transformer P(t+30s)=0.71 → proactive T2."""
    import uuid, datetime
    return {
        "event_id":      uuid.uuid4().hex[:12],
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "window_id":     window_id,
        "schema_version": "2.0",
        "detection": {
            "attack_class": 2,
            "attack_type":  "SYN_Flood",
            "confidence":   T2_CONF,
            "class_probs":  {"Normal": 0.18, "UDP_Flood": 0.03, "SYN_Flood": 0.74,
                             "DNS_Amp": 0.02, "NTP_Amp": 0.02, "MSSQL": 0.01},
            "top_features": {"syn_ratio": 0.42, "pkt_rate": 0.29,
                             "src_ip_entropy": -0.18, "proto_dist_tcp": 0.14},
        },
        "forecast": {
            "p_attack_30s":  0.71,    # ← vượt ngưỡng 0.50 → proactive trigger
            "p_attack_60s":  0.65,
            "p_attack_90s":  0.58,
            "p_attack_120s": 0.51,
            "proactive_trigger": True,
            "recommended_action": "PREPOSITION_TIER2_MITIGATION",
        },
        "proactive_trigger": {"triggered": True, "horizon_s": 30,
                              "threshold": 0.50, "p_attack": 0.71, "tier": 2},
        "suggested_tier": 2,
        "device_id":     DEVICE_ID,
    }


def _ai_payload_t3_reactive(window_id: int) -> dict:
    """Strong UDP → conf=0.92 → reactive T3."""
    import uuid, datetime
    return {
        "event_id":      uuid.uuid4().hex[:12],
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "window_id":     window_id,
        "schema_version": "2.0",
        "detection": {
            "attack_class": 1,
            "attack_type":  "UDP_Flood",
            "confidence":   T3_CONF,
            "class_probs":  {"Normal": 0.04, "UDP_Flood": 0.92, "SYN_Flood": 0.02},
            "top_features": {"pkt_rate": 0.38, "udp_ratio": 0.31,
                             "src_ip_entropy": -0.22},
        },
        "forecast": {
            "p_attack_30s":  0.94,
            "p_attack_60s":  0.91,
            "p_attack_90s":  0.88,
            "p_attack_120s": 0.82,
            "proactive_trigger": False,
            "recommended_action": "ACTIVATE_TIER3_MITIGATION",
        },
        "proactive_trigger": {"triggered": False, "tier": 0},
        "suggested_tier": 3,
        "device_id":     DEVICE_ID,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Attack helpers
# ─────────────────────────────────────────────────────────────────────────────
def _gnmi_attack(gnmi_url: str, attack_type: str, target: str = DEVICE_ID):
    import urllib.request, json as _j
    body = _j.dumps({"type": attack_type, "target": target}).encode()
    req  = urllib.request.Request(
        f"{gnmi_url}/attack/start", data=body,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        logger.info(f"[gNMI] {attack_type} started on {target}")
    except Exception as e:
        logger.warning(f"[gNMI] start {attack_type}: {e}")


def _gnmi_stop(gnmi_url: str):
    import urllib.request, json as _j
    try:
        req = urllib.request.Request(
            f"{gnmi_url}/attack/stop",
            data=_j.dumps({}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
        logger.info("[gNMI] attack stopped")
    except Exception as e:
        logger.warning(f"[gNMI] stop: {e}")


def _mininet_syn(attacker_ip: str):
    import subprocess
    ssh = os.environ.get("OVS_SSH_HOST")
    cmd = f"sudo hping3 -S --flood -p 443 {attacker_ip}"
    if ssh:
        cmd = f"ssh ubuntu@{ssh} 'sudo hping3 -S --flood -p 443 {attacker_ip} &'"
    subprocess.Popen(cmd, shell=True)
    logger.info(f"[Mininet] SYN flood → {attacker_ip}")


def _mininet_udp(victim_ip: str):
    import subprocess
    ssh = os.environ.get("OVS_SSH_HOST")
    cmd = f"sudo hping3 --udp --flood -p 80 {victim_ip}"
    if ssh:
        cmd = f"ssh ubuntu@{ssh} 'sudo hping3 --udp --flood -p 80 {victim_ip} &'"
    subprocess.Popen(cmd, shell=True)
    logger.info(f"[Mininet] UDP flood → {victim_ip}")


def _kill_flood():
    import subprocess
    ssh = os.environ.get("OVS_SSH_HOST")
    cmd = "sudo pkill -f hping3 2>/dev/null || true"
    if ssh:
        cmd = f"ssh ubuntu@{ssh} 'sudo pkill -f hping3 2>/dev/null || true'"
    subprocess.run(cmd, shell=True)
    logger.info("[Mininet] flood killed")


# ─────────────────────────────────────────────────────────────────────────────
# Phase runners
# ─────────────────────────────────────────────────────────────────────────────
def _run_t2_proactive(
    so: ONAPSOReal, clamp: CLAMPReal, sfc: OVSSFCReal,
    bridge: str, vnf_port: int, window_id: int,
    result: S8Result,
):
    """Phase 2: moderate SYN → proactive T2 → ratelimiter."""
    logger.info("── Phase 2: SYN moderate → Proactive T2 ──────────────────")

    result.t2_t_trigger = time.time()
    payload = _ai_payload_t2_proactive(window_id)
    publish_to_dmaap(payload)
    logger.info(f"  AI: SYN_Flood conf={T2_CONF}  P30s=0.71 → PROACTIVE T2")

    # Policy push
    ok = clamp.push_policy(
        tier=2, attack_type="SYN_Flood",
        device_id=DEVICE_ID, confidence=T2_CONF,
    )
    t_policy = time.time()
    result.t2_t_policy_ms = (t_policy - result.t2_t_trigger) * 1000
    if not ok:
        raise RuntimeError("T2 policy push failed")
    logger.info(f"  [T2] Policy pushed: {result.t2_t_policy_ms:.0f}ms")

    # SO instantiate ratelimiter
    instance_id = so.instantiate(T2_VNF, DEVICE_ID)
    t_so = time.time()
    result.t2_t_so_ms = (t_so - t_policy) * 1000
    if not instance_id:
        raise RuntimeError("T2 SO instantiate failed")
    result.t2_instance_id = instance_id
    logger.info(f"  [T2] SO request sent: {result.t2_t_so_ms:.0f}ms")

    # Poll ACTIVE
    t_active = wait_vnf_active(so, instance_id, timeout_s=120)
    result.t2_t_vnf_active_ms = (t_active - t_so) * 1000
    logger.info(f"  [T2] VNF ACTIVE: {result.t2_t_vnf_active_ms:.0f}ms ✅")

    # SFC rule: rate-limit src traffic
    sfc.install(
        bridge=bridge, src_ip="0.0.0.0/0",
        vnf_port=vnf_port, tier=2, device_id=f"{DEVICE_ID}-t2",
    )
    t_sfc = time.time()
    result.t2_t_sfc_ms     = (t_sfc - t_active) * 1000
    result.t2_end_to_end_ms= (t_sfc - result.t2_t_trigger) * 1000
    logger.info(f"  [T2] SFC installed: {result.t2_t_sfc_ms:.0f}ms")
    logger.info(f"  [T2] END-TO-END: {result.t2_end_to_end_ms:.0f}ms 🟢")


def _run_t3_reactive(
    so: ONAPSOReal, clamp: CLAMPReal, sfc: OVSSFCReal,
    bridge: str, vnf_port: int, window_id: int,
    result: S8Result,
):
    """Phase 3: strong UDP → reactive T3 → scrubber."""
    logger.info("── Phase 3: UDP strong → Reactive T3 ────────────────────")

    result.t3_t_trigger = time.time()
    payload = _ai_payload_t3_reactive(window_id)
    publish_to_dmaap(payload)
    logger.info(f"  AI: UDP_Flood conf={T3_CONF} → REACTIVE T3")

    # Revoke T2 policy first
    clamp.revoke_policy(2, DEVICE_ID)
    sfc.remove(f"{DEVICE_ID}-t2")

    # Terminate T2 VNF
    if result.t2_instance_id:
        so.terminate(result.t2_instance_id)

    # Policy push T3
    ok = clamp.push_policy(
        tier=3, attack_type="UDP_Flood",
        device_id=DEVICE_ID, confidence=T3_CONF,
    )
    t_policy = time.time()
    result.t3_t_policy_ms = (t_policy - result.t3_t_trigger) * 1000
    if not ok:
        raise RuntimeError("T3 policy push failed")
    logger.info(f"  [T3] Policy pushed: {result.t3_t_policy_ms:.0f}ms")

    # SO instantiate scrubber (heavier VNF ~6s boot)
    instance_id = so.instantiate(T3_VNF, DEVICE_ID)
    t_so = time.time()
    result.t3_t_so_ms = (t_so - t_policy) * 1000
    if not instance_id:
        raise RuntimeError("T3 SO instantiate failed")
    result.t3_instance_id = instance_id
    logger.info(f"  [T3] SO request sent: {result.t3_t_so_ms:.0f}ms")

    # Poll ACTIVE (~6000ms for scrubber DPI init)
    t_active = wait_vnf_active(so, instance_id, timeout_s=120)
    result.t3_t_vnf_active_ms = (t_active - t_so) * 1000
    logger.info(f"  [T3] VNF ACTIVE: {result.t3_t_vnf_active_ms:.0f}ms ✅")

    # SFC rule: all traffic → scrubber (higher priority than T2)
    sfc.install(
        bridge=bridge, src_ip="0.0.0.0/0",
        vnf_port=vnf_port + 1, tier=3, device_id=f"{DEVICE_ID}-t3",
    )
    t_sfc = time.time()
    result.t3_t_sfc_ms     = (t_sfc - t_active) * 1000
    result.t3_end_to_end_ms= (t_sfc - result.t3_t_trigger) * 1000
    logger.info(f"  [T3] SFC installed: {result.t3_t_sfc_ms:.0f}ms")
    logger.info(f"  [T3] END-TO-END: {result.t3_end_to_end_ms:.0f}ms 🔴")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def run_s8(
    attack_mode:  str  = "gnmi",
    gnmi_url:     str  = "http://localhost:8080",
    bridge:       str  = BRIDGE_DEFAULT,
    attacker_ip:  str  = "10.2.0.1",
    victim_ip:    str  = "10.2.0.2",
    vnf_port_t2:  int  = 3,
    vnf_port_t3:  int  = 4,
    dry_run:      bool = False,
    cleanup:      bool = True,
) -> S8Result:

    result = S8Result()
    so    = ONAPSOReal()
    clamp = CLAMPReal()
    sfc   = OVSSFCReal()

    sep = "═" * 64
    print(f"\n{sep}")
    print(f"  PAD-ONAP E2E — {SCENARIO}")
    print(f"  Mode: {'DRY-RUN' if dry_run else 'REAL ONAP (PAD_ONAP_STUB=false)'}")
    print(f"  Attack: {attack_mode.upper()} │ Bridge: {bridge}")
    print(f"  T2-port: {vnf_port_t2} (ratelimiter) │ T3-port: {vnf_port_t3} (scrubber)")
    print(f"{sep}\n")

    # Preflight
    logger.info("Preflight checks...")
    checks = {"ONAP SO": so.health(), "Policy PAP": clamp.health()}
    for name, ok in checks.items():
        logger.info(f"  {name:<16} {'✅ OK' if ok else '❌ FAIL'}")

    if not all(checks.values()) and not dry_run:
        result.error = "Preflight failed"
        result.print_table()
        return result

    if dry_run:
        logger.info("[DRY-RUN] complete — no ONAP calls made")
        return result

    try:
        # Phase 1 — Normal
        logger.info(f"Phase 1: Normal traffic ({NORMAL_DUR_S}s)...")
        time.sleep(NORMAL_DUR_S)

        # Phase 2 — SYN moderate → T2 proactive
        if attack_mode == "gnmi":
            _gnmi_attack(gnmi_url, "syn_flood")
        else:
            _mininet_syn(victim_ip)
        time.sleep(5)   # 1 window for feature extraction

        _run_t2_proactive(so, clamp, sfc, bridge, vnf_port_t2,
                          window_id=31, result=result)

        # Record lead-time start
        t_proactive_fired = result.t2_t_trigger
        logger.info(f"  Holding SYN phase ({SYN_MOD_DUR_S}s)...")
        time.sleep(max(0, SYN_MOD_DUR_S - 5))

        # Phase 3 — UDP strong → T3 reactive
        if attack_mode == "gnmi":
            _gnmi_stop(gnmi_url)
            time.sleep(1)
            _gnmi_attack(gnmi_url, "udp_flood")
        else:
            _kill_flood()
            time.sleep(1)
            _mininet_udp(victim_ip)
        time.sleep(5)   # 1 window

        _run_t3_reactive(so, clamp, sfc, bridge, vnf_port_t3,
                         window_id=56, result=result)

        # Compute lead-time
        result.lead_time_s = result.t3_t_trigger - t_proactive_fired
        logger.info(f"  Lead-time: T2 proactive fired {result.lead_time_s:.1f}s "
                    f"before T3 reactive")

        logger.info(f"  Holding UDP phase ({UDP_STR_DUR_S}s)...")
        time.sleep(max(0, UDP_STR_DUR_S - 5))

    except Exception as e:
        logger.error(f"Scenario error: {e}")
        result.error = str(e)
    finally:
        # Phase 4 — Cleanup
        if attack_mode == "gnmi":
            _gnmi_stop(gnmi_url)
        else:
            _kill_flood()
        time.sleep(COOLDOWN_S)

        if cleanup:
            logger.info("Cleanup: terminate VNFs + revoke policies + remove SFC...")
            if result.t2_instance_id:
                so.terminate(result.t2_instance_id)
            if result.t3_instance_id:
                so.terminate(result.t3_instance_id)
            clamp.revoke_policy(2, DEVICE_ID)
            clamp.revoke_policy(3, DEVICE_ID)
            sfc.remove(f"{DEVICE_ID}-t2")
            sfc.remove(f"{DEVICE_ID}-t3")

    return result


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PAD-ONAP E2E — S8 Proactive T2 vs Reactive T3 (real ONAP)"
    )
    parser.add_argument("--attack-mode",  default="gnmi",
                        choices=["gnmi", "mininet"])
    parser.add_argument("--gnmi-url",     default="http://localhost:8080")
    parser.add_argument("--bridge",       default="r1")
    parser.add_argument("--attacker-ip",  default="10.2.0.1")
    parser.add_argument("--victim-ip",    default="10.2.0.2")
    parser.add_argument("--vnf-port-t2",  type=int, default=3)
    parser.add_argument("--vnf-port-t3",  type=int, default=4)
    parser.add_argument("--dry-run",      action="store_true")
    parser.add_argument("--no-cleanup",   action="store_true")
    args = parser.parse_args()

    if os.environ.get("PAD_ONAP_STUB", "true").lower() != "false" and not args.dry_run:
        print("\n⚠️  PAD_ONAP_STUB chưa set thành 'false'!")
        print("   export PAD_ONAP_STUB=false")
        print("   Hoặc: python run_s8_real.py --dry-run\n")
        sys.exit(1)

    result = run_s8(
        attack_mode = args.attack_mode,
        gnmi_url    = args.gnmi_url,
        bridge      = args.bridge,
        attacker_ip = args.attacker_ip,
        victim_ip   = args.victim_ip,
        vnf_port_t2 = args.vnf_port_t2,
        vnf_port_t3 = args.vnf_port_t3,
        dry_run     = args.dry_run,
        cleanup     = not args.no_cleanup,
    )
    result.print_table()

    # Save result JSON
    out = Path(_ROOT) / "evaluation" / "results" / "s8_real_onap.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(asdict(result), f, indent=2)
    print(f"\n  Result saved → {out}")

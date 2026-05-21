"""
Dual-path publisher — sits at the end of M3 (after tier classification) and
emits the decision to BOTH the fast-path (Ryu) and the slow-path (CLAMP).

Usage in pipeline.s4_orchestration.orchestrator:

    from pipeline.s5_fastpath.dual_path_publisher import publish
    publish(src_ip="10.0.0.1", dst_ip="10.0.3.4",
            tier=3, attack_type="SYN")
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from pipeline.s5_fastpath import scenario_state

log = logging.getLogger("pad.fastpath.publisher")

RYU_URL = os.environ.get("PAD_RYU_URL", "http://127.0.0.1:8080")
CLAMP_URL = os.environ.get(
    "PAD_CLAMP_URL",
    "https://clamp.onap.svc.cluster.local:30258"
    "/restservices/clds/v2/loop/operation/PAD-ONAP-DDoS-ClosedLoop",
)
CLAMP_AUTH = (os.environ.get("PAD_CLAMP_USER", "admin"),
              os.environ.get("PAD_CLAMP_PASS", "password"))

_EXEC = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dual-path")


def _post_ryu(payload: dict) -> dict:
    t0 = time.time()
    try:
        r = requests.post(f"{RYU_URL}/pad/tier", json=payload, timeout=2.0)
        r.raise_for_status()
        latency_ms = int((time.time() - t0) * 1000)
        log.info("[fastpath] ryu OK in %d ms", latency_ms)
        return {"ok": True, "latency_ms": latency_ms, "resp": r.json()}
    except requests.RequestException as e:
        log.warning("[fastpath] ryu failed: %s", e)
        return {"ok": False, "latency_ms": int((time.time() - t0) * 1000),
                "error": str(e)}


def _post_clamp(payload: dict) -> dict:
    t0 = time.time()
    try:
        r = requests.post(
            CLAMP_URL,
            json={"tier": payload["tier"], "attack_type": payload["attack_type"],
                  "target": payload["dst_ip"]},
            auth=CLAMP_AUTH, verify=False, timeout=10.0)
        r.raise_for_status()
        latency_ms = int((time.time() - t0) * 1000)
        log.info("[slowpath] clamp OK in %d ms", latency_ms)
        return {"ok": True, "latency_ms": latency_ms}
    except requests.RequestException as e:
        log.warning("[slowpath] clamp failed: %s", e)
        return {"ok": False, "latency_ms": int((time.time() - t0) * 1000),
                "error": str(e)}


def publish(*, src_ip: str, dst_ip: str, tier: int, attack_type: str = "",
            redirect_to: str = "") -> dict[str, Any]:
    """Fire BOTH paths in parallel; return when both complete.

    Side-effect: writes scenario_state per-stage statuses so frontend
    animates M4 → fast/slow branches.
    """
    # Mark M4 starting
    scenario_state.mark_stage("M4_publisher", "active")
    scenario_state.mark_stage("fastpath", "active") if hasattr(
        scenario_state, "mark_stage") else None

    payload = {
        "src_ip": src_ip, "dst_ip": dst_ip, "tier": tier,
        "attack_type": attack_type, "redirect_to": redirect_to,
    }
    fut_fast = _EXEC.submit(_post_ryu, payload)
    fut_slow = _EXEC.submit(_post_clamp, payload)

    fast = fut_fast.result()
    slow = fut_slow.result()

    with scenario_state.update() as s:
        s["active_tier"] = tier
        s["pipeline"]["M4_publisher"]["status"] = "done"
        s["pipeline"]["M4_publisher"]["latency_ms"] = max(
            fast["latency_ms"], slow["latency_ms"])
        s["fastpath"] = {
            "status": "done" if fast["ok"] else "error",
            "rules_installed": 1 if fast["ok"] else 0,
            "last_action": fast.get("resp", {}).get("action", ""),
            "latency_ms": fast["latency_ms"],
        }
        s["slowpath"] = {
            "status": "active" if slow["ok"] else "error",
            "stage": "clamp_received" if slow["ok"] else "clamp_failed",
            "vnf_name": "",
            "vnf_pod": "",
            "latency_ms": slow["latency_ms"],
        }
    scenario_state.push_event(
        "tier_decision", tier=tier, src=src_ip, dst=dst_ip,
        fast_ms=fast["latency_ms"], slow_ms=slow["latency_ms"])
    return {"fastpath": fast, "slowpath": slow}

"""
Scenario state tracker — single source of truth for the testbed UI.
Atomic JSON file on /tmp/pad-onap/scenario_state.json; read by the frontend
backend, written by the pipeline orchestrator + Ryu app + scenario runner.

Schema follows systemdesign.md §14 (KPIs, mode, selected_node).
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

STATE_PATH = Path(os.environ.get(
    "PAD_SCENARIO_STATE", "/tmp/pad-onap/scenario_state.json"))
STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

_LOCK = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Mitigation tier nomenclature (per systemdesign.md §11)
# ─────────────────────────────────────────────────────────────────────────────
TIER_LABEL = {0: "T0", 1: "T1", 2: "T2", 3: "T3", 4: "T4"}
TIER_MEANING = {
    0: "Normal",
    1: "Suspicious",
    2: "Medium risk",
    3: "High risk / active attack",
    4: "Critical attack",
}

# Demo topology node IDs (systemdesign.md §7.2)
NODES = ("N1", "N2", "N3", "N4", "N5", "N6",
         "N7", "N8", "N9", "N10", "N11")

# ─────────────────────────────────────────────────────────────────────────────
# Default state
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_STATE: dict[str, Any] = {
    "scenario": "idle",
    "started_at": 0.0,

    # Operator-controlled (systemdesign.md §6, §12)
    "mode": "ai_assisted",         # ai_assisted | rule_only

    # High-level demo state
    "attacker_host": "",
    "victim_host": "",
    "attack_type": "",
    "active_tier": 0,              # 0..4 → display as T0..T4

    # KPI row (systemdesign.md §5)
    "kpis": {
        "traffic_rate_gbps": 0.0,
        "traffic_rate_delta_pct": 0,    # vs 5 min ago
        "traffic_trend": [],            # last 30 values for sparkline
        "attack_score": 0,              # 0..100
        "attack_score_label": "Low",    # Low | Medium | High | Critical
        "attack_trend": [],
        "forecast_risk": "Low",         # Low | Medium | High | Critical
        "forecast_horizon_s": 30,
        "forecast_direction": "stable",  # increasing | decreasing | stable
        "forecast_trend": [],
        "cnf_status": "Healthy",        # Healthy | Degraded | Failed
        "cnf_active": 0,
        "cnf_degraded": 0,
        "cnf_failed": 0,
        "cnf_desired": 1,
    },

    # Per-stage pipeline timing
    "pipeline": {
        "M1_collector":  {"status": "idle", "latency_ms": 0,
                           "throughput_pps": 0,
                           "label": "M1 · NetFlow/sFlow collector"},
        "M2_features":   {"status": "idle", "latency_ms": 0,
                           "features_per_sec": 0,
                           "label": "M2 · Kafka + Flink"},
        "M3_ai":         {"status": "idle", "latency_ms": 0,
                           "tier_out": 0, "confidence": 0.0,
                           "label": "M3 · XGBoost + Transformer/LSTM"},
        "M4_publisher":  {"status": "idle", "latency_ms": 0,
                           "label": "M4 · Dual-path publisher"},
    },

    # Per-topology-node runtime details (right panel content, §9)
    "node_details": {n: {"status": "idle", "metrics": {}} for n in NODES},

    # Operator selection for the right detail panel
    "selected_node": "",

    # Dual-path execution
    "fastpath": {
        "status": "idle", "rules_installed": 0,
        "last_action": "", "latency_ms": 0,
    },
    "slowpath": {
        "status": "idle", "stage": "idle", "vnf_name": "", "vnf_pod": "",
        "latency_ms": 0,
    },

    # Traffic counters per direction (used by topology edge animations)
    "traffic": {"inbound_pps": 0, "return_pps": 0, "mitigated_pps": 0},

    "metrics": {"attack_pps": 0, "drop_pps": 0, "victim_pps_in": 0},

    "history": [],
}


def _read() -> dict:
    if not STATE_PATH.exists():
        return _clone_default()
    try:
        with STATE_PATH.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except (json.JSONDecodeError, OSError):
        return _clone_default()


def _clone_default() -> dict:
    return json.loads(json.dumps(DEFAULT_STATE))


def _write(state: dict) -> None:
    tmp = STATE_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(state, fp, indent=2, sort_keys=True)
    tmp.replace(STATE_PATH)


@contextlib.contextmanager
def update():
    """Atomic read-modify-write helper.

        with scenario_state.update() as s:
            s["active_tier"] = 3
    """
    with _LOCK:
        state = _read()
        yield state
        state["updated_at"] = time.time()
        _write(state)


def get() -> dict:
    with _LOCK:
        return _read()


def reset(scenario: str = "idle", attacker: str = "", victim: str = "",
          attack_type: str = "", mode: str | None = None) -> dict:
    with _LOCK:
        state = _clone_default()
        if mode:
            state["mode"] = mode
        state.update({
            "scenario": scenario,
            "started_at": time.time(),
            "attacker_host": attacker,
            "victim_host": victim,
            "attack_type": attack_type,
            "history": [],
        })
        _write(state)
        return state


def push_event(kind: str, **payload) -> None:
    """Append an event to the history ring (kept short)."""
    with _LOCK:
        state = _read()
        state.setdefault("history", []).append({
            "ts": time.time(), "kind": kind, **payload,
        })
        state["history"] = state["history"][-200:]
        _write(state)


def mark_stage(stage: str, status: str, **extra) -> None:
    """Mark one pipeline stage with status + arbitrary fields."""
    with _LOCK:
        state = _read()
        state.setdefault("pipeline", {}).setdefault(stage, {})
        state["pipeline"][stage]["status"] = status
        state["pipeline"][stage].update(extra)
        state["updated_at"] = time.time()
        _write(state)


def update_node(node_id: str, status: str | None = None, **metrics) -> None:
    """Update one topology node's details (shown in the right detail panel)."""
    with _LOCK:
        state = _read()
        nd = state.setdefault("node_details", {}).setdefault(
            node_id, {"status": "idle", "metrics": {}})
        if status is not None:
            nd["status"] = status
        nd.setdefault("metrics", {}).update(metrics)
        state["updated_at"] = time.time()
        _write(state)


def update_kpis(**kpi) -> None:
    """Patch KPI fields. Append sparkline trends automatically (last 30)."""
    with _LOCK:
        state = _read()
        k = state.setdefault("kpis", {})
        for field, value in kpi.items():
            k[field] = value
        if "traffic_rate_gbps" in kpi:
            k.setdefault("traffic_trend", []).append(kpi["traffic_rate_gbps"])
            k["traffic_trend"] = k["traffic_trend"][-30:]
        if "attack_score" in kpi:
            k.setdefault("attack_trend", []).append(kpi["attack_score"])
            k["attack_trend"] = k["attack_trend"][-30:]
            score = kpi["attack_score"]
            k["attack_score_label"] = (
                "Critical" if score >= 90 else
                "High"     if score >= 70 else
                "Medium"   if score >= 40 else "Low")
        if "forecast_risk" in kpi:
            k.setdefault("forecast_trend", []).append({
                "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
            }.get(kpi["forecast_risk"], 0))
            k["forecast_trend"] = k["forecast_trend"][-30:]
        state["updated_at"] = time.time()
        _write(state)


def set_mode(mode: str) -> None:
    """Toggle AI-assisted ↔ rule-only."""
    if mode not in ("ai_assisted", "rule_only"):
        raise ValueError(f"unknown mode: {mode}")
    with _LOCK:
        state = _read()
        state["mode"] = mode
        state["updated_at"] = time.time()
        _write(state)


def select_node(node_id: str) -> None:
    """Set the node whose details show in the right panel."""
    with _LOCK:
        state = _read()
        state["selected_node"] = node_id
        state["updated_at"] = time.time()
        _write(state)

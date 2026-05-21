"""
FastAPI backend for the PAD-ONAP topology demo dashboard.
Implements the API surface described in systemdesign.md §16.

Endpoints
─────────
  GET   /api/topology              demo topology (11 nodes, 3 layers)
  GET   /api/state                 full scenario_state snapshot
  GET   /api/kpis                  KPI cards only
  GET   /api/events                event timeline
  GET   /api/node/{id}             one-node detail (right panel)
  GET   /api/flows                 Ryu installed flows
  GET   /api/vnfs                  kubectl probe (best-effort)
  GET   /api/scenarios             scenario catalog (cards)
  POST  /api/scenario/{id}         start S1..S8  |  stop  |  reset
  POST  /api/mode                  {"mode":"ai_assisted"|"rule_only"}
  POST  /api/node/select           {"id":"N6"}
  POST  /api/scenario/start-attack alias for the default attack scenario
  POST  /api/scenario/stop-attack  alias for stop
  POST  /api/scenario/enable-ai    set mode=ai_assisted
  POST  /api/scenario/compare-rule-only set mode=rule_only
  WS    /ws                        live push every 1s
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from pipeline.s5_fastpath import scenario_state
from frontend.scenarios import SCENARIOS, by_id, DEFAULT_ATTACK_ID

RYU_URL = os.environ.get("PAD_RYU_URL", "http://127.0.0.1:8080")
PROM_URL = os.environ.get("PAD_PROM_URL", "http://127.0.0.1:9190")
SCENARIO_RUNNER = os.environ.get(
    "PAD_SCENARIO_RUNNER",
    str(Path(__file__).resolve().parent.parent / "scripts" / "run_scenario.sh"))

FRONTEND_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="PAD-ONAP Topology Demo", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Demo topology (systemdesign.md §7.2) — 11 nodes, 3 layers
# ─────────────────────────────────────────────────────────────────────────────
LAYERS = [
    {"id": "L1", "label": "Network Layer",       "kind": "layer",
     "color": "#06B6D4"},
    {"id": "L2", "label": "Streaming & AI Layer", "kind": "layer",
     "color": "#7C3AED"},
    {"id": "L3", "label": "ONAP Closed Loop",    "kind": "layer",
     "color": "#059669"},
]

NODES = [
    {"id": "N1",  "parent": "L1", "label": "Users / Attackers",
     "type": "users",     "x":  120, "y":  120,
     "description": "Source of normal or attack traffic."},
    {"id": "N2",  "parent": "L1", "label": "Edge Router / Switch",
     "type": "router",    "x":  300, "y":  120,
     "description": "Ingress point. Exports gNMI/gRPC telemetry."},
    {"id": "N3",  "parent": "L1", "label": "Telemetry Collector",
     "type": "collector", "x":  480, "y":  120,
     "description": "Collects gNMI/gRPC samples; forwards to Kafka."},
    {"id": "N4",  "parent": "L2", "label": "Apache Kafka",
     "type": "kafka",     "x":  660, "y":  120,
     "description": "Buffers and distributes telemetry streams."},
    {"id": "N5",  "parent": "L2", "label": "Apache Flink",
     "type": "flink",     "x":  840, "y":  120,
     "description": "Sliding-window aggregation; emits feature vectors."},
    {"id": "N6",  "parent": "L2", "label": "AI Detection & Forecasting",
     "type": "ai",        "x": 1020, "y":  120,
     "description": "XGBoost + Transformer/LSTM. Score + forecast."},
    {"id": "N7",  "parent": "L3", "label": "ONAP DCAE",
     "type": "dcae",      "x": 1080, "y":  360,
     "description": "Ingests AI analytics events."},
    {"id": "N8",  "parent": "L3", "label": "Policy Framework",
     "type": "policy",    "x":  900, "y":  360,
     "description": "Drools rules → selects mitigation tier (T0..T4)."},
    {"id": "N9",  "parent": "L3", "label": "Service Orchestrator",
     "type": "so",        "x":  720, "y":  360,
     "description": "Coordinates CNF deployment / scaling."},
    {"id": "N10", "parent": "L3", "label": "CNF Scrubber",
     "type": "cnf",       "x":  540, "y":  360,
     "description": "Filters / rate-limits malicious traffic."},
    {"id": "N11", "parent": "L3", "label": "Protected Service",
     "type": "service",   "x":  360, "y":  360,
     "description": "Downstream service shielded by the CNF Scrubber."},
]

EDGES = [
    {"id": "e1",  "source": "N1",  "target": "N2",
     "type": "attack",      "label": "traffic"},
    {"id": "e2",  "source": "N2",  "target": "N3",
     "type": "telemetry",   "label": "gNMI/gRPC"},
    {"id": "e3",  "source": "N3",  "target": "N4",  "type": "telemetry"},
    {"id": "e4",  "source": "N4",  "target": "N5",  "type": "telemetry"},
    {"id": "e5",  "source": "N5",  "target": "N6",
     "type": "ai",          "label": "feature vector"},
    {"id": "e6",  "source": "N6",  "target": "N7",
     "type": "ai",          "label": "AI events"},
    {"id": "e7",  "source": "N7",  "target": "N8",  "type": "onap"},
    {"id": "e8",  "source": "N8",  "target": "N9",  "type": "onap"},
    {"id": "e9",  "source": "N9",  "target": "N10",
     "type": "mitigation",  "label": "deploy/scale"},
    {"id": "e10", "source": "N10", "target": "N11",
     "type": "mitigation",  "label": "protected"},
    {"id": "e11", "source": "N2",  "target": "N11",
     "type": "protected",   "label": "clean traffic"},
]


def topology_snapshot() -> dict:
    """Return the static demo topology with per-node status overlaid."""
    state = scenario_state.get()
    node_details = state.get("node_details", {})
    nodes_out = []
    for n in NODES:
        nd = node_details.get(n["id"], {})
        nodes_out.append({
            **n,
            "status":  nd.get("status", "idle"),
            "metrics": nd.get("metrics", {}),
        })
    edges_out = []
    for e in EDGES:
        st = _edge_status(e, state)
        edges_out.append({
            **e,
            "status": st,
            "pps":     _edge_throughput(e, state),
            "particles": _edge_particle_rate(e, state),
        })
    return {
        "layers": LAYERS, "nodes": nodes_out, "edges": edges_out,
        "narration": _narrate(state),
        "trace":     _build_trace(state),
    }


def _edge_status(edge: dict, state: dict) -> str:
    """Decide whether an edge is active/inactive/highlighted given state."""
    t = edge["type"]
    tier = state.get("active_tier", 0)
    mode = state.get("mode", "ai_assisted")
    inbound = state.get("traffic", {}).get("inbound_pps", 0)
    if t == "attack":
        return "active" if inbound > 0 else "idle"
    if t == "telemetry":
        return "active" if state.get("scenario", "idle") != "idle" else "idle"
    if t == "ai":
        return ("inactive" if mode == "rule_only"
                else "active" if tier > 0 else "idle")
    if t == "onap":
        return "active" if tier >= 2 else "idle"
    if t == "mitigation":
        return "active" if tier >= 2 else "idle"
    if t == "protected":
        return "active" if tier >= 2 else "idle"
    return "idle"


def _edge_throughput(edge: dict, state: dict) -> int:
    """Estimate pps flowing on the edge given pipeline state."""
    t = edge["type"]
    inbound   = state.get("traffic", {}).get("inbound_pps", 0)
    mitigated = state.get("traffic", {}).get("mitigated_pps", 0)
    return_p  = state.get("traffic", {}).get("return_pps", 0)
    tier = state.get("active_tier", 0)
    if t == "attack":
        return inbound
    if t == "telemetry":
        # Telemetry sampling: 1 sample/64 packets (sFlow), or 1 sample/s for gNMI
        if edge["source"] == "N2":
            return min(inbound, 1000)              # N2→N3 sampled
        return int(inbound / 64) if inbound else 0  # downstream of sampler
    if t == "ai":
        # 1 feature vector per sliding window per second
        return 1 if state.get("scenario", "idle") != "idle" else 0
    if t == "onap":
        # 1 event per tier transition
        return 1 if tier > 0 else 0
    if t == "mitigation":
        if edge["target"] == "N11":
            return inbound - mitigated  # clean reaches service
        return tier  # control plane: deploy/scale commands
    if t == "protected":
        return inbound - mitigated  # parallel clean traffic shortcut
    return 0


def _edge_particle_rate(edge: dict, state: dict) -> float:
    """Per-second particle spawn rate for the canvas animation (0..6)."""
    pps = _edge_throughput(edge, state)
    if pps <= 0:
        return 0
    t = edge["type"]
    # Map ranges roughly: log-scale → particles/s
    if t == "attack":
        # 1k pps → ~3 particles, 50k pps → ~6
        return min(6.0, 1.5 + 0.0001 * pps)
    if t == "telemetry":
        return min(4.0, 1.0 + 0.005 * pps)
    if t == "ai":
        return 1.5
    if t == "onap":
        return 1.0
    if t == "mitigation":
        return min(5.0, 1.5 + 0.0001 * (pps + 1))
    if t == "protected":
        return min(4.0, 1.0 + 0.0001 * pps)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Step narration — explains what the pipeline is doing right now
# (systemdesign.md §10/§13 — supports the demo narrator role)
# ─────────────────────────────────────────────────────────────────────────────
def _narrate(state: dict) -> dict:
    """Build a step explainer card. Returns {step, total, title, body, focus_node}."""
    scenario = state.get("scenario", "idle")
    tier = state.get("active_tier", 0)
    mode = state.get("mode", "ai_assisted")
    fp_status = state.get("fastpath", {}).get("status", "idle")
    sp_stage  = state.get("slowpath", {}).get("stage", "idle")
    inbound   = state.get("traffic", {}).get("inbound_pps", 0)
    score = state.get("kpis", {}).get("attack_score", 0)
    conf = (state.get("pipeline", {}).get("M3_ai", {}).get("confidence", 0))
    fr = state.get("kpis", {}).get("forecast_risk", "Low")

    if scenario == "idle":
        return {"step": 0, "total": 8, "title": "System idle",
                "body": "All nodes healthy. Pick a scenario to start.",
                "focus_node": ""}
    if inbound == 0:
        return {"step": 1, "total": 8, "title": "Scenario armed",
                "body": f"Scenario {scenario} loaded; awaiting first packets.",
                "focus_node": "N1"}
    if state.get("pipeline", {}).get("M1_collector", {}).get("status") != "done" \
            and tier == 0 and score < 10:
        return {"step": 2, "total": 8,
                "title": "Step 2 — Attack ingress",
                "body": (f"N1 → N2: {inbound:,} pps entering. "
                         f"Edge router exports gNMI/gRPC telemetry."),
                "focus_node": "N2"}
    if tier == 0 and score < 30:
        return {"step": 3, "total": 8,
                "title": "Step 3 — Telemetry → Kafka → Flink",
                "body": ("N3 collector samples flows, N4 Kafka buffers, "
                         "N5 Flink computes 22-feature sliding window."),
                "focus_node": "N5"}
    if mode == "ai_assisted" and tier == 0:
        return {"step": 4, "total": 8,
                "title": "Step 4 — AI inference",
                "body": (f"N6 XGBoost + Transformer/LSTM. "
                         f"Score {score}/100, conf {conf:.2f}, "
                         f"forecast risk {fr}."),
                "focus_node": "N6"}
    if tier >= 1 and sp_stage in ("idle", "clamp_received", "policy_eval"):
        return {"step": 5, "total": 8,
                "title": "Step 5 — Policy decision",
                "body": (f"N7 DCAE ingests AI event → N8 Policy Drools "
                         f"selects tier T{tier} based on score+forecast."),
                "focus_node": "N8"}
    if tier >= 2 and fp_status in ("active", "done") \
            and sp_stage not in ("vnf_active",):
        return {"step": 6, "total": 8,
                "title": "Step 6 — Fast-path Ryu rule (~8 ms)",
                "body": (f"Ryu installs Flow-Mod on OVS switches. "
                         f"Attack already dropped/rate-limited at dataplane."),
                "focus_node": "N10"}
    if tier >= 2 and sp_stage == "so_instantiate":
        return {"step": 7, "total": 8,
                "title": "Step 7 — SO instantiates CNF",
                "body": ("N9 Service Orchestrator runs kubectl create. "
                         "Waiting for VNF pod to become Ready (~2s)."),
                "focus_node": "N9"}
    if tier >= 2 and sp_stage == "vnf_active":
        return {"step": 8, "total": 8,
                "title": "Step 8 — Closed loop complete",
                "body": ("N10 CNF Scrubber Active. N11 Protected Service "
                         "receives only clean traffic. Loop holds."),
                "focus_node": "N11"}
    return {"step": 0, "total": 8, "title": "—", "body": "", "focus_node": ""}


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline trace strip — waterfall timing for the latest "wave"
# ─────────────────────────────────────────────────────────────────────────────
TRACE_STAGES = [
    ("ingress",      "Ingress",        0),
    ("M1_collector", "M1 Collector",   0),
    ("M2_features",  "M2 Features",    0),
    ("M3_ai",        "M3 AI",          0),
    ("M4_publisher", "M4 Publisher",   0),
    ("fastpath",     "Ryu (fast)",     0),
    ("slowpath",     "ONAP (slow)",    0),
]


def _build_trace(state: dict) -> list[dict]:
    """Return [{stage, label, t_start_ms, duration_ms, status}] for the
    latest pipeline wave so the frontend can draw a waterfall."""
    p = state.get("pipeline", {})
    fp = state.get("fastpath", {})
    sp = state.get("slowpath", {})

    cursor = 0
    out = []
    # ingress is the t=0 marker
    out.append({"stage": "ingress", "label": "Ingress",
                "t_start_ms": 0, "duration_ms": 0, "status":
                "active" if state.get("traffic", {}).get("inbound_pps", 0) > 0
                else "idle"})
    for key, label, _ in TRACE_STAGES[1:5]:
        s = p.get(key, {})
        dur = s.get("latency_ms", 0)
        out.append({"stage": key, "label": label,
                    "t_start_ms": cursor, "duration_ms": dur,
                    "status": s.get("status", "idle")})
        cursor += dur
    # Fast/slow branches: both start at cursor (parallel)
    out.append({"stage": "fastpath", "label": "Ryu (fast)",
                "t_start_ms": cursor,
                "duration_ms": fp.get("latency_ms", 0),
                "status": fp.get("status", "idle")})
    out.append({"stage": "slowpath", "label": "ONAP (slow)",
                "t_start_ms": cursor,
                "duration_ms": sp.get("latency_ms", 0),
                "status": sp.get("status", "idle")})
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
async def _get_json(url: str, timeout: float = 2.0) -> Any:
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        return {"error": str(e)}


def _kubectl(*args: str) -> str:
    if not shutil.which("kubectl"):
        return ""
    try:
        return subprocess.run(
            ["kubectl", *args], capture_output=True, text=True,
            timeout=3).stdout
    except subprocess.SubprocessError:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# REST endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/topology")
async def topology():
    return topology_snapshot()


@app.get("/api/state")
async def state():
    return scenario_state.get()


@app.get("/api/kpis")
async def kpis():
    return scenario_state.get().get("kpis", {})


@app.get("/api/events")
async def events(limit: int = 50):
    history = scenario_state.get().get("history", [])
    return {"events": history[-limit:]}


@app.get("/api/node/{node_id}")
async def node_detail(node_id: str):
    meta = next((n for n in NODES if n["id"] == node_id), None)
    if meta is None:
        raise HTTPException(404, detail=f"unknown node {node_id}")
    state = scenario_state.get()
    nd = state.get("node_details", {}).get(node_id, {})
    return {
        **meta,
        "status":  nd.get("status", "idle"),
        "metrics": nd.get("metrics", {}),
        "related_events": [
            h for h in state.get("history", [])
            if h.get("related_node") == node_id
        ][-10:],
    }


@app.get("/api/scenarios")
async def scenarios():
    return {"scenarios": SCENARIOS}


@app.get("/api/flows")
async def flows():
    return await _get_json(f"{RYU_URL}/pad/flows")


@app.get("/api/vnfs")
async def vnfs():
    raw = _kubectl("get", "pods", "-n", "pad-onap",
                   "-l", "app.kubernetes.io/component=vnf", "-o", "json")
    if not raw:
        return {"pods": []}
    try:
        data = json.loads(raw)
        return {"pods": [{
            "name": p["metadata"]["name"],
            "phase": p["status"].get("phase", "?"),
            "ip": p["status"].get("podIP", ""),
            "kind": p["metadata"].get("labels", {}).get(
                "pad-onap.tier", "?"),
        } for p in data.get("items", [])]}
    except (json.JSONDecodeError, KeyError):
        return {"pods": []}


@app.get("/api/metrics")
async def metrics():
    queries = {
        "fastpath_latency_ms": "pad_dual_path_fastpath_latency_ms",
        "slowpath_latency_ms": "pad_dual_path_slowpath_latency_ms",
        "victim_pps_in":
            "rate(pad_vnf_packets_total{direction=\"in\"}[10s])",
        "drop_pps": "rate(pad_vnf_drop_total[10s])",
    }
    out = {}
    async with httpx.AsyncClient(timeout=1.5) as c:
        for k, q in queries.items():
            try:
                r = await c.get(f"{PROM_URL}/api/v1/query",
                                params={"query": q})
                d = r.json()
                v = d.get("data", {}).get("result", [])
                out[k] = float(v[0]["value"][1]) if v else 0
            except Exception:
                out[k] = 0
    return out


# ─── Scenario control ────────────────────────────────────────────────────────
# NB: FastAPI matches routes in registration order. Specific (non-parametric)
# routes MUST come before the catch-all "/api/scenario/{scenario_id}" — otherwise
# clicking "Enable AI" would start the default attack scenario.

async def _start_scenario(scenario_id: str) -> dict:
    """Inner helper — kept separate so the convenience routes can reuse it."""
    if scenario_id in ("reset", "stop", "stop-attack"):
        scenario_state.reset()
        async with httpx.AsyncClient(timeout=2.0) as c:
            try:
                await c.delete(f"{RYU_URL}/pad/tier")
            except Exception:
                pass
        return {"ok": True, "msg": "reset"}

    sc = by_id(scenario_id)
    if sc is None:
        raise HTTPException(404, detail=f"unknown scenario {scenario_id!r}")
    scenario_state.reset(scenario=sc["id"],
                         attacker=sc["attacker"], victim=sc["victim"],
                         attack_type=sc["attack_type"],
                         mode=scenario_state.get().get("mode", "ai_assisted"))

    if not Path(SCENARIO_RUNNER).exists():
        scenario_state.push_event("scenario_start", id=sc["id"],
                                  runner="not_present")
        return {"ok": True, "msg": f"scenario {sc['id']} marked (no runner)"}

    subprocess.Popen(
        ["bash", SCENARIO_RUNNER, sc["id"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    scenario_state.push_event("scenario_start", id=sc["id"])
    return {"ok": True, "msg": f"scenario {sc['id']} started"}


# Specific routes FIRST
@app.post("/api/scenario/start-attack")
async def start_attack():
    return await _start_scenario(DEFAULT_ATTACK_ID)


@app.post("/api/scenario/stop-attack")
async def stop_attack():
    return await _start_scenario("stop")


@app.post("/api/scenario/enable-ai")
async def enable_ai():
    scenario_state.set_mode("ai_assisted")
    scenario_state.push_event("mode_change", mode="ai_assisted")
    return {"ok": True, "mode": "ai_assisted"}


@app.post("/api/scenario/compare-rule-only")
async def compare_rule_only():
    scenario_state.set_mode("rule_only")
    scenario_state.push_event("mode_change", mode="rule_only")
    return {"ok": True, "mode": "rule_only"}


# Parametric route LAST (catches S1..S8, reset, stop)
@app.post("/api/scenario/{scenario_id}")
async def run_scenario(scenario_id: str):
    return await _start_scenario(scenario_id)


# ─── Mode toggle ────────────────────────────────────────────────────────────
@app.post("/api/mode")
async def set_mode(req: Request):
    body = await req.json()
    mode = body.get("mode")
    if mode not in ("ai_assisted", "rule_only"):
        raise HTTPException(400, detail="mode must be ai_assisted | rule_only")
    scenario_state.set_mode(mode)
    scenario_state.push_event("mode_change", mode=mode)
    return {"ok": True, "mode": mode}


# ─── Node selection ─────────────────────────────────────────────────────────
@app.post("/api/node/select")
async def select_node(req: Request):
    body = await req.json()
    node_id = body.get("id", "")
    scenario_state.select_node(node_id)
    return {"ok": True, "selected_node": node_id}


# ─────────────────────────────────────────────────────────────────────────────
# Background Ryu poll (caches /pad/flows so the WS loop never blocks on it)
# ─────────────────────────────────────────────────────────────────────────────
_RYU_CACHE: dict[str, Any] = {"flows": None, "ts": 0.0, "reachable": False}


async def _ryu_poller() -> None:
    """Poll Ryu every 3s. Short timeout — failures are silent + cached."""
    while True:
        try:
            async with httpx.AsyncClient(timeout=0.8) as c:
                r = await c.get(f"{RYU_URL}/pad/flows")
                r.raise_for_status()
                _RYU_CACHE["flows"] = r.json()
                _RYU_CACHE["reachable"] = True
        except Exception:
            _RYU_CACHE["reachable"] = False
            # Keep last-known-good flows for the UI; mark stale if too old
            if asyncio.get_event_loop().time() - _RYU_CACHE["ts"] > 30:
                _RYU_CACHE["flows"] = None
        else:
            _RYU_CACHE["ts"] = asyncio.get_event_loop().time()
        await asyncio.sleep(3.0)


@app.on_event("startup")
async def _startup_ryu_poller() -> None:
    asyncio.create_task(_ryu_poller())


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — live push every 1 s (never blocks on external services)
# ─────────────────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            try:
                await websocket.send_json({
                    "state":    scenario_state.get(),
                    "topology": topology_snapshot(),
                    "flows":    _RYU_CACHE.get("flows"),
                    "ryu_reachable": _RYU_CACHE.get("reachable", False),
                })
            except WebSocketDisconnect:
                return
            except Exception:
                # Swallow transient errors so the loop keeps going
                pass
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return


# ─────────────────────────────────────────────────────────────────────────────
# Static files (HTML/JS/CSS) — served at /
# ─────────────────────────────────────────────────────────────────────────────
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True),
              name="static")

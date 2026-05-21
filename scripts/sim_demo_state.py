#!/usr/bin/env python3
"""
Demo simulator — feed plausible state into scenario_state.json so the UI
animates the full closed loop without Mininet / Kafka / Ryu / ONAP.

Run alongside `uvicorn frontend.backend:app --port 8088`:

    python scripts/sim_demo_state.py            # follow whatever scenario UI picks
    python scripts/sim_demo_state.py --auto S3  # auto-start S3 every 60s

The simulator reads `scenario_state.json` to learn which scenario the user
clicked in the UI, then writes back: KPIs, per-stage pipeline status,
per-node details, fast/slow path status, traffic counters, timeline events.

Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.s5_fastpath import scenario_state    # noqa: E402
from frontend.scenarios import by_id, SCENARIOS    # noqa: E402


def _ramp(start: float, end: float, t: float, dur: float) -> float:
    """Linear ramp clamped to [start, end] over duration."""
    if dur <= 0:
        return end
    f = max(0.0, min(1.0, t / dur))
    return start + (end - start) * f


def simulate_step(sc: dict, t: float, mode: str) -> None:
    """One 1-second tick of the simulation for scenario `sc` at elapsed t."""
    expected_tier = sc["expected_tier"]
    rate_target = sc["rate_pps_target"]
    dur = sc["duration_s"]

    # ── 1. Traffic ramp up over first 4 s, plateau, optional burst pattern ──
    base = _ramp(0, rate_target, t, 4.0)
    if sc["id"] == "S8":  # burst on/off
        base = base if int(t) % 20 < 10 else 0
    if t > dur - 4:
        base = _ramp(rate_target, 0, t - (dur - 4), 4.0)
    inbound = int(base * (0.95 + 0.1 * random.random()))
    mitigated = 0 if expected_tier == 0 else int(inbound * (0.4 +
                                                             0.15 * expected_tier))
    victim_in = max(0, inbound - mitigated)
    return_pps = int(inbound * 0.05) if inbound > 0 else 0

    # Gbps from pps assuming 1500-byte packets
    gbps = inbound * 1500 * 8 / 1e9

    # ── 2. Attack score (gradual rise once attack actually starts) ─────────
    if inbound < 500:
        score = 0
    else:
        target_score = (expected_tier / 4) * 100
        ramp_t = min(1.0, (t - 2) / 6)
        score = int(target_score * max(0, ramp_t) + random.randint(-3, 3))
        score = max(0, min(100, score))

    # ── 3. Forecast (AI mode only — rule-only blanks it) ───────────────────
    if mode == "ai_assisted" and score >= 30:
        fr_idx = min(3, expected_tier - 1) if expected_tier > 0 else 0
        forecast_risk = ["Low", "Medium", "High", "Critical"][max(0, fr_idx)]
        direction = "increasing" if t < dur - 6 else "decreasing"
        horizon = 30
    else:
        forecast_risk = "Low" if mode == "ai_assisted" else "n/a"
        direction = "stable"
        horizon = 0

    # ── 4. Tier determination ──────────────────────────────────────────────
    # AI-assisted: ramps to expected_tier earlier (predictive)
    # Rule-only:   only crosses threshold once traffic > threshold (reactive)
    if mode == "ai_assisted":
        tier = expected_tier if score >= 30 else 0
    else:
        tier = expected_tier if (inbound >= rate_target * 0.7
                                 and score >= 50) else 0

    # ── 5. Pipeline stage animation ────────────────────────────────────────
    if inbound > 0:
        scenario_state.mark_stage("M1_collector", "active",
                                  latency_ms=12 + random.randint(0, 5),
                                  throughput_pps=inbound)
        scenario_state.mark_stage("M2_features", "active",
                                  latency_ms=45 + random.randint(0, 15),
                                  features_per_sec=int(inbound / 50))
        if mode == "ai_assisted":
            scenario_state.mark_stage("M3_ai", "active",
                                      latency_ms=80 + random.randint(0, 30),
                                      tier_out=tier,
                                      confidence=min(0.99, score / 100 + 0.05))
        else:
            scenario_state.mark_stage("M3_ai", "idle")
        if tier > 0:
            scenario_state.mark_stage("M4_publisher", "done",
                                      latency_ms=15 + random.randint(0, 10))

    # ── 6. Fast-path / slow-path execution ─────────────────────────────────
    # IMPORTANT: do NOT alias fp = sp = {...} — both names would point to the
    # SAME dict and subsequent reads of sp["stage"] (added only in the tier>=2
    # branch) would KeyError.
    fp = {"status": "idle", "latency_ms": 0,
          "rules_installed": 0, "last_action": ""}
    sp = {"status": "idle", "latency_ms": 0,
          "stage": "idle", "vnf_name": "", "vnf_pod": ""}
    if tier >= 2:
        action = {2: "ratelimit", 3: "redirect", 4: "drop"}[tier]
        fp = {"status": "done",
              "rules_installed": 1 + (tier - 2),
              "last_action": action,
              "latency_ms": 8 + random.randint(0, 6)}
        sp = {"status": "active" if t < 8 else "done",
              "stage": "vnf_active" if t >= 8 else "so_instantiate",
              "vnf_name": f"vnfd-{action}-v1",
              "vnf_pod": f"pad-vnf-{action}-abc12" if t >= 8 else "",
              "latency_ms": int(2400 - 100 * max(0, t - 4))
                             if t < 12 else 2400}

    # ── 7. Per-node details ────────────────────────────────────────────────
    if inbound > 0:
        scenario_state.update_node("N1", status="active",
                                   attack_type=sc["attack_type"],
                                   rate_pps=inbound)
        scenario_state.update_node("N2", status="active",
                                   in_pps=inbound, out_pps=victim_in,
                                   telemetry_export="kafka:9092")
        scenario_state.update_node("N3", status="active",
                                   input="gNMI/gRPC", sampling_ms=1000,
                                   export_target="kafka:9092")
        scenario_state.update_node("N4", status="active",
                                   topic="telemetry.raw",
                                   lag=random.randint(0, 200),
                                   throughput_pps=int(inbound / 1000))
        scenario_state.update_node("N5", status="active",
                                   window_s=5, slide_s=1,
                                   features_per_sec=int(inbound / 50))
        if mode == "ai_assisted":
            scenario_state.update_node("N6", status="active",
                                       attack_score=score,
                                       confidence=round(min(0.99, score/100 + 0.05), 2),
                                       forecast_horizon_s=horizon,
                                       forecast_risk=forecast_risk,
                                       model="XGBoost + Transformer/LSTM")
        else:
            scenario_state.update_node("N6", status="idle")
        if tier >= 1:
            scenario_state.update_node("N7", status="active",
                                       events_in=int(t),
                                       related_loop="PAD-ONAP-DDoS-ClosedLoop")
            scenario_state.update_node(
                "N8", status="active", tier=f"T{tier}",
                rule_matched=f"high_severity_T{tier}",
                decision_basis="attack score + forecast" if mode == "ai_assisted"
                                else "threshold rule")
        if tier >= 2:
            scenario_state.update_node("N9", status="active",
                                       vnf_name=sp.get("vnf_name", ""),
                                       action="instantiate",
                                       replica_target=1)
            scenario_state.update_node(
                "N10", status="active" if sp["stage"] == "vnf_active" else "warn",
                replica="1/1" if sp["stage"] == "vnf_active" else "0/1",
                mode={"ratelimit":"token-bucket","redirect":"syn-proxy",
                      "drop":"blackhole"}.get(fp["last_action"], "n/a"),
                action=fp["last_action"])
            scenario_state.update_node("N11", status="active",
                                       status_text="protected",
                                       rps=int(victim_in / 10))

    # ── 8. Commit aggregate snapshot ───────────────────────────────────────
    delta = int((inbound - rate_target * 0.5) / max(1, rate_target * 0.5) * 100)
    scenario_state.update_kpis(
        traffic_rate_gbps=round(gbps, 3),
        traffic_rate_delta_pct=delta,
        attack_score=score,
        forecast_risk=forecast_risk,
        forecast_horizon_s=horizon,
        forecast_direction=direction,
        cnf_status="Healthy" if tier == 0 or sp["stage"] == "vnf_active"
                              else "Degraded",
        cnf_active=1 if sp["stage"] == "vnf_active" else 0,
        cnf_degraded=0,
        cnf_failed=0,
        cnf_desired=1 if tier >= 2 else 0,
    )

    with scenario_state.update() as s:
        s["active_tier"] = tier
        s["traffic"] = {"inbound_pps": inbound, "return_pps": return_pps,
                        "mitigated_pps": mitigated}
        s["metrics"] = {"attack_pps": inbound, "drop_pps": mitigated,
                        "victim_pps_in": victim_in}
        s["fastpath"] = fp
        s["slowpath"] = sp


def push_event_if_needed(prev_tier: int, new_tier: int) -> None:
    if prev_tier != new_tier:
        scenario_state.push_event(
            "tier_decision", tier=new_tier,
            related_node="N8" if new_tier > 0 else "")
    if new_tier >= 2 and prev_tier < 2:
        scenario_state.push_event(
            "cnf_deployed", related_node="N10")


def follow_loop(auto_id: str | None) -> None:
    """Main loop. Polls scenario_state for current scenario; auto-fires if asked."""
    last_scenario = ""
    last_start = 0.0
    prev_tier = 0

    auto_sc = by_id(auto_id) if auto_id else None
    if auto_id and auto_sc is None:
        print(f"[err] unknown scenario id '{auto_id}'. Use --list to inspect.",
              file=sys.stderr)
        sys.exit(2)

    if auto_sc:
        scenario_state.reset(scenario=auto_sc["id"],
                             attacker=auto_sc["attacker"],
                             victim=auto_sc["victim"],
                             attack_type=auto_sc["attack_type"])
        last_start = time.time()

    while True:
        state = scenario_state.get()
        scenario = state.get("scenario", "idle")
        mode = state.get("mode", "ai_assisted")

        if scenario != last_scenario:
            last_start = state.get("started_at") or time.time()
            last_scenario = scenario
            prev_tier = 0

        sc = by_id(scenario)
        if sc is None or scenario == "idle":
            time.sleep(1.0)
            continue

        t = time.time() - last_start
        dur = sc["duration_s"]

        if t > dur + 5:
            # Auto-stop after scenario duration + 5s tail
            scenario_state.push_event("scenario_end", id=scenario)
            scenario_state.reset()
            prev_tier = 0                     # reset so next ramp emits T-up event
            if auto_sc:
                time.sleep(15)
                scenario_state.reset(scenario=auto_sc["id"],
                                     attacker=auto_sc["attacker"],
                                     victim=auto_sc["victim"],
                                     attack_type=auto_sc["attack_type"])
                last_start = time.time()
                last_scenario = auto_sc["id"]
            continue

        simulate_step(sc, t, mode)
        new_tier = scenario_state.get().get("active_tier", 0)
        push_event_if_needed(prev_tier, new_tier)
        prev_tier = new_tier
        time.sleep(1.0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto", help="auto-start this scenario id every duration+15s",
                    default=None)
    ap.add_argument("--list", action="store_true",
                    help="list available scenario ids and exit")
    args = ap.parse_args()
    if args.list:
        for s in SCENARIOS:
            print(f"  {s['id']:>3}  {s['name']:<28}  expected={s['tier_label']}")
        return
    try:
        follow_loop(args.auto)
    except KeyboardInterrupt:
        scenario_state.reset()
        print("\n[stopped]")


if __name__ == "__main__":
    main()

"""
compare_ai_vs_baseline.py — Real ONAP comparison report
========================================================
Reads up to three result JSONs and produces a side-by-side latency
breakdown:

  --ai-reactive   evaluation/results/s2_real_onap.json          (AI XGBoost reactive)
  --ai-proactive  evaluation/results/s8_real_onap.json          (AI Transformer proactive + reactive)
  --baseline      evaluation/results/s2_baseline_real_onap.json (ONAP rule-based, no AI)

All three runs use the SAME real ONAP downstream (CLAMP / SO / OVS) and
the SAME 17-feature stream from the NetFlow collector — only the
detector differs. The metrics emitted here are the thesis-grade
quantities defined in §5c of `requirements/onap_e2e_runbook.md`.

Metrics
-------
For each run:
  detection_lat_ms        = t_trigger - t_attack_start
                            (how long the detector took to recognise the attack)
  detection_to_policy_ms  = t_policy_push - t_trigger
  policy_to_so_ms         = t_so_request  - t_policy_push
  so_to_vnf_ms            = t_vnf_active  - t_so_request
  vnf_to_sfc_ms           = t_sfc_rule    - t_vnf_active
  pipeline_e2e_ms         = t_sfc_rule    - t_trigger
  time_to_mitigation_ms   = t_sfc_rule    - t_attack_start

Cross-run quantities:
  reactive_advantage_ms   = baseline.time_to_mitigation_ms - ai_reactive.time_to_mitigation_ms
  proactive_advantage_ms  = baseline.time_to_mitigation_ms - ai_proactive.t2_time_to_mitigation_ms
  forecast_lead_time_s    = ai_proactive.lead_time_s
                            (T3 trigger time − T2 trigger time inside the AI proactive run)

Usage:
    python onap/scripts/compare_ai_vs_baseline.py \\
        --ai-reactive  evaluation/results/s2_real_onap.json \\
        --ai-proactive evaluation/results/s8_real_onap.json \\
        --baseline     evaluation/results/s2_baseline_real_onap.json \\
        --out          evaluation/results/ai_vs_baseline.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def _load(path: Optional[Path]) -> Optional[dict]:
    if path is None:
        return None
    if not path.exists():
        print(f"WARNING: {path} not found — skipping", file=sys.stderr)
        return None
    with open(path) as f:
        return json.load(f)


# ── Metric extractors ────────────────────────────────────────────────────────
def _e2e_metrics(rec: dict) -> dict:
    """Pull metrics from an E2ERecord-style dict (S2 / baseline)."""
    t0 = rec.get("t_attack_start", 0.0) or 0.0
    t_trig = rec.get("t_trigger", 0.0)
    t_pol  = rec.get("t_policy_push", 0.0)
    t_so   = rec.get("t_so_request", 0.0)
    t_vnf  = rec.get("t_vnf_active", 0.0)
    t_sfc  = rec.get("t_sfc_rule", 0.0)
    return {
        "detection_lat_ms":        max(0.0, (t_trig - t0) * 1000) if t0 else None,
        "detection_to_policy_ms":  (t_pol - t_trig) * 1000 if t_trig else None,
        "policy_to_so_ms":         (t_so  - t_pol)  * 1000 if t_pol  else None,
        "so_to_vnf_ms":            (t_vnf - t_so)   * 1000 if t_so   else None,
        "vnf_to_sfc_ms":           (t_sfc - t_vnf)  * 1000 if t_vnf  else None,
        "pipeline_e2e_ms":         (t_sfc - t_trig) * 1000 if t_trig else None,
        "time_to_mitigation_ms":   (t_sfc - t0)     * 1000 if t0     else None,
        "detector":                rec.get("detector", "?"),
        "label":                   rec.get("detector_label", ""),
    }


def _s8_t2_metrics(s8: dict) -> dict:
    """Extract T2 (proactive) metrics from S8Result."""
    t0 = s8.get("t2_t_attack_start", 0.0) or 0.0
    t_trig = s8.get("t2_t_trigger", 0.0)
    e2e_pipeline = s8.get("t2_end_to_end_ms", 0.0)
    if not t_trig:
        return {"detector": "ai_proactive", "label": "T2 not fired"}
    return {
        "detection_lat_ms":       max(0.0, (t_trig - t0) * 1000) if t0 else None,
        "detection_to_policy_ms": s8.get("t2_t_policy_ms"),
        "policy_to_so_ms":        s8.get("t2_t_so_ms"),
        "so_to_vnf_ms":           s8.get("t2_t_vnf_active_ms"),
        "vnf_to_sfc_ms":          s8.get("t2_t_sfc_ms"),
        "pipeline_e2e_ms":        e2e_pipeline,
        "time_to_mitigation_ms":  ((t_trig - t0) * 1000 + e2e_pipeline) if t0 else None,
        "detector":               "ai_proactive_t2",
        "label":                  f"Transformer forecast → {s8.get('lead_time_s', 0):.1f}s ahead",
    }


def _s8_t3_metrics(s8: dict) -> dict:
    """Extract T3 (reactive within S8) metrics from S8Result."""
    t0 = s8.get("t3_t_attack_start", 0.0) or 0.0
    t_trig = s8.get("t3_t_trigger", 0.0)
    e2e_pipeline = s8.get("t3_end_to_end_ms", 0.0)
    if not t_trig:
        return {"detector": "ai_proactive_t3", "label": "T3 not fired"}
    return {
        "detection_lat_ms":       max(0.0, (t_trig - t0) * 1000) if t0 else None,
        "detection_to_policy_ms": s8.get("t3_t_policy_ms"),
        "policy_to_so_ms":        s8.get("t3_t_so_ms"),
        "so_to_vnf_ms":           s8.get("t3_t_vnf_active_ms"),
        "vnf_to_sfc_ms":          s8.get("t3_t_sfc_ms"),
        "pipeline_e2e_ms":        e2e_pipeline,
        "time_to_mitigation_ms":  ((t_trig - t0) * 1000 + e2e_pipeline) if t0 else None,
        "detector":               "ai_proactive_t3",
        "label":                  "XGBoost classifier",
    }


# ── Report rendering ─────────────────────────────────────────────────────────
def _fmt(v) -> str:
    if v is None or v == 0:
        return "—"
    return f"{v:>9.0f} ms"


METRIC_ORDER = [
    ("detection_lat_ms",       "Attack-start → Detect"),
    ("detection_to_policy_ms", "Detect → Policy push"),
    ("policy_to_so_ms",        "Policy push → SO request"),
    ("so_to_vnf_ms",           "SO request → VNF active"),
    ("vnf_to_sfc_ms",          "VNF active → SFC rule"),
    ("pipeline_e2e_ms",        "**Pipeline (Detect → SFC)**"),
    ("time_to_mitigation_ms",  "**Total (Attack → SFC)**"),
]


def render(ai_reactive: Optional[dict], ai_t2: Optional[dict],
           ai_t3: Optional[dict], baseline: Optional[dict],
           lead_time_s: float) -> str:
    cols = []
    if ai_t2:       cols.append(("AI Proactive (T2)",  ai_t2))
    if ai_reactive: cols.append(("AI Reactive (S2)",   ai_reactive))
    if ai_t3:       cols.append(("AI Reactive (S8 T3)", ai_t3))
    if baseline:    cols.append(("ONAP Rule-based",    baseline))

    if not cols:
        return "# No data — provide at least one input file.\n"

    # Header
    out = ["# AI vs ONAP Rule-based — Real-cluster Comparison\n"]
    out.append("Detector summary:\n")
    for name, m in cols:
        out.append(f"- **{name}** — {m.get('label','?')}")
    out.append("")

    # Latency table
    header = "| Metric | " + " | ".join(n for n, _ in cols) + " |"
    sep    = "|--------|" + "|".join(":---------:" for _ in cols) + "|"
    out.append(header)
    out.append(sep)
    for key, label in METRIC_ORDER:
        row = f"| {label} | " + " | ".join(_fmt(m.get(key)) for _, m in cols) + " |"
        out.append(row)
    out.append("")

    # Cross-run advantages
    out.append("## Advantage over ONAP rule-based baseline\n")
    bl_ttm = baseline.get("time_to_mitigation_ms") if baseline else None
    if bl_ttm:
        if ai_t2 and ai_t2.get("time_to_mitigation_ms") is not None:
            adv = bl_ttm - ai_t2["time_to_mitigation_ms"]
            out.append(f"- **Proactive (T2) saves**: {adv:>8.0f} ms "
                       f"({adv/bl_ttm*100:.1f}%) vs baseline "
                       f"({bl_ttm:.0f} ms → {ai_t2['time_to_mitigation_ms']:.0f} ms)")
        if ai_reactive and ai_reactive.get("time_to_mitigation_ms") is not None:
            adv = bl_ttm - ai_reactive["time_to_mitigation_ms"]
            out.append(f"- **AI Reactive (S2) saves**: {adv:>8.0f} ms "
                       f"({adv/bl_ttm*100:.1f}%) vs baseline "
                       f"({bl_ttm:.0f} ms → {ai_reactive['time_to_mitigation_ms']:.0f} ms)")
    else:
        out.append("- (no baseline result provided — advantage cannot be computed)")
    out.append("")

    if lead_time_s:
        out.append(f"- **Forecast lead-time** (T3 fire − T2 fire inside AI proactive run): "
                   f"`{lead_time_s:.1f} s`")
        out.append(f"  → that many seconds the network was already protected before "
                   f"the reactive detector would have triggered.")
    out.append("")

    # Notes on metric definitions
    out.append("## Metric definitions\n")
    out.append("- `detection_lat_ms` = t_trigger − t_attack_start. The pure "
               "**detector cost** — what AI/Transformer/forecast/threshold rule "
               "actually buys the system before any ONAP work starts.")
    out.append("- `pipeline_e2e_ms` = t_sfc_rule − t_trigger. ONAP downstream "
               "cost from CLAMP push through OVS rule install. This stage is the "
               "same code in all three runs; differences come only from the VNF "
               "profile (ratelimiter vs scrubber).")
    out.append("- `time_to_mitigation_ms` = t_sfc_rule − t_attack_start. The "
               "user-visible quantity — how long until packets stop reaching the "
               "victim. **Lower is better.**")
    out.append("- `forecast_lead_time_s` is internal to the AI proactive run "
               "(no baseline equivalent) and quantifies how early Transformer "
               "fired vs the XGBoost reactive detector on the same traffic.")

    return "\n".join(out) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai-reactive",  type=Path, default=None,
                    help="evaluation/results/s2_real_onap.json")
    ap.add_argument("--ai-proactive", type=Path, default=None,
                    help="evaluation/results/s8_real_onap.json")
    ap.add_argument("--baseline",     type=Path, default=None,
                    help="evaluation/results/s2_baseline_real_onap.json")
    ap.add_argument("--out",          type=Path, required=True,
                    help="markdown output path")
    args = ap.parse_args()

    s2  = _load(args.ai_reactive)
    s8  = _load(args.ai_proactive)
    bl  = _load(args.baseline)

    ai_reactive_m = _e2e_metrics(s2) if s2 else None
    baseline_m    = _e2e_metrics(bl) if bl else None
    ai_t2_m       = _s8_t2_metrics(s8) if s8 else None
    ai_t3_m       = _s8_t3_metrics(s8) if s8 else None
    lead_time_s   = float(s8.get("lead_time_s", 0.0)) if s8 else 0.0

    md = render(ai_reactive_m, ai_t2_m, ai_t3_m, baseline_m, lead_time_s)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md, encoding="utf-8")
    print(md)
    print(f"\nSaved → {args.out}")


if __name__ == "__main__":
    main()

"""
Threshold (non-AI) Baseline Orchestrator
========================================
Implements the *legacy* rule-based DDoS defense that the AI pipeline replaces.
Same downstream stack (PolicyEngine → ONAP SO → SFC → LatencyTracker) but the
detection stage is a static set of thresholds on the 17 raw features — no ML,
no forecast. Used as the comparison baseline for the thesis evaluation.

Rules (tuned from CICDDoS2019 attack statistics):
    pkt_rate        > 10000   → T3 (heavy flood)
    pkt_rate        > 3000    → T2 (moderate flood)
    pkt_rate        >  800    → T1 (alert)
    syn_ratio       > 0.60    → at least T3 (SYN flood)
    proto_dist_udp  > 0.85    → at least T3 (UDP flood)
    proto_dist_icmp > 0.70    → at least T2 (ICMP amp)
    src_ip_entropy  < 0.80    → at least T2 (spoofing signal)

No proactive tier: threshold baseline only reacts to *current* window — there
is no forecast, no pre-positioning. This is the key structural disadvantage
vs the AI orchestrator and is what the S3/S7/S8 comparisons quantify.

Usage:
    python -m evaluation.baseline_threshold
    python -m evaluation.baseline_threshold --scenario S8
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import List

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s4_orchestration.tier_mapper     import (
    Tier, TierDecision, TIER_LABEL, TIER_VNF_PROFILE,
    TIER_DEFAULT_CNF_PROFILE,
)
from pipeline.s4_orchestration.policy_engine   import PolicyEngine, PolicyAction
from pipeline.s4_orchestration.sla_allocator   import SLAAllocator
from pipeline.s4_orchestration.clamp_simulator import CLAMPClient
from pipeline.s4_orchestration.onap_so_client  import ONAPSOClient
from pipeline.s4_orchestration.sfc_manager     import SFCManager
from pipeline.s4_orchestration.latency_tracker import LatencyTracker, LatencyRecord

from evaluation.scenarios import (
    SCENARIOS, ScenarioSpec, ScenarioResult,
)
from pipeline.s3_ai.inference_layer import TRACK_A_FEATURES
from pipeline.s4_orchestration.orchestrator import (
    DEFAULT_TENANTS, VNF_OVERHEAD_MBPS,
)

logger = logging.getLogger('baseline_threshold')


# ── Feature index (must match evaluation/scenarios.py FEATURE_NAMES) ──────────
IDX_PKT_RATE       = 0
IDX_BYTE_RATE      = 1
IDX_SRC_IP_ENTROPY = 2
IDX_PROTO_TCP      = 6
IDX_PROTO_UDP      = 7
IDX_PROTO_ICMP     = 8
IDX_SYN_RATIO      = 9


def threshold_decide(x: np.ndarray) -> TierDecision:
    """Pure-rule tier selection. No ML, no forecast."""
    if len(x) == 22:
        f = {name: float(x[i]) for i, name in enumerate(TRACK_A_FEATURES)}
        pkt_rate = f['flow_packets_per_sec']
        total_pkts = f['total_fwd_packets'] + f['total_bwd_packets']
        syn_ratio = (f['syn_flag_count'] / total_pkts) if total_pkts > 0 else 0.0
        proto = int(f['protocol'])
        udp_frac = 1.0 if proto == 17 else 0.0
        icmp_frac = 1.0 if proto == 1 else 0.0
        src_ent = 0.0
    else:
        pkt_rate   = float(x[IDX_PKT_RATE])
        syn_ratio  = float(x[IDX_SYN_RATIO])
        udp_frac   = float(x[IDX_PROTO_UDP])
        icmp_frac  = float(x[IDX_PROTO_ICMP])
        src_ent    = float(x[IDX_SRC_IP_ENTROPY])

    tier = Tier.NORMAL
    reasons = []

    if pkt_rate > 10000:
        tier = max(tier, Tier.MITIGATE); reasons.append(f"pkt_rate={pkt_rate:.0f}>10k")
    elif pkt_rate > 3000:
        tier = max(tier, Tier.PREEMPT);  reasons.append(f"pkt_rate={pkt_rate:.0f}>3k")
    elif pkt_rate > 800:
        tier = max(tier, Tier.ALERT);    reasons.append(f"pkt_rate={pkt_rate:.0f}>800")

    if syn_ratio > 0.60:
        tier = max(tier, Tier.MITIGATE); reasons.append(f"syn_ratio={syn_ratio:.2f}")
    if udp_frac > 0.85:
        tier = max(tier, Tier.MITIGATE); reasons.append(f"udp_frac={udp_frac:.2f}")
    if icmp_frac > 0.70:
        tier = max(tier, Tier.PREEMPT);  reasons.append(f"icmp_frac={icmp_frac:.2f}")
    if src_ent < 0.80 and pkt_rate > 500:
        tier = max(tier, Tier.PREEMPT);  reasons.append(f"src_ent={src_ent:.2f}")

    reason = "; ".join(reasons) if reasons else f"below all thresholds (pkt={pkt_rate:.0f})"
    # Synthetic confidence for logging parity with AI path
    conf = 0.0 if tier == Tier.NORMAL else min(0.5 + 0.1 * int(tier), 0.99)

    return TierDecision(
        tier         = tier,
        label        = TIER_LABEL[tier],
        confidence   = conf,
        p_attack_1min = 0.0,         # no forecast
        p_attack_5min = 0.0,
        p_attack_15min = 0.0,
        attack_type  = 'RuleBased',
        attack_class_id = 0 if tier == Tier.NORMAL else 1,
        triggered_horizon = None,
        proactive    = False,         # threshold baseline is never proactive
        cnf_profile  = TIER_DEFAULT_CNF_PROFILE.get(tier),
        vnfd_profile = TIER_VNF_PROFILE.get(tier),
        source_ip_prefix = None,
        target_ip_prefix = None,
        tenant_id = None,
        severity = 'INFO' if tier < Tier.PREEMPT else 'MAJOR',
        dedup_key = None,
        reason       = reason,
    )


class BaselineOrchestrator:
    """
    Mirrors Orchestrator but swaps InferenceEngine for threshold_decide().
    Downstream stack (Policy → SO → SFC → LatencyTracker) is unchanged so the
    resulting latency / tier metrics are directly comparable.
    """

    def __init__(
        self,
        device_id:     str = 'default',
        total_bw_mbps: float = 1000.0,
        latency_port:  int = 9294,
        eval_mode:     bool = True,
    ):
        self.device_id = device_id
        self.policy    = PolicyEngine(eval_mode=eval_mode)
        self.clamp     = CLAMPClient()
        self.sla       = SLAAllocator(total_bw_mbps=total_bw_mbps)
        self.tenants   = list(DEFAULT_TENANTS)
        self.so        = ONAPSOClient()
        self.sfc       = SFCManager()
        self.tracker   = LatencyTracker()
        self.tracker.start_server(port=latency_port)
        self._active_instance: dict = {}
        self._window_count = 0

    # ── Reset helpers to match AI orchestrator's eval pattern ─────────────────
    @property
    def engine(self):  # dummy so scenarios.run_scenario reset works
        class _E:
            def reset_buffer(self): pass
        return _E()

    def _step(self, x_raw: np.ndarray) -> dict:
        rec = LatencyRecord(
            event_id  = uuid.uuid4().hex[:12],
            window_id = self._window_count + 1,
            tier      = 0,
        )
        rec.t_ai_detection = time.time()

        td   = threshold_decide(x_raw)
        pdec = self.policy.evaluate(self.device_id, td)
        rec.t_policy_decision = time.time()
        rec.tier = int(pdec.new_tier)

        overhead = VNF_OVERHEAD_MBPS.get(int(pdec.new_tier), 0.0)
        sla_res  = self.sla.allocate(self.tenants, vnf_overhead_mbps=overhead)

        if pdec.acted and pdec.action != PolicyAction.HOLD:
            policy_req = self.clamp.build_policy(pdec, device_id=self.device_id)
            self.clamp.push(policy_req)

            if pdec.action in (PolicyAction.NEW_ATTACK, PolicyAction.ESCALATE):
                old_iid = self._active_instance.pop(self.device_id, None)
                if old_iid:
                    self.sfc.remove(self.device_id)
                    self.so.terminate(old_iid)

                if pdec.new_tier >= Tier.PREEMPT and td.vnf_profile:
                    inst = self.so.instantiate(td.vnf_profile)
                    rec.t_so_request = time.time()
                    try:
                        rec.t_vnf_active = self.so.wait_active(inst, timeout_s=30.0)
                    except TimeoutError:
                        rec.t_vnf_active = time.time()
                    if inst.status == 'ACTIVE':
                        rule = self.sfc.install(
                            device_id=self.device_id, vnf_inst=inst,
                            tier=int(pdec.new_tier),
                        )
                        t_sfc = rule.t_installed
                        if rec.t_vnf_active > t_sfc:
                            t_sfc = rec.t_vnf_active + 0.001
                        rec.t_sfc_updated = t_sfc
                        self._active_instance[self.device_id] = inst.instance_id
                else:
                    rec.t_so_request  = rec.t_policy_decision
                    rec.t_vnf_active  = rec.t_policy_decision
                    rec.t_sfc_updated = rec.t_policy_decision
            elif pdec.action == PolicyAction.DEESCALATE:
                if pdec.new_tier < Tier.PREEMPT:
                    old_iid = self._active_instance.pop(self.device_id, None)
                    if old_iid:
                        self.sfc.remove(self.device_id)
                        self.so.terminate(old_iid)
                    if pdec.new_tier == Tier.NORMAL:
                        self.clamp.revoke_all(self.device_id)
                rec.t_so_request  = rec.t_policy_decision
                rec.t_vnf_active  = rec.t_policy_decision
                rec.t_sfc_updated = rec.t_policy_decision
        else:
            rec.t_so_request  = rec.t_policy_decision
            rec.t_vnf_active  = rec.t_policy_decision
            rec.t_sfc_updated = rec.t_policy_decision

        rec.finalize()
        self.tracker.record(rec)

        return {
            'window_id':     rec.window_id,
            'event_id':      rec.event_id,
            'attack_type':   td.attack_type,
            'attack_class':  td.attack_class,
            'confidence':    td.confidence,
            'p_attack_30s':  0.0,
            'tier':          rec.tier,
            'action':        pdec.action.value,
            'acted':         pdec.acted,
            'proactive':     False,
            'latency':       rec.to_dict(),
            'sla_satisfied': all(a.sla_satisfied for a in sla_res.allocations),
            'reason':        td.reason,
        }


# ── Scenario driver (mirrors evaluation.scenarios.run_scenario) ───────────────

def run_scenario_baseline(scenario: ScenarioSpec, orch: BaselineOrchestrator,
                          out_dir: Path) -> ScenarioResult:
    logger.info(f"[baseline] Scenario: {scenario.name}")
    orch.policy.reset(orch.device_id)
    orch._active_instance.clear()
    orch._window_count = 0

    records = []
    tier_dist = {0:0, 1:0, 2:0, 3:0, 4:0}
    sla_ok_count = 0

    for x in scenario.windows:
        r = orch._step(x)
        orch._window_count += 1
        records.append(r)
        tier_dist[r['tier']] = tier_dist.get(r['tier'], 0) + 1
        if r.get('sla_satisfied'):
            sla_ok_count += 1

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / f'{scenario.name}.jsonl'
    with open(jsonl, 'w') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')

    def lat_stats(tier_filter=None):
        lats = []
        for r in records:
            if tier_filter is not None and r['tier'] != tier_filter:
                continue
            if not r.get('acted', False):
                continue
            if r.get('action', '') not in ('NEW_ATTACK', 'ESCALATE'):
                continue
            e2e = r.get('latency', {}).get('end_to_end_ms', 0)
            if e2e > 10:
                lats.append(e2e)
        if not lats:
            return {'p50':0,'p95':0,'p99':0,'n':0}
        a = np.array(lats)
        return {
            'p50': round(float(np.percentile(a,50)), 2),
            'p95': round(float(np.percentile(a,95)), 2),
            'p99': round(float(np.percentile(a,99)), 2),
            'n':   len(lats),
        }

    max_tier = max((r['tier'] for r in records), default=0)
    sla_ok   = sla_ok_count == len(records) or len(records) == 0
    ceiling_ok = max_tier <= scenario.expected_max_tier
    floor_ok   = max_tier >= scenario.expected_min_tier
    pass_fail  = 'PASS' if (ceiling_ok and floor_ok) else 'FAIL'

    result = ScenarioResult(
        scenario=scenario.name, n_windows=len(records),
        max_tier_reached=max_tier, tier_dist=tier_dist,
        proactive_count=0,
        e2e_latency_ms=lat_stats(),
        tier2_latency_ms=lat_stats(2),
        tier3_latency_ms=lat_stats(3),
        sla_ok=sla_ok, pass_fail=pass_fail,
    )
    with open(out_dir / f'{scenario.name}_summary.json', 'w') as f:
        json.dump(asdict(result), f, indent=2)

    logger.info(
        f"  [{pass_fail}] max_tier=T{max_tier}  "
        f"T2={result.tier2_latency_ms['p50']:.0f}ms  "
        f"T3={result.tier3_latency_ms['p50']:.0f}ms"
    )
    return result


def run_all(out_dir: str) -> List[ScenarioResult]:
    orch = BaselineOrchestrator()
    out  = Path(out_dir)
    results = [run_scenario_baseline(s, orch, out) for s in SCENARIOS]
    summary = {
        'method':          'threshold_baseline',
        'total_scenarios': len(results),
        'passed':          sum(1 for r in results if r.pass_fail == 'PASS'),
        'failed':          sum(1 for r in results if r.pass_fail == 'FAIL'),
        'scenarios':       [asdict(r) for r in results],
    }
    with open(out / 'baseline_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Baseline done: {summary['passed']}/{summary['total_scenarios']} PASS")
    return results


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--out-dir', default=str(
        _PROJECT_ROOT / 'evaluation' / 'results_baseline'))
    parser.add_argument('--scenario', default=None)
    args = parser.parse_args()

    out = Path(args.out_dir)
    if args.scenario:
        orch = BaselineOrchestrator()
        sc = next((s for s in SCENARIOS if args.scenario.upper() in s.name), None)
        if not sc:
            print(f"Unknown scenario. Available: {[s.name for s in SCENARIOS]}")
            sys.exit(1)
        run_scenario_baseline(sc, orch, out)
    else:
        run_all(args.out_dir)

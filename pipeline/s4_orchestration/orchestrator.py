"""
M3/M4 — Orchestrator: M2 → M3 → M4 main loop (Spec-aligned §5–§6)

Connects every component into one runnable pipeline:

  InferenceEngine  (M2 / S3-AI)
       ↓ AIOutputPayload
  TierMapper       → TierDecision
       ↓
  PolicyEngine     → PolicyDecision (with frequency guard + hysteresis)
       ↓ acted == True and action != HOLD
  CLAMPClient      → push drools policy to ONAP PAP
       ↓
  ONAPSOClient     → instantiate / terminate VNF container
       ↓ wait_active()
  SFCManager       → install / remove OVS steering rule
       ↓
  SLAAllocator     → recompute tenant bandwidth allocation
       ↓
  LatencyTracker   → record E2E timestamps → Prometheus

Usage (standalone):
  python -m pipeline.s4_orchestration.orchestrator \\
      --source http \\
      --collector http://localhost:7070 \\
      --model-dir ./pad_onap_v3/models \\
      --data-dir  ./pad_onap_v3/processed

  # Full ONAP mode (real SO + Policy):
  PAD_ONAP_STUB=false python -m pipeline.s4_orchestration.orchestrator ...

  # Evaluation mode (replay test set, collect all latency records):
  python -m pipeline.s4_orchestration.orchestrator \\
      --source replay \\
      --replay-dir ./pad_onap_v3/processed \\
      --max-windows 500 \\
      --out ./evaluation/results/scenario_s1.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s4_orchestration.tier_mapper    import TierMapper, Tier
from pipeline.s4_orchestration.policy_engine  import PolicyEngine, PolicyAction
from pipeline.s4_orchestration.sla_allocator  import SLAAllocator, Tenant
from pipeline.s4_orchestration.clamp_simulator import CLAMPClient
from pipeline.s4_orchestration.onap_so_client  import ONAPSOClient
from pipeline.s4_orchestration.sfc_manager     import SFCManager
from pipeline.s4_orchestration.latency_tracker import LatencyTracker, LatencyRecord

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('orchestrator')

# ── Default 3-tenant SLA config ────────────────────────────────────────────────
DEFAULT_TENANTS = [
    Tenant('slice-eMBB',  guaranteed_bw_mbps=200, current_demand_mbps=450, priority_weight=1.0),
    Tenant('slice-URLLC', guaranteed_bw_mbps=100, current_demand_mbps=150, priority_weight=2.0),
    Tenant('slice-mMTC',  guaranteed_bw_mbps= 50, current_demand_mbps=300, priority_weight=0.5),
]
VNF_OVERHEAD_MBPS = {
    0: 0.0,
    1: 5.0,
    2: 20.0,
    3: 50.0,
    4: 80.0,
}


class Orchestrator:
    """
    Main M2→M3→M4 orchestration loop.

    Usage:
        orch = Orchestrator(model_dir='./pad_onap_v3/models',
                            data_dir='./pad_onap_v3/processed')
        orch.run(source='http', collector_url='http://localhost:7070')
    """

    def __init__(
        self,
        model_dir:        str = './pad_onap_v3/models',
        data_dir:         str = './pad_onap_v3/processed',
        device:           str = 'auto',
        shap_enabled:     bool = True,
        device_id:        str = 'default',
        total_bw_mbps:    float = 1000.0,
        latency_port:     int = 9292,
        tenants=None,
        eval_mode:        bool = False,  # True → no frequency guard, sim latency
    ):
        self.model_dir    = model_dir
        self.data_dir     = data_dir
        self.device       = device
        self.shap_enabled = shap_enabled
        self.device_id    = device_id
        self.eval_mode    = eval_mode

        # M2
        from pipeline.s3_ai.inference_layer import InferenceEngine
        self.engine = InferenceEngine.load(
            model_dir    = model_dir,
            data_dir     = data_dir,
            device       = device,
            shap_enabled = shap_enabled,
        )

        # M3
        self.mapper  = TierMapper()
        self.policy  = PolicyEngine(eval_mode=eval_mode)
        self.clamp   = CLAMPClient()
        self.sla     = SLAAllocator(total_bw_mbps=total_bw_mbps)
        self.tenants = tenants or DEFAULT_TENANTS

        # M4
        self.so  = ONAPSOClient()
        self.sfc = SFCManager()

        # Instrumentation
        self.tracker = LatencyTracker()
        self.tracker.start_server(port=latency_port)

        # Per-device active VNF instance ID
        self._active_instance: dict = {}   # device_id → instance_id
        self._window_count = 0

        logger.info("Orchestrator ready")

    # ── Main loop ──────────────────────────────────────────────────────────────

    def run(
        self,
        source:        str = 'http',
        collector_url: str = 'http://localhost:7070',
        broker:        str = 'localhost:9092',
        interval:      float = 1.0,
        out_path:      Optional[str] = None,
        max_windows:   Optional[int] = None,
    ):
        """Run continuous orchestration loop."""
        logger.info("=" * 64)
        logger.info("  PAD-ONAP Orchestrator  (M2 → M3 → M4)")
        logger.info(f"  Source: {source.upper()}  Device: {self.device_id}")
        logger.info("=" * 64)

        # Feature source setup
        if source == 'kafka':
            from pipeline.s3_ai.live_pipeline import KafkaFeatureConsumer
            kafka_consumer = KafkaFeatureConsumer(broker=broker)
        else:
            kafka_consumer = None

        out_file = open(out_path, 'a') if out_path else None

        _running = [True]
        def _handler(sig, frame):
            logger.info("Shutdown signal — stopping...")
            _running[0] = False
        signal.signal(signal.SIGINT,  _handler)
        signal.signal(signal.SIGTERM, _handler)

        FEATURE_NAMES = [
            'pkt_rate','byte_rate','src_ip_entropy','dst_ip_entropy',
            'src_port_entropy','dst_port_entropy','proto_dist_tcp',
            'proto_dist_udp','proto_dist_icmp','syn_ratio','fin_ratio',
            'avg_pkt_size','pkt_size_std','new_flows_rate',
            'flow_duration_mean','inter_arrival_mean','inter_arrival_std',
        ]

        last_ts = None

        while _running[0]:
            t_loop = time.perf_counter()

            # ── Fetch features ─────────────────────────────────────────────────
            if source == 'kafka':
                raw = kafka_consumer.poll_latest()
            elif source == 'replay':
                break   # replay handled by run_replay()
            else:
                from pipeline.s3_ai.live_pipeline import fetch_latest
                raw = fetch_latest(collector_url)

            if raw is None:
                time.sleep(interval)
                continue

            ts = raw.get('timestamp')
            if ts == last_ts:
                time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))
                continue
            last_ts = ts

            feats = raw.get('features', {})
            if not feats:
                time.sleep(interval)
                continue

            x_raw = np.array(
                [float(feats.get(n, 0.0)) for n in FEATURE_NAMES],
                dtype=np.float32,
            )

            record = self._step(x_raw)
            self._window_count += 1

            if out_file and record:
                out_file.write(json.dumps(record) + '\n')
                out_file.flush()

            if max_windows and self._window_count >= max_windows:
                break

            elapsed = time.perf_counter() - t_loop
            time.sleep(max(0.0, interval - elapsed))

        # cleanup
        if kafka_consumer:
            kafka_consumer.close()
        if out_file:
            out_file.close()
        self._log_summary()

    def run_replay(
        self,
        data_dir:    str,
        n_samples:   Optional[int] = None,
        out_path:    Optional[str] = None,
    ) -> list:
        """
        Replay test set — used by evaluation scenarios.
        Returns list of result records.
        """
        data_dir = Path(data_dir)
        scaler   = self.engine.scaler

        X_test = np.load(data_dir / 'X_test.npy').astype(np.float32)
        y_test = np.load(data_dir / 'y_test.npy').astype(int)
        X_raw  = scaler.inverse_transform(X_test).astype(np.float32)

        if n_samples:
            X_raw  = X_raw[:n_samples]
            y_test = y_test[:n_samples]

        logger.info(f"Replay: {len(X_raw):,} windows from {data_dir}")

        out_file = open(out_path, 'w') if out_path else None
        results  = []

        for x_raw in X_raw:
            record = self._step(x_raw)
            self._window_count += 1
            if record:
                results.append(record)
                if out_file:
                    out_file.write(json.dumps(record) + '\n')
                    out_file.flush()

        if out_file:
            out_file.close()
        self._log_summary()
        return results

    # ── Single step: one 5-second window ──────────────────────────────────────

    def _step(self, x_raw: np.ndarray) -> Optional[dict]:
        """Process one feature vector through M2→M3→M4. Returns record dict."""
        rec = LatencyRecord(
            event_id  = '',
            window_id = self._window_count + 1,
            tier      = 0,
        )

        # ── M2: inference ──────────────────────────────────────────────────────
        payload          = self.engine.infer(x_raw)
        rec.event_id     = payload.event_id
        rec.t_ai_detection = time.time()

        # ── M3a: tier mapping ──────────────────────────────────────────────────
        td   = self.mapper.decide(payload)
        pdec = self.policy.evaluate(self.device_id, td)
        rec.t_policy_decision = time.time()
        rec.tier = int(pdec.new_tier)

        # ── M3b: SLA reallocation ──────────────────────────────────────────────
        overhead = VNF_OVERHEAD_MBPS.get(int(pdec.new_tier), 0.0)
        sla_res  = self.sla.allocate(self.tenants, vnf_overhead_mbps=overhead)

        # ── M3c/M4: VNF lifecycle (only when tier changes) ────────────────────
        if pdec.acted and pdec.action != PolicyAction.HOLD:

            # Push CLAMP policy
            policy_req = self.clamp.build_policy(pdec, device_id=self.device_id)
            self.clamp.push(policy_req)

            if pdec.action in (PolicyAction.NEW_ATTACK, PolicyAction.ESCALATE):
                # Terminate old VNF if any
                old_iid = self._active_instance.pop(self.device_id, None)
                if old_iid:
                    self.sfc.remove(self.device_id)
                    self.so.terminate(old_iid)

                if pdec.new_tier >= Tier.PREEMPT and td.vnf_profile:
                    # Instantiate new VNF
                    inst = self.so.instantiate(td.vnf_profile)
                    rec.t_so_request = time.time()

                    try:
                        rec.t_vnf_active = self.so.wait_active(inst, timeout_s=30.0)
                    except TimeoutError as e:
                        logger.error(str(e))
                        rec.t_vnf_active = time.time()

                    # Install SFC rule
                    if inst.status == 'ACTIVE':
                        rule = self.sfc.install(
                            device_id = self.device_id,
                            vnf_inst  = inst,
                            tier      = int(pdec.new_tier),
                        )
                        # In simulation mode t_vnf_active is a future timestamp;
                        # ensure t_sfc_updated >= t_vnf_active so derived
                        # latencies (so_to_vnf_ms, end_to_end_ms) are correct.
                        t_sfc = rule.t_installed
                        if rec.t_vnf_active > t_sfc:
                            t_sfc = rec.t_vnf_active + 0.001  # 1ms OVS install
                        rec.t_sfc_updated = t_sfc
                        self._active_instance[self.device_id] = inst.instance_id
                else:
                    rec.t_so_request  = rec.t_policy_decision
                    rec.t_vnf_active  = rec.t_policy_decision
                    rec.t_sfc_updated = rec.t_policy_decision

            elif pdec.action == PolicyAction.DEESCALATE:
                if pdec.new_tier < Tier.PREEMPT:
                    # Remove VNF chain
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

        # ── Finalise latency record ────────────────────────────────────────────
        rec.finalize()
        self.tracker.record(rec)

        # ── Console log ───────────────────────────────────────────────────────
        marker = ''
        if pdec.acted and pdec.action != PolicyAction.HOLD:
            marker = f'  [{pdec.action.value} T{pdec.prev_tier}→T{pdec.new_tier}]'
        if self._window_count % 10 == 0 or marker:
            logger.info(
                f"[W{self._window_count+1:04d}] "
                f"{payload.detection.attack_type:<14} "
                f"conf={payload.detection.confidence:.3f}  "
                f"T{rec.tier}  e2e={rec.end_to_end_ms:.0f}ms{marker}"
            )

        return {
            'window_id':       rec.window_id,
            'event_id':        rec.event_id,
            'attack_type':     payload.detection.attack_type,
            'attack_class':    payload.detection.attack_class,
            'confidence':      payload.detection.confidence,
            'p_attack_30s':    payload.forecast.p_attack_30s,
            'tier':            rec.tier,
            'action':          pdec.action.value,
            'acted':           pdec.acted,
            'proactive':       td.proactive,
            'latency':         rec.to_dict(),
            'sla_satisfied':   all(a.sla_satisfied for a in sla_res.allocations),
            'sla_allocations': [
                {'tenant': a.tenant_id, 'alloc_mbps': round(a.alloc_mbps, 1)}
                for a in sla_res.allocations
            ],
        }

    def _log_summary(self):
        logger.info("=" * 64)
        logger.info(f"Orchestrator: {self._window_count} windows processed")
        s = self.tracker.summary()
        if s.get('n', 0) > 0:
            e2e = s.get('end_to_end_ms', {})
            logger.info(
                f"E2E latency — P50={e2e.get('p50',0):.0f}ms  "
                f"P95={e2e.get('p95',0):.0f}ms  "
                f"P99={e2e.get('p99',0):.0f}ms"
            )
        ts = self.tracker.per_tier_summary()
        for tier_key, stat in ts.items():
            if stat.get('n', 0) > 0:
                e = stat.get('end_to_end_ms', {})
                logger.info(
                    f"  {tier_key}: n={stat['n']}  "
                    f"P95={e.get('p95',0):.0f}ms"
                )
        logger.info("=" * 64)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    _root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Orchestrator (M2→M3→M4)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--source',     default='http',
                        choices=['http', 'kafka', 'replay'])
    parser.add_argument('--collector',  default='http://localhost:7070')
    parser.add_argument('--broker',     default='localhost:9092')
    parser.add_argument('--model-dir',  default=str(_root / 'pad_onap_v3' / 'models'))
    parser.add_argument('--data-dir',   default=str(_root / 'pad_onap_v3' / 'processed'))
    parser.add_argument('--interval',   type=float, default=1.0)
    parser.add_argument('--device',     default='auto', choices=['auto','cuda','cpu'])
    parser.add_argument('--no-shap',    action='store_true')
    parser.add_argument('--device-id',  default='default',
                        help='Device/flow identifier (source IP or ONAP instance UUID)')
    parser.add_argument('--out',        default=None,
                        help='Output JSONL path')
    parser.add_argument('--max-windows', type=int, default=None)
    parser.add_argument('--latency-port', type=int, default=9292,
                        help='Prometheus metrics port for latency tracker')
    parser.add_argument('--replay-samples', type=int, default=None,
                        help='N test samples for --source replay')
    args = parser.parse_args()

    orch = Orchestrator(
        model_dir    = args.model_dir,
        data_dir     = args.data_dir,
        device       = args.device,
        shap_enabled = not args.no_shap,
        device_id    = args.device_id,
        latency_port = args.latency_port,
    )

    if args.source == 'replay':
        orch.run_replay(
            data_dir   = args.data_dir,
            n_samples  = args.replay_samples or args.max_windows,
            out_path   = args.out,
        )
    else:
        orch.run(
            source        = args.source,
            collector_url = args.collector,
            broker        = args.broker,
            interval      = args.interval,
            out_path      = args.out,
            max_windows   = args.max_windows,
        )


if __name__ == '__main__':
    main()

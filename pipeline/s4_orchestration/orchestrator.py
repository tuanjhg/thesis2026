"""
M3/M4 — Orchestrator: M2 → M3 → M4 main loop (Spec §5–§6, schema 3.0)
=====================================================================

Connects every component into one runnable pipeline (two-track edition):

  InferenceEngine (Track A 22-dim XGBoost  +  Track B 6-dim 60-step LSTM)
       ↓ TrackADetection / TrackBForecast → coalesced AIOutputPayload
  TierMapper       → TierDecision   (horizon-specific thresholds)
       ↓
  PolicyEngine     → PolicyDecision (strict-monotonic + 1 Pod / 30 s guard
                                     + P<0.30 60s abatement + Tier-3 dedup)
       ↓ acted == True and action != HOLD
  CLAMPClient      → push policy to ONAP PAP
       ↓
  ONAPSOClient     → instantiate / terminate CNF
                     (PAD_DEPLOY_MODE = stub | helm | onap)
       ↓ wait_active() + NFV metrics
  SFCManager       → install / remove OVS steering rule
       ↓ + SLAAllocator (Gold / Silver / Bronze)
  LatencyTracker   → record E2E timestamps → Prometheus

Usage:
  python -m pipeline.s4_orchestration.orchestrator \
      --source kafka --broker localhost:9092 \
      --model-dir ./pad_onap_v3/models

  # Real ONAP SO mode
  PAD_DEPLOY_MODE=onap python -m pipeline.s4_orchestration.orchestrator ...

  # Helm mode against an existing K8s cluster
  PAD_DEPLOY_MODE=helm \
  PAD_HELM_KUBECTX=my-cluster \
  PAD_HELM_NAMESPACE=pad-onap \
  python -m pipeline.s4_orchestration.orchestrator ...

  # Replay test set (offline evaluation)
  python -m pipeline.s4_orchestration.orchestrator --source replay \
      --replay-dir ./pad_onap_v3/processed --max-windows 500 \
      --out ./evaluation/results/scenario_s1.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s3_ai.inference_layer  import (
    InferenceEngine,
    TRACK_A_FEATURES,
    TRACK_B_FEATURES,
)
from pipeline.s3_ai.ai_output         import (
    DetectionResult, ForecastResult, build_payload,
)
from pipeline.s4_orchestration.tier_mapper    import TierMapper, Tier
from pipeline.s4_orchestration.policy_engine  import PolicyEngine, PolicyAction
from pipeline.s4_orchestration.sla_allocator  import SLAAllocator, Tenant
from pipeline.s4_orchestration.clamp_simulator import CLAMPClient
from pipeline.s4_orchestration.onap_so_client  import ONAPSOClient
from pipeline.s4_orchestration.sfc_manager     import SFCManager
from pipeline.s4_orchestration.latency_tracker import LatencyTracker, LatencyRecord
from pipeline.s4_orchestration import health_endpoint

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('orchestrator')

# ── Default 3-tenant SLA config (Gold / Silver / Bronze per Spec §5.5) ───────
DEFAULT_TENANTS = [
    Tenant.gold  ('slice-finance', contracted_bw_mbps=400, current_demand_mbps=350),
    Tenant.silver('slice-eMBB',    contracted_bw_mbps=300, current_demand_mbps=280),
    Tenant.bronze('slice-IoT',     contracted_bw_mbps=200, current_demand_mbps=190),
]

# Per-tier scrubbing-CNF bandwidth overhead (Mbps)
VNF_OVERHEAD_MBPS = {
    int(Tier.NORMAL):   0.0,
    int(Tier.ALERT):    5.0,
    int(Tier.PREEMPT):  20.0,
    int(Tier.MITIGATE): 50.0,
    int(Tier.ISOLATE):  80.0,
}


class Orchestrator:
    """
    Main M2→M3→M4 orchestration loop (two-track edition).

    Public API:
        orch = Orchestrator(model_dir='./pad_onap_v3/models',
                            data_dir='./pad_onap_v3/processed',
                            mode='spec')
        orch.run(source='kafka', broker='localhost:9092')
    """

    def __init__(
        self,
        model_dir:        str = './pad_onap_v3/models',
        data_dir:         str = './pad_onap_v3/processed',
        mode:             str = 'spec',         # 'spec' (22+6) | 'legacy' (bridge)
        device:           str = 'auto',
        shap_enabled:     bool = True,
        device_id:        str = 'default',
        total_bw_mbps:    float = 1000.0,
        latency_port:     int = 9292,
        tenants=None,
        eval_mode:        bool = False,
    ):
        self.model_dir    = model_dir
        self.data_dir     = data_dir
        self.device       = device
        self.shap_enabled = shap_enabled
        self.device_id    = device_id
        self.eval_mode    = eval_mode
        self.mode         = mode

        # M2 — two-track inference engine
        self.engine = InferenceEngine.load(
            model_dir    = model_dir,
            data_dir     = data_dir,
            mode         = mode,
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

        # K8s liveness/readiness side-car
        health_port = int(os.environ.get('PAD_HEALTH_PORT', '9293'))
        health_endpoint.start(port=health_port)
        health_endpoint.register_snapshot_provider(self._health_snapshot)

        # Per-device active CNF instance
        self._active_instance: dict[str, str] = {}
        self._window_count = 0

        logger.info(
            f'Orchestrator ready  mode={mode}  deploy={self.so.deploy_mode}  '
            f'tenants={len(self.tenants)}  health=:{health_port}'
        )

    def _health_snapshot(self) -> dict:
        """Snapshot used by /readyz to expose live metrics."""
        snap: dict = {
            'mode':              self.mode,
            'deploy_mode':       self.so.deploy_mode,
            'windows_processed': self._window_count,
            'active_cnfs':       len(self._active_instance),
        }
        try:
            snap['latency'] = self.tracker.summary()
        except Exception:
            pass
        try:
            snap['nfv'] = self.so.metrics.summary()
        except Exception:
            pass
        return snap

    # ── Live loop ───────────────────────────────────────────────────────────

    def run(
        self,
        source:        str = 'kafka',
        collector_url: str = 'http://localhost:7070',
        broker:        str = 'localhost:9092',
        interval:      float = 1.0,
        out_path:      Optional[str] = None,
        max_windows:   Optional[int] = None,
    ):
        """Run the continuous orchestration loop."""
        logger.info('=' * 64)
        logger.info(f'  PAD-ONAP Orchestrator v3  (mode={self.mode})')
        logger.info(f'  Source: {source.upper()}  Device: {self.device_id}')
        logger.info('=' * 64)

        # ── Set up feature source ──────────────────────────────────────────
        from pipeline.s3_ai.live_pipeline import (
            KafkaFeatureConsumer, fetch_latest, _flow_features_from_snapshot,
        )

        kafka_a = None    # Track A consumer (telemetry.features.flow)
        kafka_b = None    # Track B consumer (telemetry.features.timeseries)
        if source == 'kafka':
            from kafka import KafkaConsumer
            kafka_a = KafkaFeatureConsumer(broker=broker,
                                           group_id='pad-orch-track-a')
            # Track B uses its own consumer subscribed to the timeseries topic
            kafka_b = KafkaConsumer(
                'telemetry.features.timeseries',
                bootstrap_servers=[broker],
                group_id='pad-orch-track-b',
                auto_offset_reset='latest',
                enable_auto_commit=True,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                consumer_timeout_ms=200,
            )
        elif source == 'replay':
            return  # caller should use run_replay()

        out_file = open(out_path, 'a') if out_path else None

        _running = [True]
        def _handler(sig, frame):
            logger.info('Shutdown signal — stopping...')
            _running[0] = False
        signal.signal(signal.SIGINT,  _handler)
        signal.signal(signal.SIGTERM, _handler)

        last_ts_a: Optional[str] = None

        while _running[0]:
            t_loop = time.perf_counter()

            # ── Fetch Track A vector ─────────────────────────────────────
            if source == 'kafka':
                msg_a = kafka_a.poll_latest()
                if msg_a is None:
                    self._drain_track_b(kafka_b)
                    time.sleep(interval); continue
                ts_a = msg_a.get('timestamp')
                if ts_a == last_ts_a:
                    self._drain_track_b(kafka_b)
                    time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))
                    continue
                last_ts_a = ts_a
                feats_a = msg_a.get('features') or {}
                src_dev = msg_a.get('source_device_id', self.device_id)
                ip_meta = {
                    'source_ip_prefix': msg_a.get('source_ip_prefix'),
                    'target_ip_prefix': msg_a.get('target_ip_prefix'),
                    'tenant_id':        msg_a.get('tenant_id'),
                }
                x22 = np.array(
                    [float(feats_a.get(n, 0.0)) for n in TRACK_A_FEATURES],
                    dtype=np.float32,
                )
            else:   # http
                raw = fetch_latest(collector_url)
                if raw is None:
                    time.sleep(interval); continue
                ts_a = raw.get('timestamp')
                if ts_a == last_ts_a:
                    time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))
                    continue
                last_ts_a = ts_a
                snapshot = raw.get('features') or raw
                x22      = _flow_features_from_snapshot(snapshot)
                src_dev  = raw.get('device_id', self.device_id)
                ip_meta  = {
                    'source_ip_prefix': raw.get('source_ip_prefix'),
                    'target_ip_prefix': raw.get('target_ip_prefix'),
                    'tenant_id':        raw.get('tenant_id'),
                }

            # ── Drain any Track B aggregates (keeps the 60-step buffer warm) ─
            if kafka_b is not None:
                self._drain_track_b(kafka_b)

            record = self._step(
                x22, source_device_id=src_dev, ip_meta=ip_meta,
            )
            self._window_count += 1

            if out_file and record:
                out_file.write(json.dumps(record) + '\n')
                out_file.flush()

            if max_windows and self._window_count >= max_windows:
                break

            time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))

        # cleanup
        if kafka_a is not None:
            kafka_a.close()
        if kafka_b is not None:
            try: kafka_b.close()
            except Exception: pass
        if out_file:
            out_file.close()
        self._log_summary()

    def _drain_track_b(self, kafka_b) -> None:
        """Drain pending Track B (timeseries) messages into the engine buffer."""
        if kafka_b is None:
            return
        try:
            for msg in kafka_b:
                payload = msg.value or {}
                feats   = payload.get('features') or {}
                src_dev = payload.get('source_device_id', self.device_id)
                x6 = np.array(
                    [float(feats.get(n, 0.0)) for n in TRACK_B_FEATURES],
                    dtype=np.float32,
                )
                self.engine.infer_track_b(x6, source_device_id=src_dev)
        except StopIteration:
            pass
        except Exception as e:
            logger.warning(f'Track B drain error: {e}')

    # ── Replay ──────────────────────────────────────────────────────────────

    def run_replay(
        self,
        data_dir:    str,
        n_samples:   Optional[int] = None,
        out_path:    Optional[str] = None,
    ) -> list:
        """
        Replay a stored test set through the two-track engine.  Looks for the
        spec-aligned arrays first; falls back to the legacy 17-feature dump.

        Spec arrays (preferred):
          X_test_track_a.npy   shape (N, 22)
          X_test_track_b.npy   shape (M, 6)        (optional)
          y_test_track_a.npy   shape (N,)          (12-class CICDDoS labels)

        Legacy fallback:
          X_test.npy           shape (N, 17)       — sent through the
                                                     engine's legacy bridge
          y_test.npy           shape (N,)          (7-class)
        """
        data_dir = Path(data_dir)
        spec_x = data_dir / 'X_test_track_a.npy'
        if spec_x.exists():
            X_a = np.load(spec_x).astype(np.float32)
            y   = np.load(data_dir / 'y_test_track_a.npy').astype(int)
            logger.info(f'Replay (spec): X_a={X_a.shape}  y={y.shape}')
            track_b_path = data_dir / 'X_test_track_b.npy'
            X_b = (np.load(track_b_path).astype(np.float32)
                   if track_b_path.exists() else None)
        else:
            X_legacy = np.load(data_dir / 'X_test.npy').astype(np.float32)
            scaler   = self.engine.scaler_a
            X_raw17  = scaler.inverse_transform(X_legacy).astype(np.float32)
            X_a = self._legacy17_to_track_a_22(X_raw17)
            y   = np.load(data_dir / 'y_test.npy').astype(int)
            X_b = None
            logger.info(
                f'Replay (legacy bridge): X_a={X_a.shape}  y={y.shape} '
                f'(arrays widened from 17→22 dims)'
            )

        if n_samples:
            X_a = X_a[:n_samples]
            y   = y[:n_samples]
            if X_b is not None:
                X_b = X_b[: max(1, n_samples // 12)]

        # Pre-load Track B history so the LSTM has context when inference
        # starts; otherwise the first ~60 forecasts return zeros.
        if X_b is not None:
            for row in X_b[:60]:
                self.engine.infer_track_b(row, source_device_id=self.device_id)

        out_file = open(out_path, 'w') if out_path else None
        results: list = []

        for x22 in X_a:
            record = self._step(
                x22,
                source_device_id=self.device_id,
                ip_meta={'source_ip_prefix': None,
                         'target_ip_prefix': None,
                         'tenant_id':        None},
            )
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

    @staticmethod
    def _legacy17_to_track_a_22(X17: np.ndarray) -> np.ndarray:
        """
        Widen a (N, 17) legacy feature matrix to (N, 22) Track A schema by
        mapping the rate-style legacy fields to their CICFlowMeter analogues.
        Used only by the replay fallback path; production code drives Track A
        from the dual-branch Flink processor's 22-dim output directly.
        """
        N = X17.shape[0]
        out = np.zeros((N, len(TRACK_A_FEATURES)), dtype=np.float32)

        # Legacy index lookup
        idx = {
            'pkt_rate': 0, 'byte_rate': 1,
            'syn_ratio': 9, 'avg_pkt_size': 11, 'pkt_size_std': 12,
            'flow_duration_mean': 14,
            'iat_mean': 15, 'iat_std': 16,
            'proto_tcp': 6, 'proto_udp': 7, 'proto_icmp': 8,
        }
        WINDOW_S = 5.0
        proto_map = np.array([6, 17, 1])     # IANA codes

        pkt_rate  = X17[:, idx['pkt_rate']]
        byte_rate = X17[:, idx['byte_rate']]
        total_pkts  = pkt_rate * WINDOW_S
        total_bytes = byte_rate * WINDOW_S

        names = TRACK_A_FEATURES
        out[:, names.index('flow_duration')]            = WINDOW_S
        out[:, names.index('total_fwd_packets')]        = 0.6 * total_pkts
        out[:, names.index('total_bwd_packets')]        = 0.4 * total_pkts
        out[:, names.index('total_length_fwd_packets')] = 0.6 * total_bytes
        out[:, names.index('total_length_bwd_packets')] = 0.4 * total_bytes
        out[:, names.index('fwd_packet_length_max')]    = (
            X17[:, idx['avg_pkt_size']] + X17[:, idx['pkt_size_std']]
        )
        out[:, names.index('fwd_packet_length_mean')]   = X17[:, idx['avg_pkt_size']]
        out[:, names.index('bwd_packet_length_mean')]   = X17[:, idx['avg_pkt_size']]
        out[:, names.index('flow_bytes_per_sec')]       = byte_rate
        out[:, names.index('flow_packets_per_sec')]     = pkt_rate
        out[:, names.index('flow_iat_mean')]            = X17[:, idx['iat_mean']]
        out[:, names.index('flow_iat_std')]             = X17[:, idx['iat_std']]
        out[:, names.index('fwd_iat_total')]            = X17[:, idx['iat_mean']] * 0.6 * total_pkts
        out[:, names.index('fwd_iat_mean')]             = X17[:, idx['iat_mean']]
        out[:, names.index('bwd_iat_total')]            = X17[:, idx['iat_mean']] * 0.4 * total_pkts
        out[:, names.index('syn_flag_count')]           = X17[:, idx['syn_ratio']] * total_pkts

        # Dominant protocol → IANA code
        proto_block = X17[:, [idx['proto_tcp'], idx['proto_udp'], idx['proto_icmp']]]
        out[:, names.index('protocol')] = proto_map[np.argmax(proto_block, axis=1)]
        return out

    # ── Single window ───────────────────────────────────────────────────────

    def _step(
        self,
        x22:               np.ndarray,
        *,
        source_device_id:  str,
        ip_meta:           dict,
    ) -> Optional[dict]:
        """
        Process one Track A window through M2 → M3 → M4.
        Track B forecast is read from the engine's most recent state for this
        device (populated by `_drain_track_b()` in live mode, or by replay
        priming).
        """
        rec = LatencyRecord(
            event_id  = '',
            window_id = self._window_count + 1,
            tier      = 0,
        )

        # ── M2: inference (Track A live; Track B pulled from buffer) ──────
        det = self.engine.infer_track_a(x22, source_device_id=source_device_id)
        rec.t_ai_detection = time.time()
        # Forecast: replay the latest 60-step buffer for this device
        buf = self.engine._buffers_b.get(source_device_id)
        if buf is not None and len(buf) > 0:
            p1, p5, p15 = self.engine._forecast_horizons(buf)
        else:
            p1, p5, p15 = 0.0, 0.0, 0.0
        from pipeline.s3_ai.inference_layer import HORIZON_THRESHOLDS
        triggered = None
        if p15 >= HORIZON_THRESHOLDS[15]: triggered = 15
        if p5  >= HORIZON_THRESHOLDS[5]:  triggered = 5
        if p1  >= HORIZON_THRESHOLDS[1]:  triggered = 1

        det_dc = DetectionResult(
            track             = det.track,
            attack_type       = det.attack_type,
            attack_class_id   = det.attack_class_id,
            confidence        = det.confidence,
            is_attack         = det.is_attack,
            class_probs       = dict(det.class_probs),
            shap_top_features = list(det.shap_top_features),
            shap_values       = dict(det.shap_values),
            explanation_text  = det.explanation_text,
            inference_ms      = det.inference_ms,
        )
        fc_dc = ForecastResult(
            track                    = 'B_LSTM',
            p_attack_1min            = float(p1),
            p_attack_5min            = float(p5),
            p_attack_15min           = float(p15),
            pre_position_recommended = (triggered is not None and triggered >= 5),
            triggered_horizon        = triggered,
        )
        payload = build_payload(
            detection            = det_dc,
            forecast             = fc_dc,
            source_ip_prefix     = ip_meta.get('source_ip_prefix'),
            target_ip_prefix     = ip_meta.get('target_ip_prefix'),
            tenant_id            = ip_meta.get('tenant_id'),
            xgboost_version      = self.engine.xgb_version,
            lstm_track_b_version = self.engine.forecaster_version,
        )
        rec.event_id = payload.event_id

        # ── M3a: tier mapping + policy ────────────────────────────────────
        td   = self.mapper.decide(payload)
        pdec = self.policy.evaluate(self.device_id, td)
        rec.t_policy_decision = time.time()
        rec.tier = int(pdec.new_tier)

        # ── M3b: SLA reallocation ─────────────────────────────────────────
        overhead = VNF_OVERHEAD_MBPS.get(int(pdec.new_tier), 0.0)
        sla_res  = self.sla.allocate(self.tenants, vnf_overhead_mbps=overhead)

        # ── M3c / M4: CNF lifecycle (only on tier change) ─────────────────
        if pdec.acted and pdec.action != PolicyAction.HOLD:
            policy_req = self.clamp.build_policy(pdec, device_id=self.device_id)
            self.clamp.push(policy_req)

            if pdec.action in (PolicyAction.NEW_ATTACK, PolicyAction.ESCALATE):
                old_iid = self._active_instance.pop(self.device_id, None)
                if old_iid:
                    self.sfc.remove(self.device_id)
                    self.so.terminate(old_iid)

                if pdec.new_tier >= Tier.PREEMPT:
                    profile = td.cnf_profile or td.vnfd_profile
                    if profile:
                        inst = self.so.instantiate(profile)
                        rec.t_so_request = time.time()
                        try:
                            rec.t_vnf_active = self.so.wait_active(inst, timeout_s=30.0)
                        except TimeoutError as e:
                            logger.error(str(e))
                            rec.t_vnf_active = time.time()
                        if inst.status == 'ACTIVE':
                            rule = self.sfc.install(
                                device_id = self.device_id,
                                vnf_inst  = inst,
                                tier      = int(pdec.new_tier),
                            )
                            t_sfc = rule.t_installed
                            if rec.t_vnf_active > t_sfc:
                                t_sfc = rec.t_vnf_active + 0.001
                            rec.t_sfc_updated = t_sfc
                            self.so.record_sfc_latency(
                                inst.instance_id,
                                (t_sfc - rec.t_vnf_active) * 1000.0,
                            )
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
        health_endpoint.heartbeat()

        # ── Console log ───────────────────────────────────────────────────
        marker = ''
        if pdec.acted and pdec.action != PolicyAction.HOLD:
            marker = f'  [{pdec.action.value} T{int(pdec.prev_tier)}→T{int(pdec.new_tier)}]'
        if self._window_count % 10 == 0 or marker:
            logger.info(
                f'[W{self._window_count + 1:04d}] '
                f'{det.attack_type:<14} conf={det.confidence:.3f}  '
                f'P1={p1:.2f} P5={p5:.2f} P15={p15:.2f}  '
                f'T{rec.tier} sev={payload.severity_estimate} '
                f'e2e={rec.end_to_end_ms:.0f}ms{marker}'
            )

        return {
            'window_id':       rec.window_id,
            'event_id':        rec.event_id,
            'attack_type':     det.attack_type,
            'attack_class_id': det.attack_class_id,
            'confidence':      det.confidence,
            'p_attack_1min':   float(p1),
            'p_attack_5min':   float(p5),
            'p_attack_15min':  float(p15),
            'triggered_horizon': triggered,
            'tier':            rec.tier,
            'severity':        payload.severity_estimate,
            'cnf_profile':     td.cnf_profile,
            'action':          pdec.action.value,
            'acted':           pdec.acted,
            'proactive':       td.proactive,
            'guard_reason':    pdec.guard_reason,
            'latency':         rec.to_dict(),
            'sla_satisfied':   all(a.sla_satisfied for a in sla_res.allocations),
            'sla_allocations': [
                {'tenant': a.tenant_id, 'tier': a.tier,
                 'alloc_mbps': round(a.alloc_mbps, 1),
                 'sla_satisfied': a.sla_satisfied}
                for a in sla_res.allocations
            ],
        }

    # ── Summary ─────────────────────────────────────────────────────────────

    def _log_summary(self):
        logger.info('=' * 64)
        logger.info(f'Orchestrator: {self._window_count} windows processed')
        s = self.tracker.summary()
        if s.get('n', 0) > 0:
            e2e = s.get('end_to_end_ms', {})
            logger.info(
                f'E2E latency — P50={e2e.get("p50", 0):.0f}ms  '
                f'P95={e2e.get("p95", 0):.0f}ms  '
                f'P99={e2e.get("p99", 0):.0f}ms'
            )
        nfv = self.so.metrics.summary()
        if nfv:
            logger.info(
                f'NFV — boot p50={nfv.get("boot_time_s_p50", 0):.2f}s  '
                f'p95={nfv.get("boot_time_s_p95", 0):.2f}s  '
                f'cpu_mean={nfv.get("peak_cpu_pct_mean", 0):.1f}%  '
                f'ram_mean={nfv.get("peak_ram_gb_mean", 0):.2f}GB'
            )
        logger.info('=' * 64)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    _root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Orchestrator v3 (M2→M3→M4, two-track inference)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--source',         default='kafka',
                        choices=['http', 'kafka', 'replay'])
    parser.add_argument('--collector',      default='http://localhost:7070')
    parser.add_argument('--broker',         default='localhost:9092')
    parser.add_argument('--model-dir',      default=str(_root / 'pad_onap_v3' / 'models'))
    parser.add_argument('--data-dir',       default=str(_root / 'pad_onap_v3' / 'processed'))
    parser.add_argument('--mode',           default='spec', choices=['spec', 'legacy'])
    parser.add_argument('--interval',       type=float, default=1.0)
    parser.add_argument('--device',         default='auto', choices=['auto', 'cuda', 'cpu'])
    parser.add_argument('--no-shap',        action='store_true')
    parser.add_argument('--device-id',      default='default')
    parser.add_argument('--out',            default=None)
    parser.add_argument('--max-windows',    type=int, default=None)
    parser.add_argument('--latency-port',   type=int, default=9292)
    parser.add_argument('--replay-samples', type=int, default=None)
    parser.add_argument('--eval-mode',      action='store_true',
                        help='Disable PolicyEngine frequency guard (replay only)')
    args = parser.parse_args()

    orch = Orchestrator(
        model_dir    = args.model_dir,
        data_dir     = args.data_dir,
        mode         = args.mode,
        device       = args.device,
        shap_enabled = not args.no_shap,
        device_id    = args.device_id,
        latency_port = args.latency_port,
        eval_mode    = args.eval_mode or args.source == 'replay',
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

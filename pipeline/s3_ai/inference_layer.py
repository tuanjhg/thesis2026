"""
M2 — Inference Engine v2 (Spec §4 — Two-Track Hybrid Inference)
================================================================

Architecture:
    Kafka topic `telemetry.features.flow`        Kafka topic `telemetry.features.timeseries`
              (Track A — 22-dim, every 1s)                 (Track B — 6-dim, every 60s)
                       │                                              │
                       ▼                                              ▼
              ┌──────────────────┐                          ┌──────────────────┐
              │ XGBoost (12-cls) │                          │ Stacked LSTM     │
              │ + SHAP TreeExpl. │                          │ (look_back=60)   │
              │ Track A path     │                          │ horizons 1/5/15  │
              └────────┬─────────┘                          └────────┬─────────┘
                       │ TrackADetection                              │ TrackBForecast
                       └──────────────────┬───────────────────────────┘
                                          ▼
                                ┌────────────────────┐
                                │  PayloadCoalescer  │
                                │  (target_ip + 30s) │
                                └─────────┬──────────┘
                                          ▼
                                Kafka topic `ai.detections`
                                (UnifiedAIOutput, schema 3.0)

Operating modes:
    mode="spec"
        Native 22-dim XGBoost + 60-step 6-dim Stacked LSTM with horizons {1,5,15}.
        Activates once Phase 1/2 trainers produce the new artefacts in `models_v3/`.
    mode="legacy"   (default while Phase 1/2 are deferred)
        Bridges the spec-aligned 22+6 message schemas to the existing 17-feature
        7-class XGBoost and 12-step 17-feature 4-horizon Transformer+LSTM, so
        the end-to-end pipeline keeps producing AI outputs while the new models
        are being trained.  Bridge is documented inline at every adaptation site.

Latency budget (Spec §4.2 / §4.3):
    Track A: <50ms total (XGBoost ≤30ms + SHAP ≤20ms)
    Track B: ≤200ms per forecast on 4-vCPU worker
"""

from __future__ import annotations

import json
import logging
import math
import pickle
import sys
import time
import uuid
import warnings
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import xgboost as xgb

# Project root on sys.path for both module + script use
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s3_ai.transformer_lstm import (
    TransformerLSTMForecaster,
    N_TIMESTEPS as LEGACY_N_TIMESTEPS,
    N_FEATURES  as LEGACY_N_FEATURES,
)

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Spec-aligned constants (Spec §3.3 / §3.4 / §4.2 / §4.3 / §4.5)
# ─────────────────────────────────────────────────────────────────────────────

TRACK_A_FEATURES: list[str] = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'total_length_fwd_packets', 'total_length_bwd_packets',
    'fwd_packet_length_max', 'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std',
    'fwd_iat_total', 'fwd_iat_mean', 'bwd_iat_total',
    'syn_flag_count', 'ack_flag_count', 'fwd_psh_flags',
    'init_win_bytes_fwd', 'init_win_bytes_bwd',
    'min_seg_size_fwd', 'protocol',
]
N_TRACK_A_FEATURES = 22

TRACK_B_FEATURES: list[str] = [
    'pkt_count_total', 'byte_count_total',
    'unique_src_ip_count', 'unique_dst_ip_count',
    'avg_pkt_size', 'syn_count',
]
N_TRACK_B_FEATURES = 6
TRACK_B_LOOK_BACK   = 60   # 60 one-minute timesteps

# Spec §4.2 (P3 hybrid) — 5-class CICDDoS2019 taxonomy.
# Rationale (see notebooks/_patch_v4_5class.py): the 8 reflection sub-types
# in the original 12-class IJSRA-2021 schema all map to the same CNF
# mitigation profile (`cnf-scrubber-reflection`), so collapsing them into a
# single "Amplification" macro-class preserves operational semantics while
# rebalancing the softmax target.
CICDDOS_CLASSES: dict[int, str] = {
    0: 'BENIGN',
    1: 'Amplification',     # DrDoS_DNS / LDAP / MSSQL / NetBIOS / NTP / SNMP / SSDP / UDP
    2: 'Syn',
    3: 'UDP-lag',
    4: 'WebDDoS',
}
N_CICDDOS_CLASSES = 5

# Legacy 12-class identifiers retained for backwards-compatibility with the
# v1/v2/v3 model artefacts (xgb_label_map.json may still reference these).
LEGACY_12CLASS_TO_5CLASS: dict[int, int] = {
    0:  0,    # BENIGN
    1:  1,    # DrDoS_DNS       → Amplification
    2:  1,    # DrDoS_LDAP      → Amplification
    3:  1,    # DrDoS_MSSQL     → Amplification
    4:  1,    # DrDoS_NetBIOS   → Amplification
    5:  1,    # DrDoS_NTP       → Amplification
    6:  1,    # DrDoS_SNMP      → Amplification
    7:  1,    # DrDoS_SSDP      → Amplification
    8:  1,    # DrDoS_UDP       → Amplification
    9:  2,    # Syn
    10: 3,    # UDP-lag
    11: 4,    # WebDDoS
}

# Spec §4.3 — horizons in minutes
HORIZONS_MIN: tuple[int, ...] = (1, 5, 15)

# Spec §5.3 — operating thresholds per horizon
HORIZON_THRESHOLDS: dict[int, float] = {1: 0.85, 5: 0.70, 15: 0.50}

# Spec §4.5 — top-K SHAP features (kept at 5 per user directive)
TOP_K_SHAP = 5

# Coalescer window (Spec §5.3 — A&AI dedup by target_ip_prefix + 30s)
COALESCER_WINDOW_S = 30.0

# Tier-A confidence trigger (Spec §5.3 disjunctive Tier 3)
TRACK_A_CONF_T3 = 0.85
TRACK_A_CONF_T4 = 0.95


# ─────────────────────────────────────────────────────────────────────────────
# Spec-aligned output dataclasses (replaces ai_output.py once Phase 5 lands)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrackADetection:
    track:               str         # always "A_XGB"
    attack_type:         str         # one of CICDDOS_CLASSES.values()
    attack_class_id:    int          # 0..11
    confidence:         float        # 1 - P(BENIGN)
    is_attack:          bool
    class_probs:        dict         # {class_name: prob}  full 12-way
    shap_top_features:  list[str]    # top-K names by |Shapley|
    shap_values:        dict         # {feature_name: shap_value (signed)}
    explanation_text:   str          # auto-generated
    inference_ms:       float


@dataclass
class TrackBForecast:
    track:                  str         # always "B_LSTM"
    p_attack_1min:          float
    p_attack_5min:          float
    p_attack_15min:         float
    pre_position_recommended: bool
    triggered_horizon:      Optional[int]    # 1, 5, 15, or None
    perm_importance:        dict             # {var_name: importance}
    forecast_justification: str
    inference_ms:           float


@dataclass
class UnifiedAIOutput:
    """Spec §4.6 message published to `ai.detections`."""
    event_id:           str
    timestamp_utc:      str
    schema_version:     str = "3.0"
    source_ip_prefix:   Optional[str] = None
    target_ip_prefix:   Optional[str] = None
    tenant_id:          Optional[str] = None
    severity_estimate:  str = "INFO"          # INFO/MINOR/MAJOR/CRITICAL
    detection:          Optional[dict] = None
    forecast:           Optional[dict] = None
    xai:                dict = field(default_factory=dict)
    model_versions:     dict = field(default_factory=dict)


def _to_dict(payload) -> dict:
    """Serialize a dataclass to a JSON-safe dict (NumPy-aware)."""
    def _convert(o):
        if isinstance(o, dict):
            return {k: _convert(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [_convert(v) for v in o]
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, (np.integer,)):
            return int(o)
        return o
    return _convert(asdict(payload))


# ─────────────────────────────────────────────────────────────────────────────
# Drift detector (Spec §4.4 — ADWIN stub for Track A)
# ─────────────────────────────────────────────────────────────────────────────

class _ADWINStub:
    """
    Lightweight placeholder for ADWIN(δ=0.002, buffer=10k) drift detection.
    Real implementation will plug into `river.drift.ADWIN` at Phase 1 retrain.
    """
    def __init__(self, delta: float = 0.002, buffer_size: int = 10_000):
        self.delta = delta
        self.buf:   deque = deque(maxlen=buffer_size)
        self.warnings_emitted: int = 0

    def update(self, score: float) -> bool:
        self.buf.append(float(score))
        if len(self.buf) < 1_000:
            return False
        # Simple variance-shift heuristic; real ADWIN swaps in at Phase 1.
        n  = len(self.buf)
        a  = np.fromiter(self.buf, dtype=np.float32, count=n)
        h  = a[-1_000:]
        b  = a[:max(1_000, n // 2)]
        if abs(float(h.mean()) - float(b.mean())) > 0.10:
            self.warnings_emitted += 1
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Coalescer — Spec §5.3 dedup by (target_ip_prefix, 30s bucket)
# ─────────────────────────────────────────────────────────────────────────────

class PayloadCoalescer:
    """
    Merges TrackADetection and TrackBForecast events emitted around the same
    30-second bucket for the same target_ip_prefix into a UnifiedAIOutput.

    The coalescer flushes on any of:
      - Both Track A and Track B contributed to the bucket
      - Bucket age exceeds COALESCER_WINDOW_S (forced flush — partial payload)
    """

    def __init__(self, window_s: float = COALESCER_WINDOW_S):
        self.window_s = window_s
        # key: (target_ip_prefix, bucket_id) → dict with 'a','b','t0',meta
        self._buckets: dict[tuple[str, int], dict] = {}

    def _bucket_key(self, target: str, t: float) -> tuple[str, int]:
        return (target or 'unknown', int(t // self.window_s))

    def add_track_a(
        self,
        det: TrackADetection,
        *,
        source_ip_prefix: Optional[str],
        target_ip_prefix: Optional[str],
        tenant_id: Optional[str],
    ) -> Optional[UnifiedAIOutput]:
        return self._merge('a', det, source_ip_prefix, target_ip_prefix, tenant_id)

    def add_track_b(
        self,
        fc: TrackBForecast,
        *,
        source_ip_prefix: Optional[str],
        target_ip_prefix: Optional[str],
        tenant_id: Optional[str],
    ) -> Optional[UnifiedAIOutput]:
        return self._merge('b', fc, source_ip_prefix, target_ip_prefix, tenant_id)

    def _merge(self, kind, item, src, tgt, tenant) -> Optional[UnifiedAIOutput]:
        now = time.time()
        key = self._bucket_key(tgt, now)
        slot = self._buckets.setdefault(key, {
            'a': None, 'b': None, 't0': now,
            'src': src, 'tgt': tgt, 'tenant': tenant,
        })
        slot[kind] = item
        # Update late-arriving meta if missing
        slot['src']    = slot['src']    or src
        slot['tgt']    = slot['tgt']    or tgt
        slot['tenant'] = slot['tenant'] or tenant

        # Flush when both tracks present
        if slot['a'] is not None and slot['b'] is not None:
            return self._build(self._buckets.pop(key))
        return None

    def flush_stale(self) -> list[UnifiedAIOutput]:
        """Force-emit any buckets older than window_s with whatever is present."""
        now = time.time()
        stale = [k for k, s in self._buckets.items() if now - s['t0'] >= self.window_s]
        out = []
        for k in stale:
            s = self._buckets.pop(k)
            if s['a'] is not None or s['b'] is not None:
                out.append(self._build(s))
        return out

    @staticmethod
    def _severity(track_a: Optional[TrackADetection],
                  track_b: Optional[TrackBForecast]) -> str:
        conf = track_a.confidence if track_a else 0.0
        p1   = track_b.p_attack_1min  if track_b else 0.0
        if conf >= TRACK_A_CONF_T4 or p1 >= 0.95:
            return 'CRITICAL'
        if conf >= TRACK_A_CONF_T3 or p1 >= HORIZON_THRESHOLDS[1]:
            return 'MAJOR'
        if (track_b and track_b.p_attack_5min >= HORIZON_THRESHOLDS[5]):
            return 'MINOR'
        return 'INFO'

    def _build(self, slot: dict) -> UnifiedAIOutput:
        a: Optional[TrackADetection] = slot['a']
        b: Optional[TrackBForecast]  = slot['b']

        det_dict = _to_dict(a) if a is not None else None
        fc_dict  = _to_dict(b) if b is not None else None

        xai: dict = {}
        if a is not None:
            xai['shap_top_features'] = a.shap_top_features
            xai['shap_values']       = a.shap_values
            xai['explanation_text']  = a.explanation_text
        if b is not None:
            xai['perm_importance']        = b.perm_importance
            xai['forecast_justification'] = b.forecast_justification

        return UnifiedAIOutput(
            event_id          = str(uuid.uuid4()),
            timestamp_utc     = datetime.now(timezone.utc).isoformat(),
            source_ip_prefix  = slot['src'],
            target_ip_prefix  = slot['tgt'],
            tenant_id         = slot['tenant'],
            severity_estimate = self._severity(a, b),
            detection         = det_dict,
            forecast          = fc_dict,
            xai               = xai,
        )


# ─────────────────────────────────────────────────────────────────────────────
# InferenceEngine v2
# ─────────────────────────────────────────────────────────────────────────────

class InferenceEngine:
    """
    Two-track real-time inference engine.

    Public API:
        engine = InferenceEngine.load(model_dir, mode="legacy")
        det    = engine.infer_track_a(features_22, source_device_id=...)
        fc     = engine.infer_track_b(features_6,  source_device_id=...)

    The caller (Kafka runner) feeds Track A and Track B messages independently
    and uses the embedded `coalescer` to produce UnifiedAIOutput when both
    tracks' contributions for a (target_ip_prefix, 30s) bucket are ready.
    """

    def __init__(
        self,
        booster:        xgb.Booster,
        forecaster:     torch.nn.Module,
        scaler_a,
        scaler_b,
        label_to_idx:   dict,
        idx_to_label:   dict,
        mode:           str = 'legacy',
        device:         str = 'cpu',
        shap_enabled:   bool = True,
        xgb_version:    str = 'unknown',
        forecaster_version: str = 'unknown',
    ):
        if mode not in ('legacy', 'spec'):
            raise ValueError(f"mode must be 'legacy' or 'spec', got {mode!r}")

        self.booster        = booster
        self.forecaster     = forecaster
        self.scaler_a       = scaler_a
        self.scaler_b       = scaler_b
        self.label_to_idx   = label_to_idx
        self.idx_to_label   = idx_to_label
        self.mode           = mode
        self.device         = torch.device(device)
        self.shap_enabled   = shap_enabled
        self.xgb_version    = xgb_version
        self.forecaster_version = forecaster_version

        # Per-device 60-step rolling buffer for Track B
        self._buffers_b: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=TRACK_B_LOOK_BACK)
        )

        # SHAP explainer (lazy)
        self._shap_explainer = None
        self._shap_pkg_failed = False

        # Drift detection
        self.drift = _ADWINStub()

        # Latency tracking
        self._lat_a: list[float] = []
        self._lat_b: list[float] = []

        # Coalescer
        self.coalescer = PayloadCoalescer()

        self.forecaster.eval()
        logger.info(
            f"InferenceEngine v2 ready | mode={mode} | device={device} | "
            f"SHAP={'on' if shap_enabled else 'off'}"
        )

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def load(
        cls,
        model_dir:    str = './pad_onap_v3/models',
        data_dir:     str = './pad_onap_v3/processed',
        mode:         str = 'legacy',
        device:       str = 'auto',
        shap_enabled: bool = True,
    ) -> 'InferenceEngine':
        model_dir = Path(model_dir)
        data_dir  = Path(data_dir)

        if device == 'auto':
            device = 'cuda' if torch.cuda.is_available() else 'cpu'

        logger.info(f"Loading models from {model_dir} | mode={mode} | device={device}")

        # ── XGBoost (Track A) ────────────────────────────────────────────────
        xgb_candidates = [
            model_dir / 'xgboost_track_a.json',     # spec-mode artefact
            model_dir / 'xgboost_v3.json',          # legacy v3 artefact
            model_dir / 'xgboost_7class_v2.json',   # legacy v2 artefact
        ]
        xgb_path = next((p for p in xgb_candidates if p.exists()), None)
        if xgb_path is None:
            raise FileNotFoundError(
                f"No XGBoost model found in {model_dir} "
                f"(tried: {[p.name for p in xgb_candidates]})"
            )
        booster = xgb.Booster()
        booster.load_model(str(xgb_path))
        xgb_version = xgb_path.stem
        logger.info(f"  XGBoost loaded: {xgb_path.name}")

        # ── Label map ────────────────────────────────────────────────────────
        lbl_map_path = model_dir / 'xgb_label_map.json'
        if lbl_map_path.exists():
            with open(lbl_map_path) as f:
                lm = json.load(f)
            label_to_idx = {int(k): int(v) for k, v in lm['label_to_idx'].items()}
            idx_to_label = {int(k): int(v) for k, v in lm['idx_to_label'].items()}
        else:
            # identity over 12 classes
            label_to_idx = {i: i for i in range(N_CICDDOS_CLASSES)}
            idx_to_label = {i: i for i in range(N_CICDDOS_CLASSES)}
            logger.warning("  No xgb_label_map.json — using identity over 12 classes")

        # ── Track B forecaster ───────────────────────────────────────────────
        tf_candidates = [
            model_dir / 'lstm_track_b.pt',          # spec-mode artefact
            model_dir / 'transformer_v3.pt',        # legacy v3 artefact
            model_dir / 'transformer_lstm_v2.pth',  # legacy v2 artefact
        ]
        tf_path = next((p for p in tf_candidates if p.exists()), None)
        if tf_path is None:
            raise FileNotFoundError(
                f"No forecaster model found in {model_dir} "
                f"(tried: {[p.name for p in tf_candidates]})"
            )

        # Load HP from sidecar if present
        hp = {}
        for meta_name in ('tf_best_config.json', 'lstm_track_b_config.json'):
            meta_path = model_dir / meta_name
            if meta_path.exists():
                with open(meta_path) as f:
                    meta = json.load(f)
                hp = meta.get('best_hp', meta)
                break

        if mode == 'spec' and tf_path.name.startswith('lstm_track_b'):
            # Native stacked LSTM (Spec §4.3) — defined locally; Phase 2 will
            # promote this to its own module.
            forecaster = _StackedLSTMForecaster(
                input_dim   = N_TRACK_B_FEATURES,
                hidden_l1   = hp.get('hidden_l1', 100),
                hidden_l2   = hp.get('hidden_l2', 100),
                hidden_l3   = hp.get('hidden_l3', 50),
                fc_hidden   = hp.get('fc_hidden', 25),
                n_horizons  = len(HORIZONS_MIN),
                dropout     = hp.get('dropout', 0.2),
            )
        else:
            # Legacy bridge — re-use Transformer+LSTM (12-step × 17-feature input,
            # 4-horizon output {30s,60s,90s,120s}).
            forecaster = TransformerLSTMForecaster(
                input_dim   = LEGACY_N_FEATURES,
                hidden_dim  = hp.get('hidden_dim',  64),
                num_heads   = hp.get('num_heads',    4),
                num_layers  = hp.get('num_layers',   2),
                lstm_hidden = hp.get('lstm_hidden', 128),
                lstm_layers = hp.get('lstm_layers',  2),
                dropout     = 0.0,
            )

        state_dict = torch.load(str(tf_path), map_location=device, weights_only=True)
        try:
            forecaster.load_state_dict(state_dict)
        except RuntimeError as e:
            logger.warning(
                f"Forecaster state_dict mismatch ({e}); loading with strict=False"
            )
            forecaster.load_state_dict(state_dict, strict=False)
        forecaster = forecaster.to(device).eval()
        forecaster_version = tf_path.stem
        logger.info(f"  Forecaster loaded: {tf_path.name}")

        # ── Scalers ──────────────────────────────────────────────────────────
        scaler_a_path = next(
            (p for p in (model_dir / 'scaler_track_a.pkl',
                         model_dir / 'scaler.pkl',
                         data_dir  / 'scaler.pkl') if p.exists()),
            None,
        )
        if scaler_a_path is None:
            raise FileNotFoundError("Track A scaler not found")
        with open(scaler_a_path, 'rb') as f:
            scaler_a = pickle.load(f)
        logger.info(f"  Track A scaler: {scaler_a_path.name}")

        scaler_b_path = next(
            (p for p in (model_dir / 'scaler_track_b_minmax.pkl',
                         model_dir / 'scaler_track_b.pkl') if p.exists()),
            None,
        )
        if scaler_b_path is not None:
            with open(scaler_b_path, 'rb') as f:
                scaler_b = pickle.load(f)
            logger.info(f"  Track B scaler: {scaler_b_path.name}")
        else:
            scaler_b = None
            logger.warning(
                "  Track B scaler missing — using identity in legacy mode "
                "(Track B path will reuse Track A scaler over a 17-dim adapter)"
            )

        engine = cls(
            booster        = booster,
            forecaster     = forecaster,
            scaler_a       = scaler_a,
            scaler_b       = scaler_b,
            label_to_idx   = label_to_idx,
            idx_to_label   = idx_to_label,
            mode           = mode,
            device         = device,
            shap_enabled   = shap_enabled,
            xgb_version    = xgb_version,
            forecaster_version = forecaster_version,
        )
        cls._warmup(engine)
        return engine

    # ── Warm-up ──────────────────────────────────────────────────────────────

    @classmethod
    def _warmup(cls, engine: 'InferenceEngine') -> None:
        logger.info("  Running warm-up passes (Track A x2, Track B x2)...")
        dummy_a = np.zeros(N_TRACK_A_FEATURES, dtype=np.float32)
        dummy_b = np.zeros(N_TRACK_B_FEATURES, dtype=np.float32)
        for _ in range(2):
            engine.infer_track_a(dummy_a, source_device_id='__warmup__')
        for _ in range(2):
            engine.infer_track_b(dummy_b, source_device_id='__warmup__')
        # Reset state polluted by warm-up
        engine._buffers_b.clear()
        engine._lat_a.clear()
        engine._lat_b.clear()
        engine.coalescer = PayloadCoalescer()
        logger.info("  Warm-up complete.")

    # ─────────────────────────────────────────────────────────────────────────
    # Track A path — XGBoost classifier
    # ─────────────────────────────────────────────────────────────────────────

    def infer_track_a(
        self,
        features_22: np.ndarray,
        *,
        source_device_id: str = 'unknown',
    ) -> TrackADetection:
        """
        Run the Track A classifier on a 22-dim flow feature vector.

        Args:
            features_22: shape (22,) — order must match TRACK_A_FEATURES
        """
        if features_22.shape[0] != N_TRACK_A_FEATURES:
            raise ValueError(
                f"Track A expects {N_TRACK_A_FEATURES} features, "
                f"got shape {features_22.shape}"
            )
        t0 = time.perf_counter()

        # Adapt to the loaded model's expected feature dim
        x_in = self._adapt_track_a_input(features_22)

        # Scale
        x_scaled = self.scaler_a.transform(x_in.reshape(1, -1)).astype(np.float32)

        # XGBoost predict
        dm  = xgb.DMatrix(x_scaled)
        raw = self.booster.predict(dm)
        if raw.ndim == 1:
            raw = raw.reshape(1, -1)
        probs_remapped = raw[0]

        # Project remapped → canonical 12-class space (Spec §4.6 attack_class_id ∈ [0,11])
        class_probs_12 = self._remap_to_12class(probs_remapped)

        best_id  = int(np.argmax(class_probs_12))
        best_p   = float(class_probs_12[best_id])
        attack_p = float(1.0 - class_probs_12[0])    # 1 − P(BENIGN) — Spec §4.2
        is_attack = best_id != 0

        # SHAP top-K
        shap_top_names: list[str] = []
        shap_values:    dict      = {}
        if self.shap_enabled:
            shap_top_names, shap_values = self._compute_shap(x_scaled[0], best_id)

        explanation_text = self._build_explanation(
            attack_type=CICDDOS_CLASSES[best_id],
            shap_values=shap_values,
        )

        # Drift hook
        if self.drift.update(attack_p):
            logger.warning(
                f"[Drift] ADWIN stub flagged drift after "
                f"{self.drift.warnings_emitted} alarms"
            )

        ms = (time.perf_counter() - t0) * 1000.0
        self._lat_a.append(ms)

        det = TrackADetection(
            track             = 'A_XGB',
            attack_type       = CICDDOS_CLASSES[best_id],
            attack_class_id   = best_id,
            confidence        = attack_p,         # P(attack) per Spec §4.2 mapping
            is_attack         = is_attack,
            class_probs       = {
                CICDDOS_CLASSES[i]: float(class_probs_12[i])
                for i in range(N_CICDDOS_CLASSES)
            },
            shap_top_features = shap_top_names,
            shap_values       = shap_values,
            explanation_text  = explanation_text,
            inference_ms      = ms,
        )
        return det

    def _adapt_track_a_input(self, features_22: np.ndarray) -> np.ndarray:
        """
        Bridge the 22-dim flow vector to whatever feature dimension the loaded
        XGBoost expects.

        spec mode    : returns the 22-dim vector unchanged
        legacy mode  : maps the 22 CICFlowMeter-style features to the 17-dim
                       legacy schema by deriving rate-style features that match
                       the legacy scaler's training distribution.

                       Legacy 17-feature order (training-time):
                         [pkt_rate, byte_rate,
                          src_ip_entropy, dst_ip_entropy,
                          src_port_entropy, dst_port_entropy,
                          proto_dist_tcp, proto_dist_udp, proto_dist_icmp,
                          syn_ratio, fin_ratio,
                          avg_pkt_size, pkt_size_std,
                          new_flows_rate, flow_duration_mean,
                          inter_arrival_mean, inter_arrival_std]

                       Bridge rules (best-effort; entropy/ratio fields default
                       to 0 — they will be reconstructed properly once Phase 1
                       retrains XGBoost on the native 22-dim schema):
                         pkt_rate          ← flow_packets_per_sec
                         byte_rate         ← flow_bytes_per_sec
                         src/dst_ip_entropy: 0 (not derivable from 22-dim flow set)
                         src/dst_port_entropy: 0
                         proto_dist_tcp    ← 1 if protocol==6 else 0
                         proto_dist_udp    ← 1 if protocol==17 else 0
                         proto_dist_icmp   ← 1 if protocol==1 else 0
                         syn_ratio         ← syn_flag_count / total_pkts
                         fin_ratio         ← 0
                         avg_pkt_size      ← fwd_packet_length_mean
                         pkt_size_std      ← 0
                         new_flows_rate    ← 0
                         flow_duration_mean← flow_duration
                         inter_arrival_mean← flow_iat_mean
                         inter_arrival_std ← flow_iat_std
        """
        if self.mode == 'spec':
            return features_22.astype(np.float32)

        f = {name: float(features_22[i]) for i, name in enumerate(TRACK_A_FEATURES)}
        total_pkts = f['total_fwd_packets'] + f['total_bwd_packets']
        proto      = int(f['protocol'])

        legacy_17 = np.array([
            f['flow_packets_per_sec'],
            f['flow_bytes_per_sec'],
            0.0, 0.0,                                   # src/dst_ip_entropy
            0.0, 0.0,                                   # src/dst_port_entropy
            1.0 if proto == 6  else 0.0,
            1.0 if proto == 17 else 0.0,
            1.0 if proto == 1  else 0.0,
            (f['syn_flag_count'] / total_pkts) if total_pkts > 0 else 0.0,
            0.0,                                        # fin_ratio
            f['fwd_packet_length_mean'],
            0.0,                                        # pkt_size_std
            0.0,                                        # new_flows_rate
            f['flow_duration'],
            f['flow_iat_mean'],
            f['flow_iat_std'],
        ], dtype=np.float32)
        return legacy_17

    def _remap_to_12class(self, probs_remapped: np.ndarray) -> np.ndarray:
        """
        Map model output to the canonical 5-class P3 hybrid taxonomy.
        (Name kept as `_remap_to_12class` for backwards compatibility with any
        external caller; the return shape is now N_CICDDOS_CLASSES=5.)

        spec mode (P3, 5-class native):
          The booster already emits a 5-vector; `idx_to_label` is the identity
          map from `xgb_label_map.json`, so we simply scatter into `out`.

        spec mode (legacy 12-class booster on disk):
          If the loaded model still has `n_classes=12` (e.g. an earlier v3
          training run), each old class index is folded into its 5-class
          parent through `LEGACY_12CLASS_TO_5CLASS`.

        legacy mode (7-class booster on disk):
          Provisional bridge from the v2 7-class schema
          [Normal, UDP_Flood, SYN_Flood, HTTP_Flood, ICMP_Flood, Amplification, Slow_rate]
          into the 5-class P3 space.  Mapping:
            Normal        → BENIGN          (0)
            UDP_Flood     → Amplification   (1)  (UDP-based reflection-like)
            SYN_Flood     → Syn             (2)
            HTTP_Flood    → WebDDoS         (4)
            ICMP_Flood    → UDP-lag         (3)  (closest exploitation proxy)
            Amplification → Amplification   (1)
            Slow_rate     → WebDDoS         (4)
        """
        out = np.zeros(N_CICDDOS_CLASSES, dtype=np.float32)

        if self.mode == 'spec':
            n = len(probs_remapped)
            for remapped_idx, orig in self.idx_to_label.items():
                p = float(probs_remapped[remapped_idx]) if remapped_idx < n else 0.0
                orig = int(orig)
                if 0 <= orig < N_CICDDOS_CLASSES:
                    # Native 5-class output — direct scatter
                    out[orig] += p
                elif orig in LEGACY_12CLASS_TO_5CLASS:
                    # 12-class model loaded under spec mode — fold into 5-class
                    out[LEGACY_12CLASS_TO_5CLASS[orig]] += p
            s = out.sum()
            return out / s if s > 0 else out

        # ── Legacy 7-class booster → 5-class P3 (provisional bridge) ──────
        legacy_7 = np.zeros(7, dtype=np.float32)
        for remapped_idx, orig in self.idx_to_label.items():
            if 0 <= int(orig) < 7 and remapped_idx < len(probs_remapped):
                legacy_7[int(orig)] = float(probs_remapped[remapped_idx])
        out[0] = legacy_7[0]                                  # BENIGN
        out[1] = legacy_7[1] + legacy_7[5]                    # Amplification ← UDP_Flood + Amplification
        out[2] = legacy_7[2]                                  # Syn           ← SYN_Flood
        out[3] = legacy_7[4]                                  # UDP-lag       ← ICMP_Flood (proxy)
        out[4] = legacy_7[3] + legacy_7[6]                    # WebDDoS       ← HTTP_Flood + Slow_rate
        s = out.sum()
        return out / s if s > 0 else out

    def _compute_shap(self, x_scaled: np.ndarray, predicted_class_id: int):
        """
        Returns (top_K_feature_names, {feature_name: signed_shap_value}).

        Strategy chain:
          1. XGBoost native pred_contribs=True (fastest, no extra deps)
          2. shap.TreeExplainer  (used as cross-check / fallback)
          3. booster.get_score(gain) (static fallback — no per-sample values)

        Feature names are taken from the model's input space (22-dim spec, or
        17-dim legacy bridge).
        """
        if self.mode == 'spec':
            feature_names = TRACK_A_FEATURES
            n_feat = N_TRACK_A_FEATURES
        else:
            feature_names = [
                'pkt_rate', 'byte_rate',
                'src_ip_entropy', 'dst_ip_entropy',
                'src_port_entropy', 'dst_port_entropy',
                'proto_dist_tcp', 'proto_dist_udp', 'proto_dist_icmp',
                'syn_ratio', 'fin_ratio',
                'avg_pkt_size', 'pkt_size_std',
                'new_flows_rate', 'flow_duration_mean',
                'inter_arrival_mean', 'inter_arrival_std',
            ]
            n_feat = len(feature_names)

        top_k = min(TOP_K_SHAP, n_feat)
        remapped_cls = self.label_to_idx.get(predicted_class_id, 0)

        # ── Method 1: native pred_contribs ───────────────────────────────────
        try:
            dm       = xgb.DMatrix(x_scaled.reshape(1, -1))
            contribs = np.array(self.booster.predict(dm, pred_contribs=True))
            signed   = self._extract_contribs(contribs, n_feat, remapped_cls)
            if signed is not None and np.abs(signed).sum() > 0:
                return self._top_signed(signed, feature_names, top_k)
        except Exception as e:
            logger.debug(f"pred_contribs failed: {e}")

        # ── Method 2: shap.TreeExplainer ─────────────────────────────────────
        if not self._shap_pkg_failed:
            try:
                if self._shap_explainer is None:
                    import shap as _shap
                    self._shap_explainer = _shap.TreeExplainer(self.booster)
                sv = np.array(self._shap_explainer(x_scaled.reshape(1, -1)).values)
                if sv.ndim == 3:
                    rc = min(remapped_cls, sv.shape[2] - 1)
                    signed = sv[0, :n_feat, rc]
                elif sv.ndim == 2:
                    signed = sv[0, :n_feat]
                else:
                    signed = sv.flatten()[:n_feat]
                if np.abs(signed).sum() > 0:
                    return self._top_signed(signed, feature_names, top_k)
            except Exception as e:
                logger.warning(f"shap.TreeExplainer failed: {e}")
                self._shap_pkg_failed = True

        # ── Method 3: gain-based static fallback ─────────────────────────────
        try:
            scores = self.booster.get_score(importance_type='gain')
            if scores:
                top = sorted(scores.items(), key=lambda kv: -kv[1])[:top_k]
                total = sum(v for _, v in top) or 1.0
                names_out = [k for k, _ in top]
                vals_out  = {k: round(v / total, 6) for k, v in top}
                return names_out, vals_out
        except Exception:
            pass

        return [], {}

    @staticmethod
    def _extract_contribs(arr: np.ndarray, n_feat: int, remapped_cls: int):
        """Pull the per-feature contribution vector for `remapped_cls`."""
        if arr.ndim == 3:
            # (1, n_classes, n_feat+1)
            n_cls = arr.shape[1]
            rc    = min(remapped_cls, n_cls - 1)
            return arr[0, rc, :n_feat]
        if arr.ndim == 2:
            flat = arr.flatten()
            stride = n_feat + 1
            n_cls = max(1, len(flat) // stride)
            if n_cls > 1:
                rc = min(remapped_cls, n_cls - 1)
                return flat[rc * stride: rc * stride + n_feat]
            return flat[:n_feat]
        return arr.flatten()[:n_feat]

    @staticmethod
    def _top_signed(signed: np.ndarray, feature_names: list[str], top_k: int):
        order = np.argsort(np.abs(signed))[-top_k:][::-1]
        names = [feature_names[i] for i in order]
        vals  = {feature_names[i]: float(signed[i]) for i in order}
        return names, vals

    @staticmethod
    def _build_explanation(*, attack_type: str, shap_values: dict) -> str:
        """Spec §4.5 — auto-generated explanation_text."""
        if not shap_values:
            return f"Predicted {attack_type}; no SHAP attribution available."
        parts = []
        for name, val in list(shap_values.items())[:3]:
            direction = '+' if val >= 0 else '-'
            parts.append(f"{direction}{abs(val):.3f} {name}")
        joined = " and ".join(parts)
        return f"Predicted {attack_type} because {joined}"

    # ─────────────────────────────────────────────────────────────────────────
    # Track B path — Multi-horizon forecaster
    # ─────────────────────────────────────────────────────────────────────────

    def infer_track_b(
        self,
        features_6: np.ndarray,
        *,
        source_device_id: str = 'unknown',
    ) -> TrackBForecast:
        """
        Run Track B forecaster after pushing the 6-dim aggregate vector into
        the per-device 60-step rolling buffer.
        """
        if features_6.shape[0] != N_TRACK_B_FEATURES:
            raise ValueError(
                f"Track B expects {N_TRACK_B_FEATURES} features, "
                f"got shape {features_6.shape}"
            )
        t0 = time.perf_counter()

        # Scale (Min-Max if available; else identity in legacy mode)
        if self.scaler_b is not None:
            x_scaled = self.scaler_b.transform(features_6.reshape(1, -1)).flatten()
        else:
            x_scaled = features_6.astype(np.float32)

        # Push to per-device buffer
        buf = self._buffers_b[source_device_id]
        buf.append(x_scaled.astype(np.float32))

        # Run forecaster
        p1, p5, p15 = self._forecast_horizons(buf)

        # Trigger logic — first horizon (longest first) crossing its threshold
        triggered_horizon: Optional[int] = None
        if p15 >= HORIZON_THRESHOLDS[15]:
            triggered_horizon = 15
        if p5 >= HORIZON_THRESHOLDS[5]:
            triggered_horizon = 5
        if p1 >= HORIZON_THRESHOLDS[1]:
            triggered_horizon = 1

        pre_position = (triggered_horizon is not None and triggered_horizon >= 5)

        # Permutation-importance (cheap variant — single-shuffle per variable)
        perm_imp = self._perm_importance(buf) if len(buf) == TRACK_B_LOOK_BACK else {}
        justification = self._build_forecast_justification(p1, p5, p15, perm_imp)

        ms = (time.perf_counter() - t0) * 1000.0
        self._lat_b.append(ms)

        return TrackBForecast(
            track                  = 'B_LSTM',
            p_attack_1min          = float(p1),
            p_attack_5min          = float(p5),
            p_attack_15min         = float(p15),
            pre_position_recommended = pre_position,
            triggered_horizon      = triggered_horizon,
            perm_importance        = perm_imp,
            forecast_justification = justification,
            inference_ms           = ms,
        )

    def _forecast_horizons(self, buf: deque) -> tuple[float, float, float]:
        """
        Run the loaded forecaster and return (P(t+1min), P(t+5min), P(t+15min)).

        spec mode    : 60-step × 6-dim → 3-head sigmoid (direct)
        legacy mode  : the on-disk model is Transformer+LSTM with input
                       (12, 17) and 4-horizon output (30s/60s/90s/120s).
                       We adapt by:
                         (1) reusing the most-recent 12 buffer slots and
                             zero-padding 6→17 features (channels 6..16 = 0)
                         (2) projecting the 4 horizon heads to {1,5,15} via:
                                P1  ← p120s   (longest near-term head)
                                P5  ← p120s · 0.85  (linear decay extrapolation)
                                P15 ← p120s · 0.50
                       This is a transitional bridge; Phase 2 replaces it.
        """
        if isinstance(self.forecaster, TransformerLSTMForecaster) or self.mode == 'legacy':
            return self._forecast_legacy(buf)
        return self._forecast_spec(buf)

    def _forecast_spec(self, buf: deque) -> tuple[float, float, float]:
        if len(buf) < TRACK_B_LOOK_BACK:
            return 0.0, 0.0, 0.0
        seq = np.stack(list(buf), axis=0)            # (60, 6)
        x   = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.forecaster(x)               # (1, 3)
            probs  = torch.sigmoid(logits)[0].cpu().numpy()
        return float(probs[0]), float(probs[1]), float(probs[2])

    def _forecast_legacy(self, buf: deque) -> tuple[float, float, float]:
        if len(buf) < LEGACY_N_TIMESTEPS:
            return 0.0, 0.0, 0.0
        recent = list(buf)[-LEGACY_N_TIMESTEPS:]      # last 12 timesteps
        seq6   = np.stack(recent, axis=0)             # (12, 6)
        # Zero-pad 6 → 17 features for legacy model compatibility
        seq17  = np.zeros((LEGACY_N_TIMESTEPS, LEGACY_N_FEATURES), dtype=np.float32)
        seq17[:, :N_TRACK_B_FEATURES] = seq6
        x = torch.tensor(seq17, dtype=torch.float32).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.forecaster(x)               # (1, 4) — legacy 4-horizon
            probs  = torch.sigmoid(logits)[0].cpu().numpy()
        # Project 4 legacy horizons (30s/60s/90s/120s) → spec horizons (1/5/15 min)
        p_120 = float(probs[3])
        p1    = p_120
        p5    = p_120 * 0.85
        p15   = p_120 * 0.50
        return p1, p5, p15

    def _perm_importance(self, buf: deque) -> dict:
        """
        One-shuffle-per-variable permutation importance over the current buffer.
        Cost: 6 extra forward passes (≈ negligible vs. inference).
        """
        if len(buf) < min(TRACK_B_LOOK_BACK, LEGACY_N_TIMESTEPS):
            return {}

        baseline = self._forecast_horizons(buf)
        baseline_score = baseline[0] + baseline[1] + baseline[2]

        out: dict = {}
        rng = np.random.default_rng(seed=42)
        for i, var_name in enumerate(TRACK_B_FEATURES):
            shuffled = list(buf)
            col = np.array([row[i] for row in shuffled], dtype=np.float32)
            rng.shuffle(col)
            for k in range(len(shuffled)):
                row = shuffled[k].copy()
                row[i] = col[k]
                shuffled[k] = row
            shuffled_buf = deque(shuffled, maxlen=buf.maxlen)
            p1, p5, p15  = self._forecast_horizons(shuffled_buf)
            out[var_name] = float(abs(baseline_score - (p1 + p5 + p15)))

        # Normalize so values sum to 1 (relative contribution)
        s = sum(out.values()) or 1.0
        return {k: round(v / s, 6) for k, v in out.items()}

    @staticmethod
    def _build_forecast_justification(p1, p5, p15, perm_imp: dict) -> str:
        if not perm_imp:
            return (f"Forecast P(t+1)={p1:.3f}, P(t+5)={p5:.3f}, P(t+15)={p15:.3f}; "
                    f"insufficient history for permutation importance.")
        top = sorted(perm_imp.items(), key=lambda kv: -kv[1])[:3]
        var_text = ", ".join(f"{n} ({v:.2f})" for n, v in top)
        return (f"Forecast P(t+1)={p1:.3f}, P(t+5)={p5:.3f}, P(t+15)={p15:.3f}; "
                f"top drivers: {var_text}")

    # ─────────────────────────────────────────────────────────────────────────
    # Diagnostics
    # ─────────────────────────────────────────────────────────────────────────

    def latency_summary(self) -> dict:
        def pct(a):
            if not a:
                return {'p50': 0.0, 'p95': 0.0, 'p99': 0.0}
            arr = np.array(a)
            return {
                'p50': float(np.percentile(arr, 50)),
                'p95': float(np.percentile(arr, 95)),
                'p99': float(np.percentile(arr, 99)),
            }
        return {
            'track_a_ms': pct(self._lat_a),
            'track_b_ms': pct(self._lat_b),
            'n_a': len(self._lat_a),
            'n_b': len(self._lat_b),
        }

    def reset_buffers(self):
        self._buffers_b.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Spec-mode native forecaster (Spec §4.3 stacked LSTM)
# Lives here for now; Phase 2 promotes it to its own module.
# ─────────────────────────────────────────────────────────────────────────────

class _StackedLSTMForecaster(torch.nn.Module):
    """
    Stacked Multivariate LSTM Multi-Horizon Forecaster (Spec §4.3).

    Input  : (batch, 60, 6)
    Output : (batch, 3) raw logits → sigmoid at inference

    The state_dict key layout intentionally matches the `LSTMForecaster`
    class in `notebooks/ddos-train-v4.ipynb` (lstm1/lstm2/lstm3 + a single
    `dropout` module + fc1/fc2) so that the notebook's `lstm_track_b.pt`
    checkpoint loads here with `strict=True`.
    """
    def __init__(self, input_dim=6, hidden_l1=100, hidden_l2=100,
                 hidden_l3=50, fc_hidden=25, n_horizons=3, dropout=0.2):
        super().__init__()
        self.lstm1   = torch.nn.LSTM(input_dim, hidden_l1, batch_first=True)
        self.lstm2   = torch.nn.LSTM(hidden_l1, hidden_l2, batch_first=True)
        self.lstm3   = torch.nn.LSTM(hidden_l2, hidden_l3, batch_first=True)
        self.dropout = torch.nn.Dropout(dropout)
        self.fc1     = torch.nn.Linear(hidden_l3, fc_hidden)
        self.fc2     = torch.nn.Linear(fc_hidden, n_horizons)

    def forward(self, x):
        h, _ = self.lstm1(x); h = self.dropout(h)
        h, _ = self.lstm2(h); h = self.dropout(h)
        h, _ = self.lstm3(h)
        h = self.dropout(h[:, -1, :])
        h = torch.relu(self.fc1(h))
        return self.fc2(h)


# ─────────────────────────────────────────────────────────────────────────────
# Kafka runner — subscribes to both feature topics and publishes ai.detections
# ─────────────────────────────────────────────────────────────────────────────

KAFKA_TOPIC_FLOW = 'telemetry.features.flow'
KAFKA_TOPIC_TS   = 'telemetry.features.timeseries'
KAFKA_TOPIC_OUT  = 'ai.detections'

# Legacy topic names (kept subscribed for backward compat with old simulators)
KAFKA_TOPIC_FLOW_LEGACY = 'pad.telemetry.features'
KAFKA_TOPIC_OUT_LEGACY  = 'pad.ai.detections'


def run_kafka(
    *,
    broker:        str = 'localhost:9092',
    model_dir:     str = './pad_onap_v3/models',
    data_dir:      str = './pad_onap_v3/processed',
    mode:          str = 'legacy',
    shap_enabled:  bool = True,
    group_id:      str = 'pad-inference-engine',
    out_path:      Optional[str] = None,
):
    """
    Subscribe to telemetry.features.flow + telemetry.features.timeseries,
    run dual-track inference, and publish coalesced UnifiedAIOutput payloads to
    `ai.detections`.
    """
    from kafka import KafkaConsumer, KafkaProducer

    engine = InferenceEngine.load(
        model_dir    = model_dir,
        data_dir     = data_dir,
        mode         = mode,
        shap_enabled = shap_enabled,
    )

    consumer = KafkaConsumer(
        KAFKA_TOPIC_FLOW, KAFKA_TOPIC_TS, KAFKA_TOPIC_FLOW_LEGACY,
        bootstrap_servers=[broker],
        group_id=group_id,
        auto_offset_reset='latest',
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        consumer_timeout_ms=300,
    )
    producer = KafkaProducer(
        bootstrap_servers=[broker],
        key_serializer=lambda k: k.encode('utf-8') if isinstance(k, str) else k,
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        acks=1, linger_ms=20, retries=3,
    )

    fout = open(out_path, 'a') if out_path else None
    logger.info(f"Inference Kafka runner online | publishing to {KAFKA_TOPIC_OUT}")

    try:
        while True:
            try:
                for msg in consumer:
                    payload = msg.value or {}
                    feats   = payload.get('features') or {}
                    src_dev = payload.get('source_device_id') or 'unknown'
                    src_ip  = payload.get('source_ip_prefix')
                    tgt_ip  = payload.get('target_ip_prefix')
                    tenant  = payload.get('tenant_id')
                    track   = payload.get('track', '').upper()

                    if msg.topic in (KAFKA_TOPIC_FLOW, KAFKA_TOPIC_FLOW_LEGACY) or track == 'A':
                        # Track A — 22-dim flow features
                        vec = _vector_from_dict(feats, TRACK_A_FEATURES)
                        det = engine.infer_track_a(vec, source_device_id=src_dev)
                        unified = engine.coalescer.add_track_a(
                            det,
                            source_ip_prefix=src_ip,
                            target_ip_prefix=tgt_ip,
                            tenant_id=tenant,
                        )
                    elif msg.topic == KAFKA_TOPIC_TS or track == 'B':
                        # Track B — 6-dim aggregated features
                        vec = _vector_from_dict(feats, TRACK_B_FEATURES)
                        fc  = engine.infer_track_b(vec, source_device_id=src_dev)
                        unified = engine.coalescer.add_track_b(
                            fc,
                            source_ip_prefix=src_ip,
                            target_ip_prefix=tgt_ip,
                            tenant_id=tenant,
                        )
                    else:
                        continue

                    if unified is not None:
                        _publish(producer, unified, fout)
            except StopIteration:
                pass

            # Force-flush stale buckets (ensures Track-A-only or Track-B-only
            # events still reach M3 within COALESCER_WINDOW_S)
            for stale in engine.coalescer.flush_stale():
                _publish(producer, stale, fout)
    finally:
        try:
            producer.flush(timeout=5); producer.close()
        except Exception:
            pass
        try:
            consumer.close()
        except Exception:
            pass
        if fout:
            fout.close()


def _vector_from_dict(feats: dict, names: list[str]) -> np.ndarray:
    return np.array([float(feats.get(n, 0.0)) for n in names], dtype=np.float32)


def _publish(producer, unified: UnifiedAIOutput, fout) -> None:
    body = _to_dict(unified)
    key  = unified.target_ip_prefix or 'unknown'
    try:
        producer.send(KAFKA_TOPIC_OUT,        key=key, value=body)
        producer.send(KAFKA_TOPIC_OUT_LEGACY, key=key, value=body)
        producer.flush(timeout=2)
    except Exception as e:
        logger.error(f"publish to {KAFKA_TOPIC_OUT} failed: {e}")
    if fout is not None:
        fout.write(json.dumps(body) + '\n'); fout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='M2 Inference Engine v2')
    parser.add_argument('--broker',      default='localhost:9092')
    parser.add_argument('--model-dir',   default='./pad_onap_v3/models')
    parser.add_argument('--data-dir',    default='./pad_onap_v3/processed')
    parser.add_argument('--mode',        choices=('legacy', 'spec'), default='legacy')
    parser.add_argument('--no-shap',     action='store_true')
    parser.add_argument('--group-id',    default='pad-inference-engine')
    parser.add_argument('--out',         default=None,
                        help='Optional JSONL path to mirror published payloads')
    args = parser.parse_args()

    run_kafka(
        broker       = args.broker,
        model_dir    = args.model_dir,
        data_dir     = args.data_dir,
        mode         = args.mode,
        shap_enabled = not args.no_shap,
        group_id     = args.group_id,
        out_path     = args.out,
    )

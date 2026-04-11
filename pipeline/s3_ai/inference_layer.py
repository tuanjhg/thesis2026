"""
S3-AI Inference Layer — Real-time Scoring Pipeline (Spec-aligned §4.3–4.6)

Luồng:
  feature_vector (17,) từ Flink
      → StandardScaler.transform()
      → XGBoost Booster  → 7-class probs + SHAP top-5
      → Rolling buffer [12 timesteps]
      → Transformer+LSTM → [P(t+30s), P(t+60s), P(t+90s), P(t+120s)]
      → ai_output.build_output() → AIOutputPayload JSON → S4

Thiết kế:
  - Stateful: giữ rolling buffer 12 timesteps trong memory
  - Stateless từ bên ngoài: mỗi lần gọi infer() trả về 1 payload hoàn chỉnh
  - Thread-safe cho single-threaded Flink operator
  - Latency target: P99 < 10ms (XGBoost) + < 8ms (Transformer) = < 18ms tổng
"""

import time
import json
import pickle
import logging
import warnings
import sys
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb
import torch

# Ensure project root on sys.path for both script and module usage
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s3_ai.transformer_lstm import TransformerLSTMForecaster, N_TIMESTEPS, N_FEATURES
from pipeline.s3_ai.ai_output import build_output, payload_to_dict, AIOutputPayload

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    'pkt_rate', 'byte_rate', 'src_ip_entropy', 'dst_ip_entropy',
    'src_port_entropy', 'dst_port_entropy', 'proto_dist_tcp',
    'proto_dist_udp', 'proto_dist_icmp', 'syn_ratio', 'fin_ratio',
    'avg_pkt_size', 'pkt_size_std', 'new_flows_rate',
    'flow_duration_mean', 'inter_arrival_mean', 'inter_arrival_std',
]
CLASS_NAMES = {
    0: 'Normal', 1: 'UDP_Flood', 2: 'SYN_Flood', 3: 'HTTP_Flood',
    4: 'ICMP_Flood', 5: 'Amplification', 6: 'Slow_rate',
}
N_CLASSES    = 7
TOP_K_SHAP   = 5
SHAP_SAMPLE  = 1          # số samples để tính SHAP per inference (1 = fast)


class InferenceEngine:
    """
    Real-time S3-AI inference engine.

    Usage:
        engine = InferenceEngine.load()
        for window in flink_stream:
            payload = engine.infer(window.features_17)
            s4.send(payload_to_dict(payload))
    """

    def __init__(
        self,
        booster:      xgb.Booster,
        transformer:  TransformerLSTMForecaster,
        scaler,
        label_to_idx: dict,
        idx_to_label: dict,
        device:       str = 'cpu',
        shap_enabled: bool = True,
    ):
        self.booster      = booster
        self.transformer  = transformer
        self.scaler       = scaler
        self.label_to_idx = label_to_idx
        self.idx_to_label = idx_to_label
        self.device       = torch.device(device)
        self.shap_enabled = shap_enabled

        # Stateful rolling buffer (12 scaled feature vectors)
        self._buffer: deque = deque(maxlen=N_TIMESTEPS)
        self._window_id: int = 0

        # Lazy SHAP explainer (initialized on first infer call)
        self._shap_explainer = None

        # Latency tracking
        self._latencies_xgb: list = []
        self._latencies_transformer: list = []

        self.transformer.eval()
        logger.info(f"InferenceEngine ready | device={device} | SHAP={shap_enabled}")

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def load(
        cls,
        model_dir:  str = './pad_onap_v3/models',
        data_dir:   str = './pad_onap_v3/processed',
        device:     str = 'auto',
        shap_enabled: bool = True,
    ) -> 'InferenceEngine':
        """
        Load all model artifacts and return a ready InferenceEngine.

        Args:
            model_dir:    directory containing xgboost_7class_v2.json and transformer_lstm_v2.pth
            data_dir:     directory containing scaler.pkl
            device:       'auto' | 'cuda' | 'cpu'
            shap_enabled: compute SHAP values per inference (adds ~1-2ms)
        """
        model_dir = Path(model_dir)
        data_dir  = Path(data_dir)

        if device == 'auto':
            device = 'cuda' if torch.cuda.is_available() else 'cpu'

        logger.info(f"Loading models from {model_dir} | device={device}")

        # ── XGBoost — support v2 and v3 filenames ────────────────────────────
        xgb_candidates = [
            model_dir / 'xgboost_v3.json',          # Kaggle notebook output
            model_dir / 'xgboost_7class_v2.json',   # legacy v2
        ]
        xgb_path = next((p for p in xgb_candidates if p.exists()), None)
        if xgb_path is None:
            raise FileNotFoundError(f"XGBoost model not found in {model_dir}. "
                                    f"Expected: {[p.name for p in xgb_candidates]}")
        booster = xgb.Booster()
        booster.load_model(str(xgb_path))
        logger.info(f"  ✓ XGBoost loaded: {xgb_path}")

        # ── Label map — prefer xgb_label_map.json (Kaggle), fallback y_train.npy ──
        label_to_idx, idx_to_label = {}, {}
        lbl_map_path = model_dir / 'xgb_label_map.json'
        y_train_path = Path(data_dir) / 'y_train.npy'

        if lbl_map_path.exists():
            with open(lbl_map_path) as f:
                lm = json.load(f)
            label_to_idx = {int(k): int(v) for k, v in lm['label_to_idx'].items()}
            idx_to_label = {int(k): int(v) for k, v in lm['idx_to_label'].items()}
            logger.info(f"  Label map from xgb_label_map.json: {label_to_idx}")
        elif y_train_path.exists():
            y_tr = np.load(str(y_train_path)).astype(int)
            present = sorted(np.unique(y_tr).tolist())
            label_to_idx = {lbl: i for i, lbl in enumerate(present)}
            idx_to_label = {i: lbl for lbl, i in label_to_idx.items()}
            logger.info(f"  Label map from y_train.npy: {label_to_idx}")
        else:
            logger.warning("No label map found — using identity fallback")
            for i in range(6):
                label_to_idx[i] = i
                idx_to_label[i] = i

        # ── Transformer+LSTM — support v2 and v3 filenames ───────────────────
        tf_candidates = [
            model_dir / 'transformer_v3.pt',          # Kaggle notebook output
            model_dir / 'transformer_lstm_v2.pth',    # legacy v2
        ]
        t_path = next((p for p in tf_candidates if p.exists()), None)
        if t_path is None:
            raise FileNotFoundError(f"Transformer model not found in {model_dir}. "
                                    f"Expected: {[p.name for p in tf_candidates]}")

        # HP from metadata if available
        hp = {}
        for meta_name in ['tf_best_config.json', 'transformer_metrics.json', 'transformer_lstm_metadata.json']:
            meta_path = model_dir / meta_name
            if meta_path.exists():
                with open(meta_path) as f:
                    t_meta = json.load(f)
                hp = t_meta.get('best_hp', {})
                if hp:
                    logger.info(f"  Transformer HP from {meta_name}: {hp}")
                    break

        transformer = TransformerLSTMForecaster(
            input_dim   = N_FEATURES,
            hidden_dim  = hp.get('hidden_dim',  64),
            num_heads   = hp.get('num_heads',    4),
            num_layers  = hp.get('num_layers',   2),
            lstm_hidden = hp.get('lstm_hidden', 128),
            lstm_layers = hp.get('lstm_layers',  2),
            dropout     = 0.0,
        )
        state_dict = torch.load(str(t_path), map_location=device, weights_only=True)
        transformer.load_state_dict(state_dict)
        transformer = transformer.to(device)
        transformer.eval()
        logger.info(f"  ✓ Transformer+LSTM loaded: {t_path}")

        # ── Scaler — check model_dir first (Kaggle saves it there), then data_dir ──
        scaler_candidates = [model_dir / 'scaler.pkl', Path(data_dir) / 'scaler.pkl']
        scaler_path = next((p for p in scaler_candidates if p.exists()), None)
        if scaler_path is None:
            raise FileNotFoundError(f"scaler.pkl not found in {model_dir} or {data_dir}")
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        logger.info(f"  ✓ Scaler loaded: {scaler_path}")

        return cls(
            booster      = booster,
            transformer  = transformer,
            scaler       = scaler,
            label_to_idx = label_to_idx,
            idx_to_label = idx_to_label,
            device       = device,
            shap_enabled = shap_enabled,
        )

    # ── Core inference ────────────────────────────────────────────────────────

    def infer(self, features_raw: np.ndarray) -> AIOutputPayload:
        """
        Process one 5-second window and return a complete AIOutputPayload.

        Args:
            features_raw: shape (17,) — raw (unscaled) feature vector from Flink

        Returns:
            AIOutputPayload — ready to serialize and send to S4
        """
        t_total = time.perf_counter()
        self._window_id += 1

        # 1. Scale
        x_scaled = self.scaler.transform(
            features_raw.reshape(1, -1)
        ).astype(np.float32).flatten()

        # 2. XGBoost → 7-class probs
        class_probs_7, shap_top5, xgb_ms = self._run_xgboost(x_scaled)

        # 3. Update rolling buffer
        self._buffer.append(x_scaled)

        # 4. Transformer → 4-horizon forecast
        forecast_4, tf_ms = self._run_transformer()

        # 5. Compose payload
        payload = build_output(
            window_id    = self._window_id,
            class_probs  = class_probs_7,
            forecast     = forecast_4,
            top_features = shap_top5,
        )

        total_ms = (time.perf_counter() - t_total) * 1000
        logger.debug(
            f"[W{self._window_id:05d}] "
            f"class={payload.detection.attack_type} "
            f"conf={payload.detection.confidence:.3f} | "
            f"P30={forecast_4[0]:.3f} | "
            f"xgb={xgb_ms:.1f}ms tf={tf_ms:.1f}ms total={total_ms:.1f}ms"
        )
        return payload

    # ── Private: XGBoost ──────────────────────────────────────────────────────

    def _run_xgboost(self, x_scaled: np.ndarray):
        """Returns (class_probs_7, shap_top5_dict, latency_ms)."""
        t0 = time.perf_counter()

        dm = xgb.DMatrix(x_scaled.reshape(1, -1))

        # Predict probabilities
        raw = self.booster.predict(dm)          # shape: (1, n_classes) or (n_classes,)
        n_cls = len(self.label_to_idx)
        if raw.ndim == 1:
            probs_remapped = raw.reshape(1, n_cls)[0]
        else:
            probs_remapped = raw[0]

        # Map back to 7-class space (fill 0 for absent classes)
        class_probs_7 = np.zeros(7, dtype=np.float32)
        for remapped_idx, orig_label in self.idx_to_label.items():
            if orig_label < 7:
                class_probs_7[orig_label] = probs_remapped[remapped_idx]

        # SHAP
        shap_top5 = {}
        if self.shap_enabled:
            shap_top5 = self._compute_shap(x_scaled, int(np.argmax(class_probs_7)))

        ms = (time.perf_counter() - t0) * 1000
        self._latencies_xgb.append(ms)
        return class_probs_7, shap_top5, ms

    def _compute_shap(self, x_scaled: np.ndarray, predicted_class: int) -> dict:
        """Compute SHAP top-K for the predicted class."""
        try:
            if self._shap_explainer is None:
                import shap
                self._shap_explainer = shap.TreeExplainer(self.booster)

            dm_shap = xgb.DMatrix(x_scaled.reshape(1, -1))
            shap_out = self._shap_explainer(dm_shap)
            sv = shap_out.values  # (1, n_features, n_classes) or similar

            # Extract SHAP for predicted class
            n_cls = len(self.label_to_idx)
            if hasattr(sv, 'ndim') and sv.ndim == 3:
                # (1, features, n_classes_remapped)
                remapped_cls = self.label_to_idx.get(predicted_class, 0)
                if remapped_cls < sv.shape[2]:
                    shap_vals = np.abs(sv[0, :, remapped_cls])
                else:
                    shap_vals = np.abs(sv[0]).mean(axis=-1) if sv.ndim == 3 else np.abs(sv[0])
            elif hasattr(sv, 'ndim') and sv.ndim == 2:
                shap_vals = np.abs(sv[0])
            else:
                shap_vals = np.abs(np.array(sv)).flatten()[:len(FEATURE_NAMES)]

            # Pad/trim to feature count
            n = min(len(shap_vals), len(FEATURE_NAMES))
            top_k = min(TOP_K_SHAP, n)
            top_idx = np.argsort(shap_vals[:n])[-top_k:][::-1]
            return {FEATURE_NAMES[i]: float(shap_vals[i]) for i in top_idx}

        except Exception as e:
            logger.debug(f"SHAP skipped: {e}")
            return {}

    # ── Private: Transformer ──────────────────────────────────────────────────

    def _run_transformer(self):
        """Returns (forecast_4, latency_ms). Uses zeros if buffer not full yet."""
        t0 = time.perf_counter()

        if len(self._buffer) < N_TIMESTEPS:
            # Buffer not full — return neutral forecast
            ms = (time.perf_counter() - t0) * 1000
            self._latencies_transformer.append(ms)
            return [0.0, 0.0, 0.0, 0.0], ms

        # Stack buffer → (1, 12, 17)
        seq = np.stack(list(self._buffer), axis=0)   # (12, 17)
        x_t = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(self.device)

        with torch.no_grad():
            logits = self.transformer(x_t)            # (1, 4)
            probs  = torch.sigmoid(logits)[0].cpu().numpy()

        forecast_4 = [float(p) for p in probs]
        ms = (time.perf_counter() - t0) * 1000
        self._latencies_transformer.append(ms)
        return forecast_4, ms

    # ── Utilities ─────────────────────────────────────────────────────────────

    def reset_buffer(self):
        """Clear rolling buffer (call between independent traffic streams)."""
        self._buffer.clear()

    def latency_summary(self) -> dict:
        """Return P50/P95/P99 latency stats (ms)."""
        def pcts(arr):
            if not arr:
                return {'p50': 0, 'p95': 0, 'p99': 0}
            a = np.array(arr)
            return {
                'p50': float(np.percentile(a, 50)),
                'p95': float(np.percentile(a, 95)),
                'p99': float(np.percentile(a, 99)),
            }
        return {
            'xgboost_ms':     pcts(self._latencies_xgb),
            'transformer_ms': pcts(self._latencies_transformer),
            'n_inferences':   len(self._latencies_xgb),
        }

    @property
    def buffer_fill(self) -> int:
        """Current number of timesteps in rolling buffer (0–12)."""
        return len(self._buffer)


# ── Standalone replay runner ───────────────────────────────────────────────────

def run_replay(
    model_dir:  str = './pad_onap_v3/models',
    data_dir:   str = './pad_onap_v3/processed',
    n_samples:  int = 500,
    device:     str = 'auto',
    shap_enabled: bool = True,
    out_path:   str = './pad_onap_v3/models/inference_replay_results.json',
):
    """
    Replay the test set through the inference layer and collect metrics.

    Args:
        n_samples:  max windows to replay (None = all)
        out_path:   path to save JSON results summary
    """
    import json
    from sklearn.metrics import accuracy_score, f1_score, classification_report

    logger.info("=" * 60)
    logger.info("S3-AI INFERENCE LAYER — REPLAY TEST")
    logger.info("=" * 60)

    # Load engine
    engine = InferenceEngine.load(
        model_dir    = model_dir,
        data_dir     = data_dir,
        device       = device,
        shap_enabled = shap_enabled,
    )

    # Load test data (unscaled — engine will scale internally)
    data_dir = Path(data_dir)
    scaler   = engine.scaler

    X_test = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_test = np.load(data_dir / 'y_test.npy').astype(int)

    # Inverse-transform to get raw features
    X_raw = scaler.inverse_transform(X_test).astype(np.float32)

    if n_samples is not None:
        X_raw = X_raw[:n_samples]
        y_test = y_test[:n_samples]

    logger.info(f"Replaying {len(X_raw):,} windows...")

    y_pred           = []
    proactive_count  = 0
    tier_counts      = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    total_latency_ms = []
    sample_payloads  = []

    t_start = time.perf_counter()

    for i, x_raw in enumerate(X_raw):
        t0      = time.perf_counter()
        payload = engine.infer(x_raw)
        ms      = (time.perf_counter() - t0) * 1000
        total_latency_ms.append(ms)

        y_pred.append(payload.detection.attack_class)

        if payload.proactive_trigger.triggered:
            proactive_count += 1

        # Tier assignment (simplified: based on confidence + proactive)
        conf = payload.detection.confidence
        p30  = payload.forecast.p_attack_30s
        if payload.detection.attack_class == 0:
            tier = 0
        elif p30 > 0.90 and conf > 0.90:
            tier = 3
        elif p30 > 0.70 or conf > 0.80:
            tier = 2
        elif conf > 0.50:
            tier = 1
        else:
            tier = 0
        tier_counts[tier] += 1

        # Save first 3 payloads as examples
        if i < 3:
            sample_payloads.append(payload_to_dict(payload))

        if (i + 1) % 100 == 0:
            elapsed = time.perf_counter() - t_start
            logger.info(
                f"  [{i+1:4d}/{len(X_raw)}] "
                f"P99={float(np.percentile(total_latency_ms, 99)):.1f}ms "
                f"elapsed={elapsed:.1f}s"
            )

    # ── Metrics ───────────────────────────────────────────────────────────────
    present_classes = sorted(np.unique(np.concatenate([y_test, y_pred])))
    target_names    = [CLASS_NAMES[c] for c in present_classes]

    acc      = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average='macro', zero_division=0))
    lat      = engine.latency_summary()
    lat_arr  = np.array(total_latency_ms)

    logger.info("\n" + "=" * 60)
    logger.info("REPLAY RESULTS")
    logger.info("=" * 60)
    logger.info(f"Accuracy  : {acc:.4f}")
    logger.info(f"Macro F1  : {macro_f1:.4f}")
    logger.info(f"Proactive triggers: {proactive_count}/{len(X_raw)} "
                f"({proactive_count/len(X_raw)*100:.1f}%)")
    logger.info(f"\nTier distribution:")
    for t, cnt in tier_counts.items():
        logger.info(f"  T{t}: {cnt:5d} ({cnt/len(X_raw)*100:.1f}%)")
    logger.info(f"\nEnd-to-end latency (ms):")
    logger.info(f"  P50={np.percentile(lat_arr,50):.2f}  "
                f"P95={np.percentile(lat_arr,95):.2f}  "
                f"P99={np.percentile(lat_arr,99):.2f}")
    logger.info(f"\nXGBoost latency  : {lat['xgboost_ms']}")
    logger.info(f"Transformer latency: {lat['transformer_ms']}")

    logger.info("\n" + classification_report(
        y_test, y_pred,
        labels=present_classes,
        target_names=target_names,
        digits=4, zero_division=0,
    ))

    # ── Save results ──────────────────────────────────────────────────────────
    results = {
        'n_samples':      len(X_raw),
        'accuracy':       acc,
        'macro_f1':       macro_f1,
        'proactive_rate': proactive_count / len(X_raw),
        'tier_counts':    tier_counts,
        'latency_ms': {
            'p50': float(np.percentile(lat_arr, 50)),
            'p95': float(np.percentile(lat_arr, 95)),
            'p99': float(np.percentile(lat_arr, 99)),
        },
        'xgboost_latency_ms':     lat['xgboost_ms'],
        'transformer_latency_ms': lat['transformer_ms'],
        'sample_payloads':        sample_payloads,
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"\n💾 Results saved: {out_path}")

    return results


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='S3-AI Inference Layer Replay')
    parser.add_argument('--model-dir',  default='./pad_onap_v3/models')
    parser.add_argument('--data-dir',   default='./pad_onap_v3/processed')
    parser.add_argument('--n-samples',  type=int, default=500)
    parser.add_argument('--device',     default='auto')
    parser.add_argument('--no-shap',    action='store_true')
    parser.add_argument('--out',        default='./pad_onap_v3/models/inference_replay_results.json')
    args = parser.parse_args()

    run_replay(
        model_dir    = args.model_dir,
        data_dir     = args.data_dir,
        n_samples    = args.n_samples,
        device       = args.device,
        shap_enabled = not args.no_shap,
        out_path     = args.out,
    )

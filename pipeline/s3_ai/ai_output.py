"""
M2 — AI Output Schema & Proactive Trigger (Spec-aligned §4.5 / §4.6)

Spec:
  - Detection payload: attack_type (7-class), confidence, top-5 SHAP features
  - Forecast payload: P(attack) at t+30s, t+60s, t+90s, t+120s
  - Proactive trigger: if P(t+30s) > 0.50 → issue Tier 2 pre-positioning signal
  - Output: JSON over DMaaP (simulated as local JSON file / REST stub)
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Class names (spec §2) ────────────────────────────────────────────────────
CLASS_NAMES = {
    0: "Normal",
    1: "UDP_Flood",
    2: "SYN_Flood",
    3: "HTTP_Flood",
    4: "ICMP_Flood",
    5: "Amplification",
    6: "Slow_rate",
}

# ── Thresholds (spec §4.6) ───────────────────────────────────────────────────
PROACTIVE_THRESHOLD = 0.50      # P(t+30s) > 0.50 → pre-position
DETECTION_THRESHOLD = 0.50      # confidence > 0.50 → alert
TIER2_ACTION        = "PREPOSITION_TIER2_MITIGATION"
TIER3_ACTION        = "ACTIVATE_TIER3_MITIGATION"


@dataclass
class DetectionResult:
    """7-class XGBoost detection output."""
    attack_class: int               # 0–6
    attack_type:  str               # human-readable
    confidence:   float             # max softmax probability
    class_probs:  dict              # {class_name: prob}
    top_features: dict              # {feature_name: shap_value}  top-5 SHAP


@dataclass
class ForecastResult:
    """Transformer+LSTM 4-horizon forecast output."""
    p_attack_30s:  float
    p_attack_60s:  float
    p_attack_90s:  float
    p_attack_120s: float
    proactive_trigger: bool         # True if P(t+30s) > PROACTIVE_THRESHOLD
    recommended_action: str         # PREPOSITION_TIER2 / NONE


@dataclass
class ProactiveTrigger:
    """Proactive pre-positioning signal issued when threshold exceeded."""
    triggered:        bool
    horizon_s:        int           # 30
    threshold:        float         # 0.70
    p_attack:         float         # actual P(t+30s)
    action:           str
    tier:             int           # 2


@dataclass
class AIOutputPayload:
    """
    Canonical AI output JSON payload for DMaaP / Policy Framework.
    Spec §4.6 — sent every 5-second window.
    """
    event_id:         str
    timestamp:        str           # ISO-8601 UTC
    window_id:        int
    detection:        DetectionResult
    forecast:         ForecastResult
    proactive_trigger: ProactiveTrigger
    model_versions:   dict = field(default_factory=lambda: {
        "xgboost": "2.0",
        "transformer_lstm": "2.0",
    })
    schema_version:   str = "2.0"


def build_output(
    *,
    window_id:   int,
    class_probs: list,          # shape (7,) from XGBoost predict_proba
    forecast:    list,          # shape (4,) from Transformer P(attack) per horizon
    top_features: dict,         # {feat: shap_val}  (pass {} if SHAP unavailable)
    xgboost_version: str = "2.0",
    transformer_version: str = "2.0",
) -> AIOutputPayload:
    """
    Build a complete AIOutputPayload from model outputs.

    Args:
        window_id:    sequential window index
        class_probs:  7-element probability vector (XGBoost softmax)
        forecast:     4-element forecast vector [P30, P60, P90, P120]
        top_features: SHAP top-5 dict {feature_name: importance}

    Returns:
        AIOutputPayload dataclass
    """
    import numpy as np
    class_probs = list(class_probs)
    forecast    = list(forecast)

    # ── Detection ────────────────────────────────────────────────────────────
    best_class = int(np.argmax(class_probs))
    confidence = float(class_probs[best_class])
    class_prob_dict = {CLASS_NAMES[i]: float(class_probs[i]) for i in range(7)}

    detection = DetectionResult(
        attack_class = best_class,
        attack_type  = CLASS_NAMES[best_class],
        confidence   = confidence,
        class_probs  = class_prob_dict,
        top_features = top_features,
    )

    # ── Forecast ──────────────────────────────────────────────────────────────
    p30, p60, p90, p120 = [float(p) for p in forecast[:4]]

    # Gate proactive trigger on BOTH Transformer AND XGBoost signals (Fix #3).
    # Requires:
    #   1. P(t+30s) > PROACTIVE_THRESHOLD  — Transformer sees future threat
    #   2. XGBoost confidence > 0.75       — Current window is clearly attack
    #   3. XGBoost class != Normal         — Not a false positive
    CONF_GATE = 0.75
    proactive_triggered = (
        p30 > PROACTIVE_THRESHOLD
        and confidence > CONF_GATE
        and best_class != 0   # not Normal
    )
    recommended_action  = TIER2_ACTION if proactive_triggered else "NONE"

    forecast_result = ForecastResult(
        p_attack_30s  = p30,
        p_attack_60s  = p60,
        p_attack_90s  = p90,
        p_attack_120s = p120,
        proactive_trigger  = proactive_triggered,
        recommended_action = recommended_action,
    )

    # ── Proactive trigger ────────────────────────────────────────────────────
    trigger = ProactiveTrigger(
        triggered  = proactive_triggered,
        horizon_s  = 30,
        threshold  = PROACTIVE_THRESHOLD,
        p_attack   = p30,
        action     = TIER2_ACTION if proactive_triggered else "NONE",
        tier       = 2,
    )

    if proactive_triggered:
        logger.info(
            f"[ProactiveTrigger] window={window_id} "
            f"P(t+30s)={p30:.3f} > {PROACTIVE_THRESHOLD} "
            f"conf={confidence:.3f} > {CONF_GATE} "
            f"class={CLASS_NAMES[best_class]} "
            f"→ {TIER2_ACTION}"
        )

    payload = AIOutputPayload(
        event_id  = str(uuid.uuid4()),
        timestamp = datetime.now(timezone.utc).isoformat(),
        window_id = window_id,
        detection = detection,
        forecast  = forecast_result,
        proactive_trigger = trigger,
        model_versions = {
            "xgboost":            xgboost_version,
            "transformer_lstm":   transformer_version,
        },
    )
    return payload


def payload_to_dict(payload: AIOutputPayload) -> dict:
    """Serialize AIOutputPayload to a JSON-serializable dict."""
    return asdict(payload)


def payload_to_json(payload: AIOutputPayload, indent: int = 2) -> str:
    """Serialize AIOutputPayload to JSON string."""
    return json.dumps(payload_to_dict(payload), indent=indent)


def emit_to_dmaap_stub(payload: AIOutputPayload, out_path: str = None) -> None:
    """
    Emit the AI output payload.

    In the real deployment this would POST to DMaaP MR topic.
    Here it writes a JSON file (DMaaP stub for integration testing).

    Args:
        payload:  AIOutputPayload
        out_path: path to write JSON, defaults to /tmp/ai_output_<event_id>.json
    """
    import tempfile, os
    if out_path is None:
        out_path = os.path.join(
            tempfile.gettempdir(),
            f"ai_output_{payload.event_id[:8]}.json"
        )

    data = payload_to_json(payload)
    with open(out_path, 'w') as f:
        f.write(data)

    logger.debug(f"[DMaaP stub] Wrote payload to {out_path}")


# ── Example schema (for documentation) ───────────────────────────────────────
EXAMPLE_SCHEMA = {
    "event_id":   "uuid-v4",
    "timestamp":  "2026-04-05T12:00:00+00:00",
    "window_id":  42,
    "schema_version": "2.0",
    "model_versions": {
        "xgboost":          "2.0",
        "transformer_lstm": "2.0",
    },
    "detection": {
        "attack_class": 2,
        "attack_type":  "SYN_Flood",
        "confidence":   0.97,
        "class_probs": {
            "Normal": 0.01, "UDP_Flood": 0.01, "SYN_Flood": 0.97,
            "HTTP_Flood": 0.005, "ICMP_Flood": 0.0, "Amplification": 0.005, "Slow_rate": 0.0
        },
        "top_features": {
            "syn_ratio": 0.45, "pkt_rate": 0.22, "src_ip_entropy": 0.18,
            "proto_dist_tcp": 0.10, "new_flows_rate": 0.05
        }
    },
    "forecast": {
        "p_attack_30s":  0.92,
        "p_attack_60s":  0.88,
        "p_attack_90s":  0.81,
        "p_attack_120s": 0.74,
        "proactive_trigger":  True,
        "recommended_action": "PREPOSITION_TIER2_MITIGATION",
    },
    "proactive_trigger": {
        "triggered": True,
        "horizon_s": 30,
        "threshold": 0.50,
        "p_attack":  0.92,
        "action":    "PREPOSITION_TIER2_MITIGATION",
        "tier":      2,
    }
}


if __name__ == '__main__':
    # Smoke test
    import numpy as np
    logging.basicConfig(level=logging.INFO)

    fake_class_probs = np.array([0.01, 0.01, 0.92, 0.02, 0.0, 0.03, 0.01])
    fake_forecast    = [0.88, 0.82, 0.75, 0.68]
    fake_shap        = {"syn_ratio": 0.45, "pkt_rate": 0.22}

    p = build_output(
        window_id=1,
        class_probs=fake_class_probs,
        forecast=fake_forecast,
        top_features=fake_shap,
    )

    print(payload_to_json(p))
    print(f"\nProactive trigger: {p.proactive_trigger.triggered}")
    print(f"Recommended action: {p.forecast.recommended_action}")

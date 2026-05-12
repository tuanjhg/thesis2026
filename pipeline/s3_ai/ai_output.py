"""
M2 — AI Output Schema (Spec §4.6 — schema 3.0)
==============================================

Canonical JSON payload for the `ai.detections` topic, consumed by ONAP DCAE.

Shape per Spec §4.6:
{
  "event_id":           str (uuid4),
  "timestamp_utc":      ISO-8601,
  "schema_version":     "3.0",
  "source_ip_prefix":   str | null,
  "target_ip_prefix":   str | null,
  "tenant_id":          str | null,
  "severity_estimate":  "INFO" | "MINOR" | "MAJOR" | "CRITICAL",
  "detection": {                                    # Track A — XGBoost + SHAP
    "track":              "A_XGB",
    "attack_type":        one of CICDDOS_CLASS_NAMES,
    "attack_class_id":    int [0..11],
    "confidence":         float = 1 - P(BENIGN),
    "is_attack":          bool,
    "class_probs":        {class_name: prob, ...},
    "shap_top_features":  [str, ...],               # top-K (default 5) names
    "shap_values":        {feature_name: signed_shap, ...},
    "explanation_text":   str
  },
  "forecast": {                                     # Track B — Stacked LSTM
    "track":                  "B_LSTM",
    "p_attack_1min":          float,
    "p_attack_5min":          float,
    "p_attack_15min":         float,
    "pre_position_recommended": bool,
    "triggered_horizon":      1 | 5 | 15 | null,    # longest active horizon
    "perm_importance":        {var_name: importance, ...},
    "forecast_justification": str
  },
  "xai": {                                          # convenience aggregate
    "shap_top_features":     [...],
    "shap_values":           {...},
    "explanation_text":      str,
    "perm_importance":       {...},
    "forecast_justification": str
  },
  "model_versions": {
    "xgboost":     str,
    "lstm_track_b": str,
    "schema":      "3.0"
  }
}

Backward compatibility:
  - The legacy 7-class enum and 30/60/90/120s horizon names are kept as
    aliases (LEGACY_CLASS_NAMES, LEGACY_HORIZONS) so any older subscriber
    can still parse messages — see `to_legacy_v2_dict()`.
  - `build_output(...)` retains its old signature for any caller still using
    the v2 schema; it now emits a v3-compatible payload internally.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Spec §4.2 — 12-class CICDDoS2019 taxonomy
# ─────────────────────────────────────────────────────────────────────────────

CICDDOS_CLASS_NAMES: dict[int, str] = {
    0: 'BENIGN',
    1: 'Amplification',     # macro-class: DrDoS_DNS/LDAP/MSSQL/NetBIOS/NTP/SNMP/SSDP/UDP
    2: 'Syn',
    3: 'UDP-lag',
    4: 'WebDDoS',
}
N_CICDDOS_CLASSES = 5

# Spec §5.3 — `attack_type → CNF profile` map (used by M3 TierMapper).
# Sub-type entries (DrDoS_DNS, DrDoS_LDAP, ...) are kept as aliases for
# backwards-compatibility with any caller that has not yet migrated to the
# 5-class taxonomy.
ATTACK_TYPE_TO_CNF_PROFILE: dict[str, str] = {
    'BENIGN':         'none',
    # P3 canonical 5-class
    'Amplification':  'cnf-scrubber-reflection',
    'Syn':            'cnf-scrubber-syn-proxy',
    'UDP-lag':        'cnf-rate-limiter-token-bucket',
    'WebDDoS':        'cnf-rate-limiter-app-layer',
    # Legacy aliases (12-class IJSRA-2021 schema)
    'DrDoS_DNS':      'cnf-scrubber-reflection',
    'DrDoS_LDAP':     'cnf-scrubber-reflection',
    'DrDoS_MSSQL':    'cnf-scrubber-reflection',
    'DrDoS_NetBIOS':  'cnf-scrubber-reflection',
    'DrDoS_NTP':      'cnf-scrubber-reflection',
    'DrDoS_SNMP':     'cnf-scrubber-reflection',
    'DrDoS_SSDP':     'cnf-scrubber-reflection',
    'DrDoS_UDP':      'cnf-scrubber-reflection',
}

# Spec §4.3 — operating thresholds per horizon, used to set `triggered_horizon`
HORIZON_THRESHOLDS: dict[int, float] = {1: 0.85, 5: 0.70, 15: 0.50}

PROACTIVE_THRESHOLD     = HORIZON_THRESHOLDS[5]   # default pre-position trigger
DETECTION_THRESHOLD     = 0.50
TIER2_ACTION            = 'PREPOSITION_TIER2_MITIGATION'
TIER3_ACTION            = 'ACTIVATE_TIER3_MITIGATION'

# ── Legacy aliases (v2 schema — still accepted for back-compat) ──────────────
LEGACY_CLASS_NAMES: dict[int, str] = {
    0: 'Normal', 1: 'UDP_Flood', 2: 'SYN_Flood', 3: 'HTTP_Flood',
    4: 'ICMP_Flood', 5: 'Amplification', 6: 'Slow_rate',
}
LEGACY_HORIZONS = ('30s', '60s', '90s', '120s')


# ─────────────────────────────────────────────────────────────────────────────
# Severity calculator (Spec §5.2 — VES `eventSeverity` band)
# ─────────────────────────────────────────────────────────────────────────────

def severity_from_signals(
    *,
    confidence: float = 0.0,
    p_attack_1min: float = 0.0,
    p_attack_5min: float = 0.0,
) -> str:
    """
    Map AI signals to a 4-level VES severity band.

    Rules (Spec §5.2 / §5.3):
      CRITICAL  — confidence ≥ 0.95  OR  p_attack_1min ≥ 0.95
      MAJOR     — confidence ≥ 0.85  OR  p_attack_1min ≥ 0.85
      MINOR     — p_attack_5min ≥ 0.70
      INFO      — otherwise
    """
    if confidence >= 0.95 or p_attack_1min >= 0.95:
        return 'CRITICAL'
    if confidence >= 0.85 or p_attack_1min >= HORIZON_THRESHOLDS[1]:
        return 'MAJOR'
    if p_attack_5min >= HORIZON_THRESHOLDS[5]:
        return 'MINOR'
    return 'INFO'


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses (schema 3.0)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Track A output (Spec §4.6 — `detection` block)."""
    track:              str = 'A_XGB'
    attack_type:        str = 'BENIGN'
    attack_class_id:    int = 0
    confidence:         float = 0.0          # 1 − P(BENIGN)
    is_attack:          bool = False
    class_probs:        dict = field(default_factory=dict)
    shap_top_features:  list = field(default_factory=list)
    shap_values:        dict = field(default_factory=dict)
    explanation_text:   str = ''
    inference_ms:       float = 0.0


@dataclass
class ForecastResult:
    """Track B output (Spec §4.6 — `forecast` block)."""
    track:                    str = 'B_LSTM'
    p_attack_1min:            float = 0.0
    p_attack_5min:            float = 0.0
    p_attack_15min:           float = 0.0
    pre_position_recommended: bool = False
    triggered_horizon:        Optional[int] = None     # 1, 5, 15, or None
    perm_importance:          dict = field(default_factory=dict)
    forecast_justification:   str = ''
    inference_ms:             float = 0.0


@dataclass
class AIOutputPayload:
    """Spec §4.6 message published to `ai.detections` (schema 3.0)."""
    event_id:           str
    timestamp_utc:      str
    schema_version:     str = '3.0'
    source_ip_prefix:   Optional[str] = None
    target_ip_prefix:   Optional[str] = None
    tenant_id:          Optional[str] = None
    severity_estimate:  str = 'INFO'
    detection:          Optional[DetectionResult] = None
    forecast:           Optional[ForecastResult]  = None
    xai:                dict = field(default_factory=dict)
    model_versions:     dict = field(default_factory=lambda: {
        'xgboost':      'unknown',
        'lstm_track_b': 'unknown',
        'schema':       '3.0',
    })


# ─────────────────────────────────────────────────────────────────────────────
# Builders
# ─────────────────────────────────────────────────────────────────────────────

def build_payload(
    *,
    detection:          Optional[DetectionResult] = None,
    forecast:           Optional[ForecastResult]  = None,
    source_ip_prefix:   Optional[str] = None,
    target_ip_prefix:   Optional[str] = None,
    tenant_id:          Optional[str] = None,
    xgboost_version:    str = 'unknown',
    lstm_track_b_version: str = 'unknown',
) -> AIOutputPayload:
    """
    Compose a schema-3.0 payload from independent Track A / Track B results.
    Exactly one of `detection` / `forecast` may be None (partial bucket).
    """
    conf = detection.confidence       if detection is not None else 0.0
    p1   = forecast.p_attack_1min     if forecast  is not None else 0.0
    p5   = forecast.p_attack_5min     if forecast  is not None else 0.0
    sev  = severity_from_signals(
        confidence=conf, p_attack_1min=p1, p_attack_5min=p5,
    )

    xai: dict = {}
    if detection is not None:
        xai['shap_top_features'] = list(detection.shap_top_features)
        xai['shap_values']       = dict(detection.shap_values)
        xai['explanation_text']  = detection.explanation_text
    if forecast is not None:
        xai['perm_importance']        = dict(forecast.perm_importance)
        xai['forecast_justification'] = forecast.forecast_justification

    return AIOutputPayload(
        event_id          = str(uuid.uuid4()),
        timestamp_utc     = datetime.now(timezone.utc).isoformat(),
        source_ip_prefix  = source_ip_prefix,
        target_ip_prefix  = target_ip_prefix,
        tenant_id         = tenant_id,
        severity_estimate = sev,
        detection         = detection,
        forecast          = forecast,
        xai               = xai,
        model_versions    = {
            'xgboost':      xgboost_version,
            'lstm_track_b': lstm_track_b_version,
            'schema':       '3.0',
        },
    )


# ── Legacy compatibility shim ────────────────────────────────────────────────

def build_output(
    *,
    window_id:        int = 0,
    class_probs:      Optional[list] = None,    # 7 or 12 elements
    forecast:         Optional[list] = None,    # 4 or 3 elements
    top_features:     Optional[dict] = None,
    xgboost_version:  str = 'unknown',
    transformer_version: str = 'unknown',
    source_ip_prefix: Optional[str] = None,
    target_ip_prefix: Optional[str] = None,
    tenant_id:        Optional[str] = None,
) -> AIOutputPayload:
    """
    Legacy v2 entry point — kept for any caller that hasn't been migrated yet.

    Handles both:
      * 7-class (legacy) probs → folded into the 12-class taxonomy
        ('Normal'→'BENIGN', 'UDP_Flood'→'DrDoS_UDP', 'SYN_Flood'→'Syn',
         'HTTP_Flood'+'Slow_rate'→'WebDDoS', 'Amplification' split across
         DrDoS_DNS..SSDP, 'ICMP_Flood'→'UDP-lag' as proxy)
      * 12-class probs → passed through.

    Forecast input may be 4-tuple (legacy 30/60/90/120s) or 3-tuple
    (spec 1/5/15 min). For the legacy 4-tuple the 120-s head is projected
    to the 1/5/15-min horizons via the same decay used in the inference layer.
    """
    import numpy as np

    class_probs = list(class_probs or [])
    forecast    = list(forecast or [])
    top_features = dict(top_features or {})

    # ── Class-probability normalization ──────────────────────────────────────
    probs_12 = _coerce_class_probs(class_probs)

    best_id  = int(np.argmax(probs_12)) if probs_12.any() else 0
    attack_p = float(1.0 - probs_12[0])
    is_attack = best_id != 0

    detection = DetectionResult(
        track             = 'A_XGB',
        attack_type       = CICDDOS_CLASS_NAMES[best_id],
        attack_class_id   = best_id,
        confidence        = attack_p,
        is_attack         = is_attack,
        class_probs       = {
            CICDDOS_CLASS_NAMES[i]: float(probs_12[i])
            for i in range(N_CICDDOS_CLASSES)
        },
        shap_top_features = list(top_features.keys())[:5],
        shap_values       = {k: float(v) for k, v in top_features.items()},
        explanation_text  = _legacy_explanation(
            CICDDOS_CLASS_NAMES[best_id], top_features,
        ),
    )

    # ── Forecast normalization (4-horizon legacy → 3-horizon spec) ───────────
    p1, p5, p15 = _coerce_forecast(forecast)
    triggered = None
    if p15 >= HORIZON_THRESHOLDS[15]:
        triggered = 15
    if p5 >= HORIZON_THRESHOLDS[5]:
        triggered = 5
    if p1 >= HORIZON_THRESHOLDS[1]:
        triggered = 1

    fc = ForecastResult(
        track                    = 'B_LSTM',
        p_attack_1min            = float(p1),
        p_attack_5min            = float(p5),
        p_attack_15min           = float(p15),
        pre_position_recommended = (triggered is not None and triggered >= 5),
        triggered_horizon        = triggered,
    )

    return build_payload(
        detection           = detection,
        forecast            = fc,
        source_ip_prefix    = source_ip_prefix,
        target_ip_prefix    = target_ip_prefix,
        tenant_id           = tenant_id,
        xgboost_version     = xgboost_version,
        lstm_track_b_version = transformer_version,
    )


def _coerce_class_probs(class_probs: list):
    """
    Normalise a probability vector to the canonical 5-class P3 space.

    Accepted input shapes:
      * 5-vector  — pass through (P3 canonical).
      * 12-vector — fold the 8 reflection slots into Amplification.
      * 7-vector  — legacy v2 (Normal, UDP_Flood, SYN_Flood, HTTP_Flood,
                    ICMP_Flood, Amplification, Slow_rate) → P3 5-class.
      * Otherwise — zero-pad or truncate.
    """
    import numpy as np
    a = np.array(class_probs, dtype=np.float32) if class_probs else np.zeros(N_CICDDOS_CLASSES)

    # Already 5-class
    if a.size == N_CICDDOS_CLASSES:
        return a

    # 12-class CICDDoS → 5-class (fold reflection slots)
    if a.size == 12:
        out = np.zeros(N_CICDDOS_CLASSES, dtype=np.float32)
        out[0] = a[0]                       # BENIGN
        out[1] = float(a[1:9].sum())        # Amplification ← DrDoS_DNS..DrDoS_UDP
        out[2] = a[9]                       # Syn
        out[3] = a[10]                      # UDP-lag
        out[4] = a[11]                      # WebDDoS
        s = out.sum()
        return out / s if s > 0 else out

    # 7-class legacy → 5-class (provisional bridge)
    if a.size == 7:
        out = np.zeros(N_CICDDOS_CLASSES, dtype=np.float32)
        out[0] = a[0]                       # BENIGN          ← Normal
        out[1] = a[1] + a[5]                # Amplification   ← UDP_Flood + Amplification
        out[2] = a[2]                       # Syn             ← SYN_Flood
        out[3] = a[4]                       # UDP-lag         ← ICMP_Flood (proxy)
        out[4] = a[3] + a[6]                # WebDDoS         ← HTTP_Flood + Slow_rate
        s = out.sum()
        return out / s if s > 0 else out

    # Unknown shape — copy first N slots, zero-pad the rest
    out = np.zeros(N_CICDDOS_CLASSES, dtype=np.float32)
    n = min(a.size, N_CICDDOS_CLASSES)
    out[:n] = a[:n]
    return out


def _coerce_forecast(forecast: list):
    """Project a 3- or 4-element forecast vector to the spec (P1, P5, P15)."""
    if not forecast:
        return 0.0, 0.0, 0.0
    if len(forecast) == 3:
        return float(forecast[0]), float(forecast[1]), float(forecast[2])
    if len(forecast) == 4:
        # Legacy 30/60/90/120s heads → spec 1/5/15-min projection
        p120 = float(forecast[3])
        return p120, p120 * 0.85, p120 * 0.50
    p = list(forecast) + [0.0] * (3 - len(forecast))
    return float(p[0]), float(p[1]), float(p[2])


def _legacy_explanation(attack_type: str, top_features: dict) -> str:
    if not top_features:
        return f'Predicted {attack_type}; no SHAP attribution available.'
    parts = []
    for name, val in list(top_features.items())[:3]:
        parts.append(f'{val:+.3f} {name}')
    return f'Predicted {attack_type} because ' + ' and '.join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Serialization helpers
# ─────────────────────────────────────────────────────────────────────────────

def payload_to_dict(payload: AIOutputPayload) -> dict[str, Any]:
    """Schema 3.0 dict (NumPy-aware)."""
    import numpy as np

    def _conv(o):
        if isinstance(o, dict):
            return {k: _conv(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [_conv(v) for v in o]
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, np.floating):
            return float(o)
        if isinstance(o, np.integer):
            return int(o)
        return o
    return _conv(asdict(payload))


def payload_to_json(payload: AIOutputPayload, indent: int = 2) -> str:
    return json.dumps(payload_to_dict(payload), indent=indent)


def to_legacy_v2_dict(payload: AIOutputPayload) -> dict[str, Any]:
    """
    Render a v2-compatible dict for any pre-existing subscriber that still
    expects 7-class names and 30/60/90/120s horizon fields.

    Mapping (5 P3 → 7 legacy):
      BENIGN        → Normal
      Amplification → Amplification (also dual-tagged as UDP_Flood for
                                     subscribers that key on UDP_Flood)
      Syn           → SYN_Flood
      UDP-lag       → ICMP_Flood (closest legacy slot — kept as proxy)
      WebDDoS       → HTTP_Flood
      (HTTP_Flood + Slow_rate share the WebDDoS source slot.)
    """
    det  = payload.detection
    fc   = payload.forecast
    base = payload_to_dict(payload)

    if det is not None:
        cp5  = det.class_probs
        amp  = cp5.get('Amplification', 0.0)
        webd = cp5.get('WebDDoS', 0.0)
        legacy_probs = {
            'Normal':        cp5.get('BENIGN', 0.0),
            'UDP_Flood':     amp,                # subscribers keyed on UDP_Flood
            'SYN_Flood':     cp5.get('Syn', 0.0),
            'HTTP_Flood':    webd,
            'ICMP_Flood':    cp5.get('UDP-lag', 0.0),
            'Amplification': amp,
            'Slow_rate':     0.0,
        }
        legacy_class = max(legacy_probs.items(), key=lambda kv: kv[1])
        base['detection'] = {
            'attack_class': list(LEGACY_CLASS_NAMES.values()).index(legacy_class[0]),
            'attack_type':  legacy_class[0],
            'confidence':   det.confidence,
            'class_probs':  legacy_probs,
            'top_features': det.shap_values,
        }

    if fc is not None:
        # Project (P1,P5,P15) back to (30s,60s,90s,120s) heads via geometric decay
        p1 = fc.p_attack_1min
        base['forecast'] = {
            'p_attack_30s':  p1,
            'p_attack_60s':  p1 * 0.95,
            'p_attack_90s':  p1 * 0.90,
            'p_attack_120s': p1 * 0.85,
            'proactive_trigger':  fc.pre_position_recommended,
            'recommended_action': (TIER2_ACTION if fc.pre_position_recommended
                                   else 'NONE'),
        }
        base['proactive_trigger'] = {
            'triggered': fc.pre_position_recommended,
            'horizon_s': 60 * (fc.triggered_horizon or 1),
            'threshold': HORIZON_THRESHOLDS.get(fc.triggered_horizon or 1, 0.5),
            'p_attack':  p1,
            'action':    (TIER2_ACTION if fc.pre_position_recommended else 'NONE'),
            'tier':      2,
        }

    base['schema_version']   = '2.0'
    return base


def emit_to_dmaap_stub(payload: AIOutputPayload, out_path: Optional[str] = None) -> None:
    """File-system DMaaP stub (real deployment posts to DMaaP MR topic)."""
    import os
    import tempfile
    if out_path is None:
        out_path = os.path.join(
            tempfile.gettempdir(), f'ai_output_{payload.event_id[:8]}.json'
        )
    with open(out_path, 'w') as f:
        f.write(payload_to_json(payload))
    logger.debug(f'[DMaaP stub] wrote payload to {out_path}')


# ── Example schema (documentation) ───────────────────────────────────────────

EXAMPLE_SCHEMA = {
    'event_id':         'uuid-v4',
    'timestamp_utc':    '2026-05-06T12:00:00+00:00',
    'schema_version':   '3.0',
    'source_ip_prefix': '10.20.0.0/16',
    'target_ip_prefix': '198.51.100.0/24',
    'tenant_id':        'slice-eMBB',
    'severity_estimate': 'MAJOR',
    'detection': {
        'track':              'A_XGB',
        'attack_type':        'Amplification',
        'attack_class_id':    1,
        'confidence':         0.97,
        'is_attack':          True,
        'class_probs':        {n: 0.0 for n in CICDDOS_CLASS_NAMES.values()},
        'shap_top_features':  ['flow_packets_per_sec', 'flow_bytes_per_sec',
                               'syn_flag_count', 'protocol', 'flow_iat_mean'],
        'shap_values':        {'flow_packets_per_sec': 0.43,
                               'flow_bytes_per_sec':   0.31,
                               'syn_flag_count':       0.18,
                               'protocol':            -0.05,
                               'flow_iat_mean':        0.04},
        'explanation_text':   'Predicted Amplification because +0.430 flow_packets_per_sec '
                              'and +0.310 flow_bytes_per_sec and +0.180 syn_flag_count',
    },
    'forecast': {
        'track':                    'B_LSTM',
        'p_attack_1min':            0.92,
        'p_attack_5min':            0.78,
        'p_attack_15min':           0.55,
        'pre_position_recommended': True,
        'triggered_horizon':        1,
        'perm_importance': {
            'pkt_count_total':     0.31,
            'syn_count':           0.24,
            'unique_src_ip_count': 0.18,
            'byte_count_total':    0.14,
            'avg_pkt_size':        0.08,
            'unique_dst_ip_count': 0.05,
        },
        'forecast_justification': 'Forecast P(t+1)=0.920, P(t+5)=0.780, P(t+15)=0.550; '
                                  'top drivers: pkt_count_total (0.31), syn_count (0.24), '
                                  'unique_src_ip_count (0.18)',
    },
    'xai': {
        'shap_top_features':       ['flow_packets_per_sec', 'flow_bytes_per_sec'],
        'explanation_text':        'Predicted DrDoS_UDP because ...',
        'forecast_justification':  'Forecast P(t+1)=0.92 ...',
    },
    'model_versions': {
        'xgboost':      'xgboost_track_a',
        'lstm_track_b': 'lstm_track_b',
        'schema':       '3.0',
    },
}


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    sample = build_payload(
        detection = DetectionResult(
            attack_type='Amplification', attack_class_id=1, confidence=0.97,
            is_attack=True,
            class_probs={n: 0.0 for n in CICDDOS_CLASS_NAMES.values()},
            shap_top_features=['flow_packets_per_sec'],
            shap_values={'flow_packets_per_sec': 0.43},
            explanation_text='Predicted Amplification because +0.430 flow_packets_per_sec',
        ),
        forecast = ForecastResult(
            p_attack_1min=0.92, p_attack_5min=0.78, p_attack_15min=0.55,
            pre_position_recommended=True, triggered_horizon=1,
        ),
        source_ip_prefix='10.20.0.0/16',
        target_ip_prefix='198.51.100.0/24',
        tenant_id='slice-eMBB',
    )
    print(payload_to_json(sample))

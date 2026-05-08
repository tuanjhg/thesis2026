"""
M3 — Tier Mapper (Spec §5.3)
============================

5-tier graduated response driven by horizon-specific Track B forecast
thresholds and Track A reactive confidence:

  Tier 0 NORMAL     — all scores below threshold; baseline 500 ms telemetry
  Tier 1 ALERT      — Track B P(t+15) ≥ 0.50           (lead ~15 min)
                       → boost telemetry to 200 ms, log + A&AI hint
  Tier 2 PREEMPT    — Track B P(t+5)  ≥ 0.70           (lead ~5 min)
                       → pre-position scrubber (standby Pod, ready-warm)
                       → reserve BW quota
                       → [PROACTIVE NOVELTY]
  Tier 3 MITIGATE   — disjunctive: Track B P(t+1) ≥ 0.85
                                  OR Track A confidence ≥ 0.85
                       → insert CNF into SFC + apply rate-limit
                       → de-dup by (target_ip_prefix + 30 s window)
  Tier 4 ISOLATE    — Track A confidence ≥ 0.95
                       → full scrubbing + blackhole of attack source prefixes
                       → NOC alarm + cross-domain coordination

`attack_type → CNF profile` (Spec §5.3 / §6.1):
  DrDoS_*   → cnf-scrubber-reflection
  Syn       → cnf-scrubber-syn-proxy
  WebDDoS   → cnf-rate-limiter-app-layer
  UDP-lag   → cnf-rate-limiter-token-bucket
  BENIGN    → none
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from pipeline.s3_ai.ai_output import (
    ATTACK_TYPE_TO_CNF_PROFILE,
    HORIZON_THRESHOLDS,
)

logger = logging.getLogger(__name__)

# ── Spec §5.3 thresholds ─────────────────────────────────────────────────────
P15_T1     = HORIZON_THRESHOLDS[15]   # 0.50 — Tier 1 ALERT
P5_T2      = HORIZON_THRESHOLDS[5]    # 0.70 — Tier 2 PREEMPT
P1_T3      = HORIZON_THRESHOLDS[1]    # 0.85 — Tier 3 (forecast path)
CONF_T3    = 0.85                     # Tier 3 (reactive Track A path)
CONF_T4    = 0.95                     # Tier 4 ISOLATE

# Spec §5.3 — A&AI dedup window for Tier 3 (sec)
DEDUP_WINDOW_S = 30.0


class Tier(IntEnum):
    NORMAL   = 0
    ALERT    = 1
    PREEMPT  = 2
    MITIGATE = 3
    ISOLATE  = 4


TIER_LABEL = {
    Tier.NORMAL:   'NORMAL   — baseline monitoring at 500ms',
    Tier.ALERT:    'ALERT    — telemetry 200ms + capacity hint',
    Tier.PREEMPT:  'PREEMPT  — pre-position scrubber (warm standby)',
    Tier.MITIGATE: 'MITIGATE — insert CNF into SFC + rate-limit',
    Tier.ISOLATE:  'ISOLATE  — full scrubbing + source blackhole',
}

# Default per-tier CNF profile (overridden by attack_type for Tier 3+)
TIER_DEFAULT_CNF_PROFILE = {
    Tier.NORMAL:   None,
    Tier.ALERT:    None,
    Tier.PREEMPT:  'cnf-scrubber-warm-standby',
    Tier.MITIGATE: 'cnf-scrubber-reflection',
    Tier.ISOLATE:  'cnf-scrubber-blackhole',
}

# Backwards-compat: the orchestrator's existing onap_so_client uses
# vnfd-* identifiers; map our spec-aligned profile names back to those.
CNF_PROFILE_TO_VNFD = {
    'cnf-scrubber-reflection':         'vnfd-scrubber-v1',
    'cnf-scrubber-syn-proxy':          'vnfd-scrubber-v1',
    'cnf-rate-limiter-app-layer':      'vnfd-ratelimiter-v1',
    'cnf-rate-limiter-token-bucket':   'vnfd-ratelimiter-v1',
    'cnf-scrubber-warm-standby':       'vnfd-ratelimiter-v1',
    'cnf-scrubber-blackhole':          'vnfd-blackhole-v1',
}

# Legacy aliases retained so existing callers keep working
TIER_VNF_PROFILE = {
    Tier.NORMAL:   None,
    Tier.ALERT:    None,
    Tier.PREEMPT:  'vnfd-ratelimiter-v1',
    Tier.MITIGATE: 'vnfd-scrubber-v1',
    Tier.ISOLATE:  'vnfd-blackhole-v1',
}
VNF_DOCKER_IMAGE = {
    'vnfd-ratelimiter-v1': 'pad-vnf-ratelimiter:latest',
    'vnfd-scrubber-v1':    'pad-vnf-scrubber:latest',
    'vnfd-blackhole-v1':   'pad-vnf-blackhole:latest',
}


@dataclass
class TierDecision:
    tier:               Tier
    label:              str
    confidence:         float           # Track A confidence (0 if absent)
    p_attack_1min:      float
    p_attack_5min:      float
    p_attack_15min:     float
    attack_type:        str             # CICDDoS class name (or BENIGN)
    attack_class_id:    int
    triggered_horizon:  Optional[int]   # 1 / 5 / 15 / None
    proactive:          bool            # True if escalated by forecast (Track B)
    cnf_profile:        Optional[str]   # spec-aligned name
    vnfd_profile:       Optional[str]   # legacy ONAP SO descriptor
    source_ip_prefix:   Optional[str]
    target_ip_prefix:   Optional[str]
    tenant_id:          Optional[str]
    severity:           str
    dedup_key:          Optional[str]   # (target_ip_prefix + 30s bucket) for Tier 3
    reason:             str

    # Backwards-compat alias for older callers reading `p_attack_30s`
    @property
    def p_attack_30s(self) -> float:
        return self.p_attack_1min

    @property
    def attack_class(self) -> int:
        return self.attack_class_id

    @property
    def vnf_profile(self) -> Optional[str]:
        return self.vnfd_profile


class TierMapper:
    """
    Stateless mapping: AIOutputPayload (or v3 dict) → TierDecision.

    Usage:
        mapper = TierMapper()
        td     = mapper.decide(payload)        # accepts v3 dataclass or dict
    """

    def __init__(
        self,
        p15_t1: float = P15_T1,
        p5_t2:  float = P5_T2,
        p1_t3:  float = P1_T3,
        conf_t3: float = CONF_T3,
        conf_t4: float = CONF_T4,
        dedup_window_s: float = DEDUP_WINDOW_S,
    ):
        self.p15_t1 = p15_t1
        self.p5_t2  = p5_t2
        self.p1_t3  = p1_t3
        self.conf_t3 = conf_t3
        self.conf_t4 = conf_t4
        self.dedup_window_s = dedup_window_s

    def decide(self, payload) -> TierDecision:
        """
        Compute the tier decision for an AI output payload.

        Args:
            payload : either a v3 `AIOutputPayload` dataclass or a dict shaped
                      per Spec §4.6.  Older v2 payloads are also accepted
                      (read via attribute fallbacks).
        """
        det      = self._read_detection(payload)
        fc       = self._read_forecast(payload)
        ip_meta  = self._read_ip_meta(payload)

        attack_type = det.get('attack_type', 'BENIGN')
        attack_id   = int(det.get('attack_class_id', det.get('attack_class', 0)))
        conf        = float(det.get('confidence', 0.0))
        is_attack   = bool(det.get('is_attack', attack_id != 0))

        p1  = float(fc.get('p_attack_1min',  fc.get('p_attack_30s',  0.0)))
        p5  = float(fc.get('p_attack_5min',  fc.get('p_attack_60s',  0.0)))
        p15 = float(fc.get('p_attack_15min', fc.get('p_attack_120s', 0.0)))
        triggered = fc.get('triggered_horizon')

        # ── Default tier ── BENIGN traffic short-circuits to NORMAL ──────────
        if attack_id == 0 and conf < self.p15_t1 and p15 < self.p15_t1:
            tier   = Tier.NORMAL
            reason = f'BENIGN (conf={conf:.3f}, P15={p15:.3f})'
            proactive = False
        else:
            tier, reason, proactive = self._compute_tier(
                conf=conf, p1=p1, p5=p5, p15=p15, attack_type=attack_type,
            )

        cnf_profile = self._select_cnf_profile(tier, attack_type)
        vnfd        = CNF_PROFILE_TO_VNFD.get(cnf_profile or '',
                                              TIER_VNF_PROFILE.get(tier))

        severity = self._severity(conf, p1, p5)
        dedup    = self._dedup_key(tier, ip_meta.get('target_ip_prefix'))

        return TierDecision(
            tier              = tier,
            label             = TIER_LABEL[tier],
            confidence        = conf,
            p_attack_1min     = p1,
            p_attack_5min     = p5,
            p_attack_15min    = p15,
            attack_type       = attack_type,
            attack_class_id   = attack_id,
            triggered_horizon = triggered,
            proactive         = proactive,
            cnf_profile       = cnf_profile,
            vnfd_profile      = vnfd,
            source_ip_prefix  = ip_meta.get('source_ip_prefix'),
            target_ip_prefix  = ip_meta.get('target_ip_prefix'),
            tenant_id         = ip_meta.get('tenant_id'),
            severity          = severity,
            dedup_key         = dedup,
            reason            = reason,
        )

    # ── Tier computation ────────────────────────────────────────────────────

    def _compute_tier(
        self, *, conf: float, p1: float, p5: float, p15: float, attack_type: str,
    ) -> tuple[Tier, str, bool]:
        """
        Resolve tier per Spec §5.3.  `proactive` flags whether the trigger came
        from Track B (forecast) rather than Track A (reactive detection).
        """
        # Tier 4 ISOLATE — strictly reactive (Track A high confidence)
        if conf >= self.conf_t4:
            return (
                Tier.ISOLATE,
                f'Track A conf={conf:.3f} ≥ {self.conf_t4} → ISOLATE',
                False,
            )

        # Tier 3 MITIGATE — disjunctive (forecast OR reactive)
        if p1 >= self.p1_t3 or conf >= self.conf_t3:
            forecast_path = p1 >= self.p1_t3
            reactive_path = conf >= self.conf_t3
            if forecast_path and reactive_path:
                src = f'P1={p1:.3f}≥{self.p1_t3} AND conf={conf:.3f}≥{self.conf_t3}'
                proactive = False   # reactive path wins when both fire
            elif forecast_path:
                src = f'P1={p1:.3f} ≥ {self.p1_t3} (forecast path)'
                proactive = True
            else:
                src = f'conf={conf:.3f} ≥ {self.conf_t3} (Track A reactive)'
                proactive = False
            return (
                Tier.MITIGATE,
                f'{attack_type} → MITIGATE  [{src}]',
                proactive,
            )

        # Tier 2 PREEMPT — Track B mid-horizon (proactive pre-positioning)
        if p5 >= self.p5_t2:
            return (
                Tier.PREEMPT,
                f'P5={p5:.3f} ≥ {self.p5_t2} → PREEMPT (proactive)',
                True,
            )

        # Tier 1 ALERT — Track B long-horizon early warning
        if p15 >= self.p15_t1:
            return (
                Tier.ALERT,
                f'P15={p15:.3f} ≥ {self.p15_t1} → ALERT (proactive)',
                True,
            )

        # Otherwise NORMAL
        return (
            Tier.NORMAL,
            f'all signals below thresholds (conf={conf:.3f}, P15={p15:.3f})',
            False,
        )

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _select_cnf_profile(tier: Tier, attack_type: str) -> Optional[str]:
        """
        Pick a CNF profile based on tier + attack_type (Spec §5.3 fragment).
        For Tier 3+ the attack class drives the CNF mode; for Tier 0/1 there is
        no CNF action; Tier 2 uses a generic warm standby scrubber.
        """
        if tier in (Tier.NORMAL, Tier.ALERT):
            return None
        if tier == Tier.PREEMPT:
            return TIER_DEFAULT_CNF_PROFILE[Tier.PREEMPT]
        if tier == Tier.ISOLATE:
            return TIER_DEFAULT_CNF_PROFILE[Tier.ISOLATE]
        # Tier 3 MITIGATE: per-attack-type routing
        return ATTACK_TYPE_TO_CNF_PROFILE.get(
            attack_type, TIER_DEFAULT_CNF_PROFILE[Tier.MITIGATE],
        )

    @staticmethod
    def _severity(conf: float, p1: float, p5: float) -> str:
        if conf >= CONF_T4 or p1 >= 0.95:
            return 'CRITICAL'
        if conf >= CONF_T3 or p1 >= P1_T3:
            return 'MAJOR'
        if p5 >= P5_T2:
            return 'MINOR'
        return 'INFO'

    def _dedup_key(self, tier: Tier, target_ip_prefix: Optional[str]) -> Optional[str]:
        """Tier-3 dedup key per Spec §5.3 (`target_ip_prefix + 30s window`)."""
        if tier != Tier.MITIGATE:
            return None
        bucket = int(time.time() // self.dedup_window_s)
        return f'{target_ip_prefix or "unknown"}::{bucket}'

    # ── Payload accessors (handle dataclass, dict v3, or legacy v2) ─────────

    @staticmethod
    def _read_detection(payload) -> dict:
        if payload is None:
            return {}
        # AIOutputPayload-style with .detection dataclass
        det_obj = getattr(payload, 'detection', None)
        if det_obj is not None and hasattr(det_obj, '__dict__'):
            d = dict(det_obj.__dict__)
            return {
                'attack_type':     d.get('attack_type', 'BENIGN'),
                'attack_class_id': d.get('attack_class_id', d.get('attack_class', 0)),
                'confidence':      d.get('confidence', 0.0),
                'is_attack':       d.get('is_attack', d.get('attack_class', 0) != 0),
            }
        # Dict payload
        if isinstance(payload, dict):
            d = payload.get('detection', {}) or {}
            return d
        return {}

    @staticmethod
    def _read_forecast(payload) -> dict:
        fc_obj = getattr(payload, 'forecast', None)
        if fc_obj is not None and hasattr(fc_obj, '__dict__'):
            return dict(fc_obj.__dict__)
        if isinstance(payload, dict):
            return payload.get('forecast', {}) or {}
        return {}

    @staticmethod
    def _read_ip_meta(payload) -> dict:
        if isinstance(payload, dict):
            return {
                'source_ip_prefix': payload.get('source_ip_prefix'),
                'target_ip_prefix': payload.get('target_ip_prefix'),
                'tenant_id':        payload.get('tenant_id'),
            }
        return {
            'source_ip_prefix': getattr(payload, 'source_ip_prefix', None),
            'target_ip_prefix': getattr(payload, 'target_ip_prefix', None),
            'tenant_id':        getattr(payload, 'tenant_id', None),
        }


# ── Smoke test ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    mapper = TierMapper()

    cases = [
        # (name, dict payload)
        ('benign',  {'detection': {'attack_type': 'BENIGN', 'attack_class_id': 0,
                                    'confidence': 0.10, 'is_attack': False},
                     'forecast':  {'p_attack_1min': 0.10, 'p_attack_5min': 0.20,
                                    'p_attack_15min': 0.30}}),
        ('alert',   {'detection': {'attack_type': 'BENIGN', 'attack_class_id': 0,
                                    'confidence': 0.20},
                     'forecast':  {'p_attack_1min': 0.20, 'p_attack_5min': 0.40,
                                    'p_attack_15min': 0.55}}),
        ('preempt', {'detection': {'attack_type': 'DrDoS_UDP',
                                    'attack_class_id': 8, 'confidence': 0.40},
                     'forecast':  {'p_attack_1min': 0.50, 'p_attack_5min': 0.75,
                                    'p_attack_15min': 0.80}}),
        ('mitigate-forecast',
                    {'detection': {'attack_type': 'Syn',
                                    'attack_class_id': 9, 'confidence': 0.30},
                     'forecast':  {'p_attack_1min': 0.90, 'p_attack_5min': 0.85,
                                    'p_attack_15min': 0.85}}),
        ('mitigate-reactive',
                    {'detection': {'attack_type': 'WebDDoS',
                                    'attack_class_id': 11, 'confidence': 0.90},
                     'forecast':  {'p_attack_1min': 0.40, 'p_attack_5min': 0.50,
                                    'p_attack_15min': 0.60}}),
        ('isolate', {'detection': {'attack_type': 'DrDoS_UDP',
                                    'attack_class_id': 8, 'confidence': 0.97},
                     'forecast':  {'p_attack_1min': 0.95, 'p_attack_5min': 0.85,
                                    'p_attack_15min': 0.80},
                     'target_ip_prefix': '198.51.100.0/24'}),
    ]
    for name, pl in cases:
        td = mapper.decide(pl)
        print(f'  [{name:<22}] T{td.tier} {td.label:<48} '
              f'cnf={td.cnf_profile}  proactive={td.proactive}')

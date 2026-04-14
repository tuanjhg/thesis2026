"""
M3 — Tier Mapper (Spec-aligned §5.1)

5-tier policy framework:
  Tier 0 (NORMAL)   : attack_class == 0  → no action
  Tier 1 (ALERT)    : conf ∈ [0.50–0.70) → increase telemetry sampling
  Tier 2 (PREEMPT)  : conf ∈ [0.70–0.85) → pre-position VNF (no active steering)
  Tier 3 (MITIGATE) : conf ∈ [0.85–0.95) → insert VNF into SFC path
  Tier 4 (ISOLATE)  : conf ∈ [0.95–1.00] → scrubbing + blackholing

Proactive override:
  If P(t+30s) > PROACTIVE_THRESHOLD and current tier < 2 → escalate to Tier 2
  (early pre-positioning before attack reaches full confidence)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)

# ── Tier thresholds ────────────────────────────────────────────────────────────
CONF_T1     = 0.50   # alert
CONF_T2     = 0.70   # preempt
CONF_T3     = 0.85   # mitigate
CONF_T4     = 0.95   # isolate
P30_PROACT  = 0.50   # proactive pre-position trigger (aligned with ai_output.py)


class Tier(IntEnum):
    NORMAL   = 0
    ALERT    = 1
    PREEMPT  = 2
    MITIGATE = 3
    ISOLATE  = 4


TIER_LABEL = {
    Tier.NORMAL:   "NORMAL   — no action",
    Tier.ALERT:    "ALERT    — increase telemetry sampling",
    Tier.PREEMPT:  "PREEMPT  — pre-position VNF (no steering yet)",
    Tier.MITIGATE: "MITIGATE — insert VNF into SFC path",
    Tier.ISOLATE:  "ISOLATE  — scrubbing + blackholing",
}

# ONAP SO NSD/VNF descriptors per tier (used by onap_so_client)
TIER_VNF_PROFILE = {
    Tier.NORMAL:   None,
    Tier.ALERT:    None,
    Tier.PREEMPT:  "vnfd-ratelimiter-v1",
    Tier.MITIGATE: "vnfd-scrubber-v1",
    Tier.ISOLATE:  "vnfd-blackhole-v1",
}

# Docker image names per VNF profile (used by Docker stub mode)
VNF_DOCKER_IMAGE = {
    "vnfd-ratelimiter-v1": "pad-vnf-ratelimiter:latest",
    "vnfd-scrubber-v1":    "pad-vnf-scrubber:latest",
    "vnfd-blackhole-v1":   "pad-vnf-blackhole:latest",
}


@dataclass
class TierDecision:
    """Output of TierMapper.decide()."""
    tier:             Tier
    label:            str
    confidence:       float
    p_attack_30s:     float
    attack_type:      str
    attack_class:     int
    proactive:        bool        # True if escalated by forecast, not detection
    vnf_profile:      Optional[str]
    reason:           str         # human-readable explanation


class TierMapper:
    """
    Stateless mapping: (AIOutputPayload) → TierDecision.

    Usage:
        mapper  = TierMapper()
        payload = engine.infer(features)
        dec     = mapper.decide(payload)
        print(dec.tier, dec.label)
    """

    def __init__(
        self,
        conf_t1:    float = CONF_T1,
        conf_t2:    float = CONF_T2,
        conf_t3:    float = CONF_T3,
        conf_t4:    float = CONF_T4,
        p30_proact: float = P30_PROACT,
    ):
        self.conf_t1    = conf_t1
        self.conf_t2    = conf_t2
        self.conf_t3    = conf_t3
        self.conf_t4    = conf_t4
        self.p30_proact = p30_proact

    def decide(self, payload) -> TierDecision:
        """
        Map AIOutputPayload → TierDecision.

        Args:
            payload: AIOutputPayload from InferenceEngine.infer()

        Returns:
            TierDecision with tier, label, vnf_profile, reason
        """
        conf  = payload.detection.confidence
        cls   = payload.detection.attack_class
        atype = payload.detection.attack_type
        p30   = payload.forecast.p_attack_30s

        proactive = False

        # ── Step 1: base tier from attack class + confidence ──────────────────
        if cls == 0:
            tier = Tier.NORMAL
            reason = f"Normal traffic (class=0, conf={conf:.3f})"
        elif conf >= self.conf_t4:
            tier = Tier.ISOLATE
            reason = f"{atype} conf={conf:.3f} ≥ {self.conf_t4} → ISOLATE"
        elif conf >= self.conf_t3:
            tier = Tier.MITIGATE
            reason = f"{atype} conf={conf:.3f} ≥ {self.conf_t3} → MITIGATE"
        elif conf >= self.conf_t2:
            tier = Tier.PREEMPT
            reason = f"{atype} conf={conf:.3f} ≥ {self.conf_t2} → PREEMPT"
        elif conf >= self.conf_t1:
            tier = Tier.ALERT
            reason = f"{atype} conf={conf:.3f} ≥ {self.conf_t1} → ALERT"
        else:
            tier = Tier.NORMAL
            reason = f"Low confidence ({conf:.3f} < {self.conf_t1})"

        # ── Step 2: proactive escalation from 30s forecast ───────────────────
        if tier < Tier.PREEMPT and p30 >= self.p30_proact:
            tier = Tier.PREEMPT
            proactive = True
            reason = (f"Proactive escalation: P(t+30s)={p30:.3f} ≥ "
                      f"{self.p30_proact} → PREEMPT")

        vnf_profile = TIER_VNF_PROFILE.get(tier)
        return TierDecision(
            tier         = tier,
            label        = TIER_LABEL[tier],
            confidence   = conf,
            p_attack_30s = p30,
            attack_type  = atype,
            attack_class = cls,
            proactive    = proactive,
            vnf_profile  = vnf_profile,
            reason       = reason,
        )


# ── Smoke test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys, types

    logging.basicConfig(level=logging.INFO)
    mapper = TierMapper()

    # Simulate payloads
    cases = [
        # (confidence, p30, attack_class, attack_type)
        (0.10, 0.20, 0, "Normal"),
        (0.55, 0.30, 2, "SYN_Flood"),
        (0.72, 0.45, 2, "SYN_Flood"),
        (0.88, 0.80, 1, "UDP_Flood"),
        (0.97, 0.95, 1, "UDP_Flood"),
        (0.40, 0.65, 2, "SYN_Flood"),  # proactive
    ]

    class _FakeDet:
        def __init__(self, conf, cls, atype):
            self.confidence = conf; self.attack_class = cls; self.attack_type = atype
    class _FakeFore:
        def __init__(self, p30):
            self.p_attack_30s = p30
    class _FakePay:
        def __init__(self, conf, p30, cls, atype):
            self.detection = _FakeDet(conf, cls, atype)
            self.forecast  = _FakeFore(p30)

    for conf, p30, cls, atype in cases:
        dec = mapper.decide(_FakePay(conf, p30, cls, atype))
        print(f"  T{dec.tier} | {dec.label:<52} | {dec.reason}")

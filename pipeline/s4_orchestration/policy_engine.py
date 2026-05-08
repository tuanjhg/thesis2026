"""
M3 — Policy Engine (Spec §5.3 / §5.4 — Guard + Strict-Monotonic Escalation)
===========================================================================

Per-device state machine driving graduated CNF orchestration.

Rules:
  1. Strict-monotonic escalation
       Once Tier N is committed, the device may only escalate (Tier N+1, N+2, …)
       or *demote* via the abatement rule below.  Escalation requires
       `escalate_wins` consecutive windows at the higher tier (hysteresis) so
       transient spikes don't move us.

  2. Abatement / demotion
       Demotion requires *sustained* low signal:
         observed P(attack) < ABATEMENT_P_THRESHOLD       (default 0.30)
         for ABATEMENT_HOLD_S consecutive seconds         (default 60.0)
       Until that condition is met the standby Pod stays warm.

  3. Frequency guard
       At most one Pod-level VNF action per device per FREQ_GUARD_S
       (default 30 s).  Prevents Pod thrashing under flapping signals
       (Spec §5.4 "guard policy").

  4. Tier-3 dedup
       When two Tier-3 events for the same `target_ip_prefix` arrive within
       30 s (Spec §5.3 disjunctive Tier 3), the second is suppressed.

Backwards-compat:
  - `evaluate(device_id, td)` retains the old return shape (`PolicyDecision`).
  - All new params default to spec values, so existing callers don't change.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from .tier_mapper import Tier, TierDecision

logger = logging.getLogger(__name__)

# ── Spec §5.3 / §5.4 defaults ────────────────────────────────────────────────
FREQ_GUARD_S            = 30.0   # max 1 Pod instantiation per device per 30 s
ESCALATE_WINS           = 2      # consecutive windows required to escalate
ABATEMENT_P_THRESHOLD   = 0.30   # P(attack) < 0.30
ABATEMENT_HOLD_S        = 60.0   # sustained for 60 s before demotion
DEDUP_TIER3_WINDOW_S    = 30.0   # Tier-3 dedup per (target_ip_prefix, 30s)


class PolicyAction(Enum):
    HOLD       = 'HOLD'
    ESCALATE   = 'ESCALATE'
    DEESCALATE = 'DEESCALATE'
    NEW_ATTACK = 'NEW_ATTACK'
    SUPPRESSED = 'SUPPRESSED'    # blocked by Tier-3 dedup


@dataclass
class PolicyDecision:
    device_id:     str
    prev_tier:     Tier
    new_tier:      Tier
    action:        PolicyAction
    tier_decision: TierDecision
    timestamp:     float
    acted:         bool
    guard_reason:  str


class _DeviceState:
    """Per-device mutable state."""
    def __init__(self):
        self.current_tier:    Tier  = Tier.NORMAL
        self.last_action_ts:  float = 0.0
        # Track last consecutive-windows buffer (used for escalate hysteresis)
        self.window_buf:      deque = deque(maxlen=max(ESCALATE_WINS, 8))
        # Abatement tracker: when did P(attack) first drop below threshold?
        self.below_threshold_since: Optional[float] = None
        # Track-3 dedup: target_ip_prefix → (last_seen_ts, last_dedup_key)
        self.tier3_seen:      Dict[str, tuple[float, str]] = {}


class PolicyEngine:
    """
    Stateful policy engine.  One instance per pipeline run.

    Spec rule summary (§5.3 / §5.4):
      Escalate           : strict monotonic; needs `escalate_wins` consecutive
                           windows at the target tier
      De-escalate        : only after P(attack) < 0.30 for 60 s
      Frequency guard    : ≤ 1 Pod-level action / device / 30 s
      Tier-3 dedup       : suppress duplicate Tier-3 events for same target
                           prefix within 30 s
    """

    def __init__(
        self,
        freq_guard_s:           float = FREQ_GUARD_S,
        escalate_wins:          int   = ESCALATE_WINS,
        abatement_p_threshold:  float = ABATEMENT_P_THRESHOLD,
        abatement_hold_s:       float = ABATEMENT_HOLD_S,
        dedup_tier3_window_s:   float = DEDUP_TIER3_WINDOW_S,
        eval_mode:              bool  = False,
    ):
        self.freq_guard_s          = 0.0 if eval_mode else freq_guard_s
        self.escalate_wins         = escalate_wins
        self.abatement_p_threshold = abatement_p_threshold
        self.abatement_hold_s      = abatement_hold_s
        self.dedup_tier3_window_s  = dedup_tier3_window_s
        self._states: Dict[str, _DeviceState] = defaultdict(_DeviceState)

    # ── Main entry point ────────────────────────────────────────────────────

    def evaluate(self, device_id: str, td: TierDecision) -> PolicyDecision:
        now   = time.time()
        state = self._states[device_id]
        prev  = state.current_tier
        want  = td.tier

        state.window_buf.append(want)

        # Track abatement: P(attack) for this evaluation
        observed_p = self._observed_p(td)
        self._update_abatement(state, observed_p, now)

        # ── Tier-3 dedup (Spec §5.3) ────────────────────────────────────────
        if td.tier == Tier.MITIGATE and td.target_ip_prefix:
            seen = state.tier3_seen.get(td.target_ip_prefix)
            if seen and now - seen[0] < self.dedup_tier3_window_s and seen[1] == td.dedup_key:
                return self._held(
                    device_id, prev, td, now, action=PolicyAction.SUPPRESSED,
                    reason=(f'Tier-3 dedup: {td.target_ip_prefix} already '
                            f'mitigated within {self.dedup_tier3_window_s}s'),
                )
            # Record (will be committed only if escalation actually fires)

        # ── Determine logical movement ──────────────────────────────────────
        if want > prev:
            return self._handle_escalate(device_id, state, prev, want, td, now)
        if want < prev:
            return self._handle_deescalate(device_id, state, prev, want, td, now)

        # Same tier — no action
        return PolicyDecision(
            device_id     = device_id,
            prev_tier     = prev,
            new_tier      = prev,
            action        = PolicyAction.HOLD,
            tier_decision = td,
            timestamp     = now,
            acted         = True,
            guard_reason  = '',
        )

    # ── Escalation path ─────────────────────────────────────────────────────

    def _handle_escalate(
        self, device_id, state, prev: Tier, want: Tier,
        td: TierDecision, now: float,
    ) -> PolicyDecision:
        # Hysteresis: require N consecutive windows at `want`
        recent = list(state.window_buf)[-self.escalate_wins:]
        if len(recent) < self.escalate_wins or any(t < want for t in recent):
            return self._held(
                device_id, prev, td, now,
                reason=(f'Escalation hysteresis: need {self.escalate_wins} '
                        f'consecutive windows at T{int(want)}'),
            )

        # Frequency guard
        elapsed = now - state.last_action_ts
        if state.last_action_ts > 0 and elapsed < self.freq_guard_s:
            remaining = self.freq_guard_s - elapsed
            return self._held(
                device_id, prev, td, now,
                reason=(f'Frequency guard: {remaining:.1f}s remaining '
                        f'(min_interval={self.freq_guard_s:.0f}s)'),
            )

        # Commit escalation
        state.current_tier   = want
        state.last_action_ts = now
        state.below_threshold_since = None

        if td.tier == Tier.MITIGATE and td.target_ip_prefix and td.dedup_key:
            state.tier3_seen[td.target_ip_prefix] = (now, td.dedup_key)

        action = PolicyAction.NEW_ATTACK if prev == Tier.NORMAL else PolicyAction.ESCALATE
        logger.info(
            f'[Policy] device={device_id} {action.value} '
            f'T{int(prev)}→T{int(want)}  reason={td.reason}'
        )
        return PolicyDecision(
            device_id     = device_id,
            prev_tier     = prev,
            new_tier      = want,
            action        = action,
            tier_decision = td,
            timestamp     = now,
            acted         = True,
            guard_reason  = '',
        )

    # ── De-escalation path ──────────────────────────────────────────────────

    def _handle_deescalate(
        self, device_id, state, prev: Tier, want: Tier,
        td: TierDecision, now: float,
    ) -> PolicyDecision:
        """
        Spec §5.3 abatement: demote only after P(attack) < 0.30 for 60 s
        (sustained).  Until then we *hold* the higher tier — Pod stays warm.
        """
        if state.below_threshold_since is None:
            return self._held(
                device_id, prev, td, now,
                reason=('Abatement: waiting for sustained '
                        f'P(attack)<{self.abatement_p_threshold:.2f}'),
            )

        sustained = now - state.below_threshold_since
        if sustained < self.abatement_hold_s:
            return self._held(
                device_id, prev, td, now,
                reason=(f'Abatement: P(attack) low for {sustained:.1f}s, '
                        f'need ≥ {self.abatement_hold_s:.0f}s'),
            )

        # Frequency guard also applies to demotions to prevent Pod churn
        elapsed = now - state.last_action_ts
        if state.last_action_ts > 0 and elapsed < self.freq_guard_s:
            return self._held(
                device_id, prev, td, now,
                reason=(f'Frequency guard (demotion): {self.freq_guard_s - elapsed:.1f}s '
                        f'remaining'),
            )

        state.current_tier   = want
        state.last_action_ts = now
        state.below_threshold_since = None

        logger.info(
            f'[Policy] device={device_id} DEESCALATE T{int(prev)}→T{int(want)} '
            f'(abatement {sustained:.1f}s)'
        )
        return PolicyDecision(
            device_id     = device_id,
            prev_tier     = prev,
            new_tier      = want,
            action        = PolicyAction.DEESCALATE,
            tier_decision = td,
            timestamp     = now,
            acted         = True,
            guard_reason  = '',
        )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _update_abatement(self, state: _DeviceState, observed_p: float, now: float):
        if observed_p < self.abatement_p_threshold:
            if state.below_threshold_since is None:
                state.below_threshold_since = now
        else:
            state.below_threshold_since = None

    @staticmethod
    def _observed_p(td: TierDecision) -> float:
        """
        Best representative `P(attack)` for this tier decision.

        Use Track A confidence if it ever rose above 0.5 (real attack signal),
        otherwise the strongest forecast horizon — that way the abatement
        timer starts from whichever signal triggered the original escalation.
        """
        if td.confidence >= 0.5:
            return td.confidence
        return max(td.p_attack_1min, td.p_attack_5min, td.p_attack_15min)

    def _held(
        self, device_id: str, prev: Tier, td: TierDecision, now: float,
        reason: str, action: PolicyAction = PolicyAction.HOLD,
    ) -> PolicyDecision:
        return PolicyDecision(
            device_id     = device_id,
            prev_tier     = prev,
            new_tier      = prev,
            action        = action,
            tier_decision = td,
            timestamp     = now,
            acted         = (action == PolicyAction.SUPPRESSED),  # acted-upon for logs
            guard_reason  = reason,
        )

    # ── Inspection / cleanup ────────────────────────────────────────────────

    def get_tier(self, device_id: str) -> Tier:
        return self._states[device_id].current_tier

    def reset(self, device_id: str):
        if device_id in self._states:
            self._states[device_id] = _DeviceState()


# ── Smoke test ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    from pipeline.s4_orchestration.tier_mapper import TierMapper

    mapper = TierMapper()
    engine = PolicyEngine(eval_mode=True)
    device = '10.20.0.0/16'
    sample_payloads = [
        {'detection': {'attack_type': 'BENIGN', 'attack_class_id': 0,
                        'confidence': 0.05},
         'forecast': {'p_attack_1min': 0.0, 'p_attack_5min': 0.0,
                       'p_attack_15min': 0.0}},
        {'detection': {'attack_type': 'DrDoS_UDP', 'attack_class_id': 8,
                        'confidence': 0.4},
         'forecast': {'p_attack_1min': 0.5, 'p_attack_5min': 0.8,
                       'p_attack_15min': 0.8}},
        {'detection': {'attack_type': 'DrDoS_UDP', 'attack_class_id': 8,
                        'confidence': 0.92},
         'forecast': {'p_attack_1min': 0.91, 'p_attack_5min': 0.85,
                       'p_attack_15min': 0.7},
         'target_ip_prefix': '198.51.100.0/24'},
    ]
    for pl in sample_payloads:
        td  = mapper.decide(pl)
        pdc = engine.evaluate(device, td)
        print(f'  T{td.tier}  action={pdc.action.value:<12} '
              f'acted={pdc.acted}  guard={pdc.guard_reason}')

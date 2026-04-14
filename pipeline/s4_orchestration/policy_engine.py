"""
M3 — Policy Engine (Spec-aligned §5.2)

Responsibilities:
  - Per-device state machine: track current tier, escalation history
  - Frequency guard: prevent VNF thrashing (min_interval between tier changes)
  - Hysteresis: require N consecutive windows at tier Y before escalating
  - De-escalation: require M consecutive windows at lower tier before downgrading
  - Emits PolicyDecision with action (ESCALATE / DEESCALATE / HOLD / NEW_ATTACK)

Plug-and-play:
  - device_id = source IP or ONAP service instance ID (configurable)
  - All timing/hysteresis params tunable at construction time
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

from .tier_mapper import Tier, TierDecision

logger = logging.getLogger(__name__)

# ── Defaults ───────────────────────────────────────────────────────────────────
MIN_INTERVAL_S   = 10.0   # minimum seconds between tier change actions
ESCALATE_WINS    = 2      # consecutive windows at higher tier → escalate
DEESCALATE_WINS  = 5      # consecutive windows at lower tier  → de-escalate


class PolicyAction(Enum):
    HOLD        = "HOLD"           # no change
    ESCALATE    = "ESCALATE"       # move to higher tier
    DEESCALATE  = "DEESCALATE"     # move to lower tier
    NEW_ATTACK  = "NEW_ATTACK"     # first detection (from NORMAL)


@dataclass
class PolicyDecision:
    """Output of PolicyEngine.evaluate()."""
    device_id:      str
    prev_tier:      Tier
    new_tier:       Tier
    action:         PolicyAction
    tier_decision:  TierDecision
    timestamp:      float          # time.time()
    acted:          bool           # False = held by frequency guard
    guard_reason:   str            # why guard blocked (empty if acted)


class _DeviceState:
    """Per-device mutable state."""
    def __init__(self):
        self.current_tier:   Tier  = Tier.NORMAL
        self.last_action_ts: float = 0.0
        self.window_buf:     deque = deque(maxlen=max(ESCALATE_WINS,
                                                      DEESCALATE_WINS) + 2)

    def push(self, tier: Tier):
        self.window_buf.append(tier)

    def consecutive_at(self, tier: Tier, n: int) -> bool:
        """True if last n windows were all at `tier`."""
        if len(self.window_buf) < n:
            return False
        return all(t == tier for t in list(self.window_buf)[-n:])


class PolicyEngine:
    """
    Stateful policy engine.  One instance per pipeline run.

    Usage:
        engine  = InferenceEngine.load(...)
        mapper  = TierMapper()
        policy  = PolicyEngine()

        while True:
            payload = engine.infer(features)
            dec     = mapper.decide(payload)
            pdec    = policy.evaluate(device_id, dec)
            if pdec.acted and pdec.action != PolicyAction.HOLD:
                onap_so_client.apply(pdec)
    """

    def __init__(
        self,
        min_interval_s:  float = MIN_INTERVAL_S,
        escalate_wins:   int   = ESCALATE_WINS,
        deescalate_wins: int   = DEESCALATE_WINS,
        eval_mode:       bool  = False,   # bypass frequency guard in replay/eval
    ):
        self.min_interval_s  = min_interval_s if not eval_mode else 0.0
        self.escalate_wins   = escalate_wins
        self.deescalate_wins = deescalate_wins
        self._states: Dict[str, _DeviceState] = defaultdict(_DeviceState)

    def evaluate(self, device_id: str, td: TierDecision) -> PolicyDecision:
        """
        Evaluate tier decision against device state and frequency guard.

        Args:
            device_id: str key (e.g. source IP, ONAP service instance UUID)
            td:        TierDecision from TierMapper.decide()

        Returns:
            PolicyDecision — describes what action (if any) should be taken
        """
        now   = time.time()
        state = self._states[device_id]
        prev  = state.current_tier
        want  = td.tier

        state.push(want)

        # ── Determine logical action ───────────────────────────────────────────
        if want > prev:
            need  = self.escalate_wins
            check = state.consecutive_at(want, need)
            if not check:
                # Not enough consecutive windows yet → hold
                return PolicyDecision(
                    device_id     = device_id,
                    prev_tier     = prev,
                    new_tier      = prev,
                    action        = PolicyAction.HOLD,
                    tier_decision = td,
                    timestamp     = now,
                    acted         = False,
                    guard_reason  = (f"Escalation hysteresis: need {need} consecutive "
                                     f"windows at T{want}, have "
                                     f"{sum(1 for t in state.window_buf if t == want)}"),
                )
            if prev == Tier.NORMAL:
                action = PolicyAction.NEW_ATTACK
            else:
                action = PolicyAction.ESCALATE

        elif want < prev:
            need  = self.deescalate_wins
            check = state.consecutive_at(want, need)
            if not check:
                return PolicyDecision(
                    device_id     = device_id,
                    prev_tier     = prev,
                    new_tier      = prev,
                    action        = PolicyAction.HOLD,
                    tier_decision = td,
                    timestamp     = now,
                    acted         = False,
                    guard_reason  = (f"De-escalation hysteresis: need {need} consecutive "
                                     f"windows at T{want}, have "
                                     f"{sum(1 for t in state.window_buf if t == want)}"),
                )
            action = PolicyAction.DEESCALATE

        else:
            # Same tier → HOLD (no VNF action needed)
            return PolicyDecision(
                device_id     = device_id,
                prev_tier     = prev,
                new_tier      = prev,
                action        = PolicyAction.HOLD,
                tier_decision = td,
                timestamp     = now,
                acted         = True,
                guard_reason  = "",
            )

        # ── Frequency guard ────────────────────────────────────────────────────
        elapsed = now - state.last_action_ts
        if elapsed < self.min_interval_s:
            remaining = self.min_interval_s - elapsed
            return PolicyDecision(
                device_id     = device_id,
                prev_tier     = prev,
                new_tier      = prev,
                action        = PolicyAction.HOLD,
                tier_decision = td,
                timestamp     = now,
                acted         = False,
                guard_reason  = (f"Frequency guard: {remaining:.1f}s remaining "
                                 f"(min_interval={self.min_interval_s}s)"),
            )

        # ── Commit tier change ─────────────────────────────────────────────────
        state.current_tier   = want
        state.last_action_ts = now

        pdec = PolicyDecision(
            device_id     = device_id,
            prev_tier     = prev,
            new_tier      = want,
            action        = action,
            tier_decision = td,
            timestamp     = now,
            acted         = True,
            guard_reason  = "",
        )

        logger.info(
            f"[Policy] device={device_id}  {action.value}  "
            f"T{prev}→T{want}  reason={td.reason}"
        )
        return pdec

    def get_tier(self, device_id: str) -> Tier:
        return self._states[device_id].current_tier

    def reset(self, device_id: str):
        """Reset device state (call after graceful teardown)."""
        if device_id in self._states:
            self._states[device_id] = _DeviceState()

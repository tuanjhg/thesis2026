"""
ProDDoS-NFV — Policy Engine
============================
Maps ML-predicted attack types to specific VNF orchestration actions.

This module implements the core decision logic:
  prediction (attack_type, confidence) → action (scale VNF, reconfigure SFC, rate-limit)

Usage:
    engine = PolicyEngine()
    action = engine.decide(prediction)
"""
import json
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("proddos.policy")


# ── Data Classes ─────────────────────────────────────────────────

class ActionType(Enum):
    NONE = "none"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    RATE_LIMIT = "rate_limit"
    BLACKHOLE = "blackhole"
    SFC_INSERT = "sfc_insert"
    SFC_REMOVE = "sfc_remove"
    ALERT = "alert"


@dataclass
class Prediction:
    """ML model prediction output."""
    attack_type: str
    confidence: float
    class_probabilities: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    flow_id: str = ""


@dataclass
class OrchestrationAction:
    """Action to be executed by the VNF manager."""
    action_type: ActionType
    vnf_type: str  # e.g., "dns_scrubber", "syn_proxy", "rate_limiter"
    parameters: dict = field(default_factory=dict)
    priority: int = 5  # 1=highest, 10=lowest
    reason: str = ""
    prediction: Optional[Prediction] = None
    timestamp: float = field(default_factory=time.time)


# ── Attack-to-Action Mapping ─────────────────────────────────────

# Each attack type maps to a list of actions with their parameters
DEFAULT_ATTACK_ACTIONS = {
    "DrDoS_DNS": {
        "vnf_type": "dns_scrubber",
        "actions": [
            {"type": ActionType.SFC_INSERT, "vnf": "dns_scrubber", "priority": 2},
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 53, "limit_mbps": 100}},
        ],
        "scale_factor": 2,
    },
    "DrDoS_LDAP": {
        "vnf_type": "ldap_filter",
        "actions": [
            {"type": ActionType.SFC_INSERT, "vnf": "ldap_filter", "priority": 2},
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 389, "limit_mbps": 50}},
        ],
        "scale_factor": 2,
    },
    "DrDoS_MSSQL": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 1434, "limit_mbps": 50}},
            {"type": ActionType.SFC_INSERT, "vnf": "generic_scrubber", "priority": 3},
        ],
        "scale_factor": 1,
    },
    "DrDoS_NetBIOS": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 137, "limit_mbps": 30}},
        ],
        "scale_factor": 1,
    },
    "DrDoS_NTP": {
        "vnf_type": "ntp_scrubber",
        "actions": [
            {"type": ActionType.SFC_INSERT, "vnf": "ntp_scrubber", "priority": 2},
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 123, "limit_mbps": 100}},
        ],
        "scale_factor": 2,
    },
    "DrDoS_SNMP": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 161, "limit_mbps": 50}},
        ],
        "scale_factor": 1,
    },
    "DrDoS_SSDP": {
        "vnf_type": "ssdp_filter",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 1900, "limit_mbps": 50}},
            {"type": ActionType.SFC_INSERT, "vnf": "ssdp_filter", "priority": 3},
        ],
        "scale_factor": 2,
    },
    "DrDoS_UDP": {
        "vnf_type": "rate_limiter",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "limit_mbps": 200}},
            {"type": ActionType.SCALE_OUT, "vnf": "rate_limiter", "priority": 2},
        ],
        "scale_factor": 3,
    },
    "Syn": {
        "vnf_type": "syn_proxy",
        "actions": [
            {"type": ActionType.SFC_INSERT, "vnf": "syn_proxy", "priority": 1},
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "tcp", "flags": "SYN", "limit_pps": 50000}},
        ],
        "scale_factor": 2,
    },
    "TFTP": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 69, "limit_mbps": 20}},
        ],
        "scale_factor": 1,
    },
    "UDPLag": {
        "vnf_type": "rate_limiter",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "limit_mbps": 100}},
        ],
        "scale_factor": 1,
    },
    "Portmap": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 111, "limit_mbps": 30}},
        ],
        "scale_factor": 1,
    },
    "UDP": {
        "vnf_type": "rate_limiter",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "limit_mbps": 200}},
            {"type": ActionType.SCALE_OUT, "vnf": "rate_limiter", "priority": 2},
        ],
        "scale_factor": 2,
    },
    "LDAP": {
        "vnf_type": "ldap_filter",
        "actions": [
            {"type": ActionType.SFC_INSERT, "vnf": "ldap_filter", "priority": 2},
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 389, "limit_mbps": 50}},
        ],
        "scale_factor": 2,
    },
    "MSSQL": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 1434, "limit_mbps": 50}},
        ],
        "scale_factor": 1,
    },
    "NetBIOS": {
        "vnf_type": "generic_scrubber",
        "actions": [
            {"type": ActionType.RATE_LIMIT, "vnf": "rate_limiter",
             "params": {"protocol": "udp", "port": 137, "limit_mbps": 30}},
        ],
        "scale_factor": 1,
    },
}


class PolicyEngine:
    """
    Decision engine that maps ML predictions to orchestration actions.

    Confidence thresholds:
        - HIGH (>=0.8): Full mitigation (insert VNFs + rate limit + scale)
        - MEDIUM (>=0.6): Partial mitigation (rate limit only)
        - LOW (<0.6): Alert only (log for human review)
    """

    def __init__(
        self,
        confidence_high: float = 0.8,
        confidence_medium: float = 0.6,
        cooldown_seconds: float = 30.0,
        attack_actions: Optional[dict] = None,
    ):
        self.confidence_high = confidence_high
        self.confidence_medium = confidence_medium
        self.cooldown_seconds = cooldown_seconds
        self.attack_actions = attack_actions or DEFAULT_ATTACK_ACTIONS

        # Track active mitigations to avoid duplicate actions
        self._active_mitigations: dict[str, float] = {}  # attack_type → timestamp
        self._action_history: list[OrchestrationAction] = []

    def decide(self, prediction: Prediction) -> list[OrchestrationAction]:
        """
        Given a prediction, return a list of orchestration actions.

        Returns empty list for BENIGN traffic or low-confidence predictions.
        """
        actions = []

        # Benign traffic → no action
        if prediction.attack_type == "BENIGN":
            return actions

        # Check cooldown: avoid re-triggering same mitigation too quickly
        if prediction.attack_type in self._active_mitigations:
            elapsed = prediction.timestamp - self._active_mitigations[prediction.attack_type]
            if elapsed < self.cooldown_seconds:
                logger.debug(
                    f"Cooldown active for {prediction.attack_type} "
                    f"({elapsed:.1f}s < {self.cooldown_seconds}s)"
                )
                return actions

        # Low confidence → alert only
        if prediction.confidence < self.confidence_medium:
            actions.append(OrchestrationAction(
                action_type=ActionType.ALERT,
                vnf_type="",
                parameters={"message": f"Low-confidence detection: {prediction.attack_type}"},
                priority=8,
                reason=f"Confidence {prediction.confidence:.2f} < {self.confidence_medium}",
                prediction=prediction,
            ))
            return actions

        # Lookup attack-specific actions
        attack_config = self.attack_actions.get(prediction.attack_type)
        if not attack_config:
            # Unknown attack type → generic rate limiting
            actions.append(OrchestrationAction(
                action_type=ActionType.RATE_LIMIT,
                vnf_type="rate_limiter",
                parameters={"limit_mbps": 100},
                priority=5,
                reason=f"Unknown attack type: {prediction.attack_type}",
                prediction=prediction,
            ))
            self._active_mitigations[prediction.attack_type] = prediction.timestamp
            return actions

        # HIGH confidence → full mitigation
        if prediction.confidence >= self.confidence_high:
            for action_def in attack_config["actions"]:
                actions.append(OrchestrationAction(
                    action_type=action_def["type"],
                    vnf_type=action_def["vnf"],
                    parameters=action_def.get("params", {}),
                    priority=action_def.get("priority", 3),
                    reason=(
                        f"High-confidence {prediction.attack_type} "
                        f"(conf={prediction.confidence:.2f})"
                    ),
                    prediction=prediction,
                ))

            # Add scale-out if needed
            scale_factor = attack_config.get("scale_factor", 1)
            if scale_factor > 1:
                actions.append(OrchestrationAction(
                    action_type=ActionType.SCALE_OUT,
                    vnf_type=attack_config["vnf_type"],
                    parameters={"replicas": scale_factor},
                    priority=2,
                    reason=f"Scale-out {attack_config['vnf_type']} x{scale_factor}",
                    prediction=prediction,
                ))

        # MEDIUM confidence → only rate limiting
        elif prediction.confidence >= self.confidence_medium:
            for action_def in attack_config["actions"]:
                if action_def["type"] == ActionType.RATE_LIMIT:
                    actions.append(OrchestrationAction(
                        action_type=ActionType.RATE_LIMIT,
                        vnf_type=action_def["vnf"],
                        parameters=action_def.get("params", {}),
                        priority=action_def.get("priority", 5),
                        reason=(
                            f"Medium-confidence {prediction.attack_type} "
                            f"(conf={prediction.confidence:.2f})"
                        ),
                        prediction=prediction,
                    ))

        # Update active mitigations
        self._active_mitigations[prediction.attack_type] = prediction.timestamp
        self._action_history.extend(actions)

        logger.info(
            f"PolicyEngine: {prediction.attack_type} "
            f"(conf={prediction.confidence:.2f}) → {len(actions)} actions"
        )
        return actions

    def check_scale_in(self, current_time: float, idle_threshold: float = 120.0) -> list[OrchestrationAction]:
        """
        Check for mitigations that should be scaled in (attack subsided).

        Returns scale-in actions for VNFs that have been idle longer than idle_threshold seconds.
        """
        actions = []
        expired = []

        for attack_type, last_time in self._active_mitigations.items():
            if current_time - last_time > idle_threshold:
                attack_config = self.attack_actions.get(attack_type, {})
                vnf_type = attack_config.get("vnf_type", "rate_limiter")
                actions.append(OrchestrationAction(
                    action_type=ActionType.SCALE_IN,
                    vnf_type=vnf_type,
                    parameters={"attack_type": attack_type},
                    priority=7,
                    reason=f"No {attack_type} traffic for {idle_threshold}s",
                ))
                # Also remove SFC insertions
                actions.append(OrchestrationAction(
                    action_type=ActionType.SFC_REMOVE,
                    vnf_type=vnf_type,
                    parameters={"attack_type": attack_type},
                    priority=7,
                    reason=f"Removing {vnf_type} from SFC (attack subsided)",
                ))
                expired.append(attack_type)

        for attack_type in expired:
            del self._active_mitigations[attack_type]

        return actions

    def get_stats(self) -> dict:
        """Return engine statistics."""
        return {
            "total_actions": len(self._action_history),
            "active_mitigations": len(self._active_mitigations),
            "active_attack_types": list(self._active_mitigations.keys()),
            "action_type_counts": {},
        }

    def reset(self):
        """Reset the engine state."""
        self._active_mitigations.clear()
        self._action_history.clear()


# ── CLI / Testing ─────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = PolicyEngine()

    # Simulate predictions
    test_predictions = [
        Prediction("BENIGN", 0.95),
        Prediction("DrDoS_DNS", 0.92),
        Prediction("Syn", 0.75),
        Prediction("DrDoS_UDP", 0.45),
        Prediction("DrDoS_NTP", 0.88),
    ]

    for pred in test_predictions:
        actions = engine.decide(pred)
        print(f"\n{'='*60}")
        print(f"Prediction: {pred.attack_type} (confidence={pred.confidence:.2f})")
        if not actions:
            print("  → No action (benign or cooldown)")
        for a in actions:
            print(f"  → {a.action_type.value}: {a.vnf_type} "
                  f"(priority={a.priority}, reason={a.reason})")

    print(f"\nEngine stats: {engine.get_stats()}")

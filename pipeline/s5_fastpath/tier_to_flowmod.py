"""Map tier decision (M3 AI output) to OpenFlow Flow-Mod actions."""

from dataclasses import dataclass, field
from typing import Literal


Action = Literal["pass", "monitor", "ratelimit", "redirect", "drop"]


@dataclass
class FlowDirective:
    """High-level mitigation directive translated from a tier decision."""

    action: Action
    # When action == "ratelimit": packets-per-second cap per src IP
    rate_pps: int = 0
    # When action == "redirect": target IP of scrubber pod (set at runtime
    # by ONAP SO once the pod is up)
    redirect_to: str = ""
    # Per-flow installation TTL (seconds) — Ryu clears entry if no refresh
    idle_timeout: int = 30
    # Hard cap on rule lifetime (seconds); 0 = until removed
    hard_timeout: int = 0
    # Match: src IP / dst IP / dport (None = wildcard)
    match: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Tier → FlowDirective mapping
# ─────────────────────────────────────────────────────────────────────────────
TIER_MAP: dict[int, FlowDirective] = {
    0: FlowDirective(action="pass"),
    1: FlowDirective(action="monitor", idle_timeout=60),
    # Tier 2 — token bucket equivalent in the dataplane (OF meter)
    2: FlowDirective(action="ratelimit", rate_pps=5000, idle_timeout=30),
    # Tier 3 — redirect suspicious flows to scrubber VNF pod (IP injected at
    # runtime once SO finishes instantiate). Until then Ryu still rate-limits.
    3: FlowDirective(action="redirect", rate_pps=2000, idle_timeout=20),
    # Tier 4 — drop at the first switch the packet hits (blackhole)
    4: FlowDirective(action="drop", hard_timeout=120),
}


def directive_for(tier: int, attack_type: str = "") -> FlowDirective:
    """Pick a FlowDirective for a tier; lower-bound clamp to 0, upper to 4."""
    tier = max(0, min(4, int(tier)))
    base = TIER_MAP[tier]
    # SYN-flood specific tweak: lower rate cap because SYNs are cheap to spoof
    if base.action == "ratelimit" and attack_type.upper().startswith("SYN"):
        return FlowDirective(
            action=base.action,
            rate_pps=base.rate_pps // 2,
            idle_timeout=base.idle_timeout,
            match=base.match,
        )
    return base

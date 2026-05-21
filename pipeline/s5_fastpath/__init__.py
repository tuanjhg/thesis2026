"""
PAD-ONAP M5 — Fast-path SDN controller (Ryu).

Slow-path (ONAP): pipeline → CLAMP → Policy → SO → kubectl create VNF.
                  Latency ~seconds, full audit trail.

Fast-path (Ryu):  pipeline → REST → Ryu Flow-Mod on OVS switches.
                  Latency ~ms, in-dataplane drop/ratelimit/redirect.

Both paths run in parallel: Ryu kicks in immediately at the switch level,
ONAP closes the loop with a permanent VNF pod for sustained mitigation.
"""

__all__ = ["ryu_app", "scenario_state", "tier_to_flowmod"]

"""
M3/M4 — S4 Orchestration & NFV Enforcement Package (Spec-aligned §5)

Modules:
  tier_mapper     — confidence/forecast → 5-tier policy decision
  policy_engine   — frequency guard, hysteresis, state machine
  sla_allocator   — scipy.linprog SLA fairness for 3 tenants
  clamp_simulator — CLAMP / ONAP Policy Framework stub + real client
  onap_so_client  — ONAP SO VNF lifecycle (real REST + Docker stub)
  latency_tracker — per-stage timestamp instrumentation + Prometheus
  orchestrator    — main M2→M3→M4 loop
"""
from .tier_mapper     import TierMapper, TierDecision, Tier
from .policy_engine   import PolicyEngine
from .sla_allocator   import SLAAllocator
from .clamp_simulator import CLAMPClient
from .onap_so_client  import ONAPSOClient
from .sfc_manager     import SFCManager
from .latency_tracker import LatencyTracker, LatencyRecord
from .orchestrator    import Orchestrator

__all__ = [
    'TierMapper', 'TierDecision', 'Tier',
    'PolicyEngine',
    'SLAAllocator',
    'CLAMPClient',
    'ONAPSOClient',
    'SFCManager',
    'LatencyTracker', 'LatencyRecord',
    'Orchestrator',
]

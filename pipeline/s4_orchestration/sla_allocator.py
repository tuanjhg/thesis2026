"""
M3 — SLA-Aware Allocator (Spec §5.5)
====================================

Bandwidth allocator across multi-tenant slices during a CNF mitigation event.
Implements the two-objective LP from Spec §5.5:

  Minimise   Σ_i  w_i · max(0, SLA_i − BW_i)        [SLA violation cost]
           + λ · CNF_scrub_cost                      [resource cost]

  s.t.       BW_i        ≥ SLA_floor_i               (tenant SLA floors)
             Σ BW_i + BW_scrub ≤ C_total              (link capacity)
             BW_i        ≥ 0
             BW_i        ≤ demand_i                   (no over-allocation)

  w_i        = tenant priority weight  (Gold=3, Silver=2, Bronze=1)
  SLA_floor  = % of contracted BW      (Gold=50%, Silver=30%, Bronze=20%)

Backwards-compat:
  - The old `Tenant(guaranteed_bw_mbps, current_demand_mbps, priority_weight)`
    constructor still works (priority_weight defaults to 1.0).
  - The new helper `TenantTier.GOLD / SILVER / BRONZE` produces a Tenant
    pre-populated with the spec weights and floor ratios.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Spec §5.5 — priority weights
PRIORITY_GOLD   = 3.0
PRIORITY_SILVER = 2.0
PRIORITY_BRONZE = 1.0

# Spec §5.5 — SLA floor as a percentage of contracted bandwidth
FLOOR_RATIO_GOLD   = 0.50   # 50 %
FLOOR_RATIO_SILVER = 0.30   # 30 %
FLOOR_RATIO_BRONZE = 0.20   # 20 %


class TenantTier(str, Enum):
    GOLD   = 'gold'
    SILVER = 'silver'
    BRONZE = 'bronze'

    @property
    def weight(self) -> float:
        return {self.GOLD: PRIORITY_GOLD,
                self.SILVER: PRIORITY_SILVER,
                self.BRONZE: PRIORITY_BRONZE}[self]

    @property
    def floor_ratio(self) -> float:
        return {self.GOLD: FLOOR_RATIO_GOLD,
                self.SILVER: FLOOR_RATIO_SILVER,
                self.BRONZE: FLOOR_RATIO_BRONZE}[self]


@dataclass
class Tenant:
    tenant_id:           str
    guaranteed_bw_mbps:  float                # SLA floor (computed or given)
    current_demand_mbps: float
    priority_weight:     float = PRIORITY_BRONZE
    tier:                Optional[TenantTier] = None
    contracted_bw_mbps:  Optional[float] = None    # used by Tenant.gold/silver/bronze

    @classmethod
    def gold(cls, tenant_id: str, contracted_bw_mbps: float,
             current_demand_mbps: float) -> 'Tenant':
        return cls._tier(tenant_id, contracted_bw_mbps, current_demand_mbps,
                         TenantTier.GOLD)

    @classmethod
    def silver(cls, tenant_id: str, contracted_bw_mbps: float,
               current_demand_mbps: float) -> 'Tenant':
        return cls._tier(tenant_id, contracted_bw_mbps, current_demand_mbps,
                         TenantTier.SILVER)

    @classmethod
    def bronze(cls, tenant_id: str, contracted_bw_mbps: float,
               current_demand_mbps: float) -> 'Tenant':
        return cls._tier(tenant_id, contracted_bw_mbps, current_demand_mbps,
                         TenantTier.BRONZE)

    @classmethod
    def _tier(cls, tenant_id, contracted, demand, tier: TenantTier) -> 'Tenant':
        return cls(
            tenant_id           = tenant_id,
            guaranteed_bw_mbps  = contracted * tier.floor_ratio,
            current_demand_mbps = demand,
            priority_weight     = tier.weight,
            tier                = tier,
            contracted_bw_mbps  = contracted,
        )


@dataclass
class TenantAllocation:
    tenant_id:         str
    alloc_mbps:        float
    guaranteed_mbps:   float
    demand_mbps:       float
    utilisation_pct:   float
    sla_satisfied:     bool
    violation_mbps:    float = 0.0    # max(0, floor − alloc)
    weighted_violation_cost: float = 0.0
    tier:              Optional[str] = None


@dataclass
class AllocationResult:
    success:                  bool
    total_capacity:           float
    vnf_overhead:             float
    available:                float
    allocations:              List[TenantAllocation]
    solver_status:            str
    total_weighted_violation: float = 0.0
    total_resource_cost:      float = 0.0


class SLAAllocator:
    """
    Spec §5.5 LP-based allocator.

    Usage:
        alloc = SLAAllocator(total_bw_mbps=10_000.0, lambda_resource=0.01)
        tenants = [
            Tenant.gold(  'slice-finance', 4000, current_demand_mbps=3500),
            Tenant.silver('slice-eMBB',    3000, current_demand_mbps=2800),
            Tenant.bronze('slice-IoT',     2000, current_demand_mbps=1900),
        ]
        result = alloc.allocate(tenants, vnf_overhead_mbps=500.0,
                                cnf_scrub_cost=1.0)
    """

    def __init__(self, total_bw_mbps: float = 10_000.0,
                 lambda_resource: float = 0.0):
        self.total_bw_mbps   = total_bw_mbps
        self.lambda_resource = lambda_resource

    # ── Main API ────────────────────────────────────────────────────────────

    def allocate(
        self,
        tenants:           List[Tenant],
        vnf_overhead_mbps: float = 0.0,
        cnf_scrub_cost:    float = 0.0,
    ) -> AllocationResult:
        """
        Solve the LP from Spec §5.5 and return per-tenant allocations.
        Falls back to a proportional heuristic if scipy is unavailable or the
        LP is infeasible.
        """
        available = self.total_bw_mbps - vnf_overhead_mbps

        if available <= 0:
            return self._capacity_exhausted(tenants, vnf_overhead_mbps)

        try:
            from scipy.optimize import linprog  # noqa: F401
            return self._lp_allocate(tenants, available, vnf_overhead_mbps,
                                     cnf_scrub_cost)
        except ImportError:
            logger.warning('scipy not available — falling back to proportional')
            return self._proportional_allocate(tenants, available,
                                               vnf_overhead_mbps)

    # ── LP solver (Spec §5.5) ───────────────────────────────────────────────

    def _lp_allocate(
        self,
        tenants:           List[Tenant],
        available:         float,
        vnf_overhead_mbps: float,
        cnf_scrub_cost:    float,
    ) -> AllocationResult:
        """
        Decision vars: x = [BW_1..N, s_1..N]  (slack s_i = max(0, floor_i − BW_i))
        Min   Σ w_i · s_i + λ · cnf_scrub_cost          (constant w.r.t. x)
        s.t.  s_i + BW_i ≥ floor_i        ∀ i           (violation slack)
              0 ≤ BW_i ≤ demand_i         ∀ i
              s_i ≥ 0                     ∀ i
              Σ BW_i ≤ available
        """
        from scipy.optimize import linprog

        n = len(tenants)
        if n == 0:
            return AllocationResult(
                success=True, total_capacity=self.total_bw_mbps,
                vnf_overhead=vnf_overhead_mbps, available=available,
                allocations=[], solver_status='EMPTY',
            )

        weights = np.array([t.priority_weight for t in tenants], dtype=float)
        floors  = np.array([t.guaranteed_bw_mbps for t in tenants], dtype=float)
        demands = np.array([t.current_demand_mbps for t in tenants], dtype=float)

        # Objective: only slack contributes (BW gets zero coefficient — the LP
        # would otherwise be unbounded above; bounds on BW_i + capacity cap it).
        # We add a tiny negative coefficient on BW_i (-ε) to break ties in
        # favour of giving spare capacity to tenants of higher priority.
        eps     = 1e-3
        c_bw    = -eps * weights                                      # BW_i coeffs
        c_slack = weights                                             # s_i coeffs
        c       = np.concatenate([c_bw, c_slack])

        # Inequality A_ub x ≤ b_ub
        # 1) Σ BW_i ≤ available
        A_cap = np.concatenate([np.ones(n), np.zeros(n)])
        b_cap = available
        # 2) -BW_i - s_i ≤ -floor_i        (i.e.  BW_i + s_i ≥ floor_i)
        A_floor = np.zeros((n, 2 * n))
        for i in range(n):
            A_floor[i, i]     = -1.0      # -BW_i
            A_floor[i, n + i] = -1.0      # -s_i
        b_floor = -floors

        A_ub = np.vstack([A_cap, A_floor])
        b_ub = np.concatenate([[b_cap], b_floor])

        # Bounds
        bounds = (
            [(0.0, float(d)) for d in demands]      # BW_i ∈ [0, demand_i]
            + [(0.0, None) for _ in range(n)]       # s_i ≥ 0
        )

        res = linprog(c, A_ub=A_ub, b_ub=b_ub, bounds=bounds, method='highs')

        if res.success:
            allocs = res.x[:n]
            slacks = res.x[n:]
            status = 'OPTIMAL'
        else:
            logger.warning(f'LP infeasible ({res.message}) — using floors')
            allocs = floors.copy()
            slacks = np.zeros(n)
            status = f'LP_INFEASIBLE:{res.message}'

        allocations: List[TenantAllocation] = []
        total_violation = 0.0
        for i, t in enumerate(tenants):
            alloc_i  = float(allocs[i])
            viol_i   = float(max(0.0, t.guaranteed_bw_mbps - alloc_i))
            wviol_i  = viol_i * t.priority_weight
            total_violation += wviol_i
            allocations.append(TenantAllocation(
                tenant_id        = t.tenant_id,
                alloc_mbps       = alloc_i,
                guaranteed_mbps  = t.guaranteed_bw_mbps,
                demand_mbps      = t.current_demand_mbps,
                utilisation_pct  = (alloc_i / t.current_demand_mbps * 100
                                    if t.current_demand_mbps > 0 else 0.0),
                sla_satisfied    = viol_i < 0.01,
                violation_mbps   = viol_i,
                weighted_violation_cost = wviol_i,
                tier             = (t.tier.value if t.tier else None),
            ))

        return AllocationResult(
            success                  = bool(res.success),
            total_capacity           = self.total_bw_mbps,
            vnf_overhead             = vnf_overhead_mbps,
            available                = available,
            allocations              = allocations,
            solver_status            = status,
            total_weighted_violation = total_violation,
            total_resource_cost      = self.lambda_resource * cnf_scrub_cost,
        )

    # ── Fallbacks ───────────────────────────────────────────────────────────

    def _capacity_exhausted(self, tenants, overhead) -> AllocationResult:
        logger.warning(
            f'Capacity exhausted: VNF overhead {overhead:.0f} ≥ total '
            f'{self.total_bw_mbps:.0f} Mbps — issuing floors only'
        )
        allocations = [
            TenantAllocation(
                tenant_id        = t.tenant_id,
                alloc_mbps       = t.guaranteed_bw_mbps,
                guaranteed_mbps  = t.guaranteed_bw_mbps,
                demand_mbps      = t.current_demand_mbps,
                utilisation_pct  = (t.guaranteed_bw_mbps / t.current_demand_mbps * 100
                                    if t.current_demand_mbps > 0 else 0.0),
                sla_satisfied    = True,
                violation_mbps   = 0.0,
                weighted_violation_cost = 0.0,
                tier             = (t.tier.value if t.tier else None),
            ) for t in tenants
        ]
        return AllocationResult(
            success        = False,
            total_capacity = self.total_bw_mbps,
            vnf_overhead   = overhead,
            available      = self.total_bw_mbps - overhead,
            allocations    = allocations,
            solver_status  = 'CAPACITY_EXHAUSTED',
        )

    def _proportional_allocate(
        self, tenants: List[Tenant], available: float, overhead: float,
    ) -> AllocationResult:
        # Step 1: pay floors first, in priority order
        order = sorted(range(len(tenants)),
                       key=lambda i: -tenants[i].priority_weight)
        allocs = [0.0] * len(tenants)
        remaining = available
        for i in order:
            t   = tenants[i]
            pay = min(t.guaranteed_bw_mbps, remaining)
            allocs[i]  = pay
            remaining -= pay

        # Step 2: distribute leftover proportionally to weight × demand-above-floor
        if remaining > 0:
            scores = [
                (i, max(0.0, tenants[i].current_demand_mbps - allocs[i])
                 * tenants[i].priority_weight)
                for i in range(len(tenants))
            ]
            total = sum(s for _, s in scores) or 1.0
            for i, s in scores:
                add = remaining * s / total
                allocs[i] = min(tenants[i].current_demand_mbps, allocs[i] + add)

        allocations: List[TenantAllocation] = []
        total_violation = 0.0
        for i, t in enumerate(tenants):
            viol_i  = max(0.0, t.guaranteed_bw_mbps - allocs[i])
            wviol_i = viol_i * t.priority_weight
            total_violation += wviol_i
            allocations.append(TenantAllocation(
                tenant_id        = t.tenant_id,
                alloc_mbps       = allocs[i],
                guaranteed_mbps  = t.guaranteed_bw_mbps,
                demand_mbps      = t.current_demand_mbps,
                utilisation_pct  = (allocs[i] / t.current_demand_mbps * 100
                                    if t.current_demand_mbps > 0 else 0.0),
                sla_satisfied    = viol_i < 0.01,
                violation_mbps   = viol_i,
                weighted_violation_cost = wviol_i,
                tier             = (t.tier.value if t.tier else None),
            ))

        return AllocationResult(
            success                  = True,
            total_capacity           = self.total_bw_mbps,
            vnf_overhead             = overhead,
            available                = available,
            allocations              = allocations,
            solver_status            = 'PROPORTIONAL_FALLBACK',
            total_weighted_violation = total_violation,
        )


# ── Smoke test ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    alloc = SLAAllocator(total_bw_mbps=10_000.0, lambda_resource=0.01)
    tenants = [
        Tenant.gold  ('slice-finance', contracted_bw_mbps=4000, current_demand_mbps=3500),
        Tenant.silver('slice-eMBB',    contracted_bw_mbps=3000, current_demand_mbps=2800),
        Tenant.bronze('slice-IoT',     contracted_bw_mbps=2000, current_demand_mbps=1900),
    ]
    for overhead in (0, 1000, 3000, 7000):
        r = alloc.allocate(tenants, vnf_overhead_mbps=overhead, cnf_scrub_cost=1.0)
        print(f'\novhd={overhead:5d}  status={r.solver_status:<22} '
              f'wviol={r.total_weighted_violation:8.1f}')
        for ta in r.allocations:
            sla = '✓' if ta.sla_satisfied else '✗'
            print(f'  {ta.tenant_id:<14} tier={ta.tier:<6} '
                  f'alloc={ta.alloc_mbps:6.0f}  floor={ta.guaranteed_mbps:5.0f}  '
                  f'util={ta.utilisation_pct:5.1f}%  SLA={sla}')

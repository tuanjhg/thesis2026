"""
M3 — SLA Allocator (Spec-aligned §5.3)

Uses scipy.optimize.linprog to fairly reallocate bandwidth among tenants when
one or more VNFs are active (consuming bandwidth for mitigation traffic).

Model:
  - N tenants, each with:
      - guaranteed_bw_mbps : minimum bandwidth floor (SLA commitment)
      - current_demand_mbps: observed demand
      - priority_weight    : relative priority (default 1.0)
  - total_bw_mbps: total link capacity
  - vnf_overhead_mbps: bandwidth consumed by active VNF chains

Optimisation (LP):
  Maximise   Σ priority_weight[i] * alloc[i]          (weighted throughput)
  Subject to:
    alloc[i]  ≥ guaranteed_bw_mbps[i]    ∀i            (SLA floor)
    alloc[i]  ≤ current_demand_mbps[i]   ∀i            (no over-allocation)
    Σ alloc[i] ≤ total_bw_mbps - vnf_overhead_mbps     (link capacity)
    alloc[i]  ≥ 0                         ∀i

Outputs TenantAllocation per tenant with alloc_mbps + utilisation %.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class Tenant:
    tenant_id:          str
    guaranteed_bw_mbps: float       # SLA floor
    current_demand_mbps: float      # observed demand
    priority_weight:    float = 1.0


@dataclass
class TenantAllocation:
    tenant_id:      str
    alloc_mbps:     float
    guaranteed_mbps: float
    demand_mbps:    float
    utilisation_pct: float           # alloc / demand * 100
    sla_satisfied:  bool             # alloc >= guaranteed


@dataclass
class AllocationResult:
    success:         bool
    total_capacity:  float
    vnf_overhead:    float
    available:       float           # capacity - overhead
    allocations:     List[TenantAllocation]
    solver_status:   str


class SLAAllocator:
    """
    Fair bandwidth allocator.

    Usage (3-tenant example):
        alloc = SLAAllocator(total_bw_mbps=1000.0)
        tenants = [
            Tenant('slice-embb',  guaranteed_bw_mbps=200, current_demand_mbps=400),
            Tenant('slice-urllc', guaranteed_bw_mbps=100, current_demand_mbps=150, priority_weight=2.0),
            Tenant('slice-mmtc',  guaranteed_bw_mbps= 50, current_demand_mbps=300),
        ]
        result = alloc.allocate(tenants, vnf_overhead_mbps=100.0)
        for ta in result.allocations:
            print(ta)
    """

    def __init__(self, total_bw_mbps: float = 1000.0):
        self.total_bw_mbps = total_bw_mbps

    def allocate(
        self,
        tenants:          List[Tenant],
        vnf_overhead_mbps: float = 0.0,
    ) -> AllocationResult:
        """
        Run LP to compute fair allocation.

        Falls back to proportional allocation if scipy unavailable or LP infeasible.
        """
        available = self.total_bw_mbps - vnf_overhead_mbps

        if available <= 0:
            logger.warning(
                f"SLAAllocator: VNF overhead ({vnf_overhead_mbps} Mbps) ≥ "
                f"total capacity ({self.total_bw_mbps} Mbps) — "
                f"all tenants receive guaranteed_bw floor"
            )
            allocations = [
                TenantAllocation(
                    tenant_id       = t.tenant_id,
                    alloc_mbps      = t.guaranteed_bw_mbps,
                    guaranteed_mbps = t.guaranteed_bw_mbps,
                    demand_mbps     = t.current_demand_mbps,
                    utilisation_pct = (t.guaranteed_bw_mbps / t.current_demand_mbps * 100
                                       if t.current_demand_mbps > 0 else 0.0),
                    sla_satisfied   = True,
                )
                for t in tenants
            ]
            return AllocationResult(
                success        = False,
                total_capacity = self.total_bw_mbps,
                vnf_overhead   = vnf_overhead_mbps,
                available      = available,
                allocations    = allocations,
                solver_status  = "CAPACITY_EXHAUSTED",
            )

        try:
            from scipy.optimize import linprog
            result = self._lp_allocate(tenants, available)
            return result
        except ImportError:
            logger.warning("scipy not installed — using proportional fallback")
            return self._proportional_allocate(tenants, available, vnf_overhead_mbps)

    def _lp_allocate(self, tenants: List[Tenant], available: float) -> AllocationResult:
        """scipy.optimize.linprog based allocation."""
        from scipy.optimize import linprog

        n = len(tenants)
        # Objective: maximise Σ weight[i]*alloc[i]  → minimise -Σ weight[i]*alloc[i]
        c = np.array([-t.priority_weight for t in tenants], dtype=float)

        # Inequality constraint: Σ alloc[i] ≤ available
        A_ub = np.ones((1, n), dtype=float)
        b_ub = np.array([available], dtype=float)

        # Bounds: guaranteed_bw ≤ alloc[i] ≤ current_demand
        bounds = [
            (t.guaranteed_bw_mbps, t.current_demand_mbps)
            for t in tenants
        ]

        res = linprog(c, A_ub=A_ub, b_ub=b_ub, bounds=bounds, method='highs')

        if res.success:
            allocs = res.x
            solver_status = "OPTIMAL"
        else:
            # LP infeasible (e.g. sum of floors > available) → use floors only
            logger.warning(f"LP infeasible ({res.message}) — using SLA floors")
            allocs = np.array([t.guaranteed_bw_mbps for t in tenants], dtype=float)
            solver_status = f"LP_INFEASIBLE:{res.message}"

        allocations = [
            TenantAllocation(
                tenant_id        = t.tenant_id,
                alloc_mbps       = float(allocs[i]),
                guaranteed_mbps  = t.guaranteed_bw_mbps,
                demand_mbps      = t.current_demand_mbps,
                utilisation_pct  = (float(allocs[i]) / t.current_demand_mbps * 100
                                    if t.current_demand_mbps > 0 else 0.0),
                sla_satisfied    = float(allocs[i]) >= t.guaranteed_bw_mbps - 0.01,
            )
            for i, t in enumerate(tenants)
        ]

        return AllocationResult(
            success        = res.success,
            total_capacity = self.total_bw_mbps,
            vnf_overhead   = self.total_bw_mbps - available,
            available      = available,
            allocations    = allocations,
            solver_status  = solver_status,
        )

    def _proportional_allocate(
        self,
        tenants:          List[Tenant],
        available:        float,
        vnf_overhead_mbps: float,
    ) -> AllocationResult:
        """Proportional fallback when scipy not available."""
        # First satisfy floors
        floor_sum = sum(t.guaranteed_bw_mbps for t in tenants)
        surplus   = max(0.0, available - floor_sum)

        # Distribute surplus proportionally to demand above floor
        demand_above = [max(0.0, t.current_demand_mbps - t.guaranteed_bw_mbps)
                        for t in tenants]
        total_above  = sum(demand_above) or 1.0
        extras       = [surplus * d / total_above for d in demand_above]

        allocs = [t.guaranteed_bw_mbps + extras[i] for i, t in enumerate(tenants)]

        allocations = [
            TenantAllocation(
                tenant_id        = t.tenant_id,
                alloc_mbps       = allocs[i],
                guaranteed_mbps  = t.guaranteed_bw_mbps,
                demand_mbps      = t.current_demand_mbps,
                utilisation_pct  = (allocs[i] / t.current_demand_mbps * 100
                                    if t.current_demand_mbps > 0 else 0.0),
                sla_satisfied    = allocs[i] >= t.guaranteed_bw_mbps - 0.01,
            )
            for i, t in enumerate(tenants)
        ]

        return AllocationResult(
            success        = True,
            total_capacity = self.total_bw_mbps,
            vnf_overhead   = vnf_overhead_mbps,
            available      = available,
            allocations    = allocations,
            solver_status  = "PROPORTIONAL_FALLBACK",
        )


# ── Smoke test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    alloc = SLAAllocator(total_bw_mbps=1000.0)

    tenants = [
        Tenant('slice-eMBB',  guaranteed_bw_mbps=200, current_demand_mbps=450, priority_weight=1.0),
        Tenant('slice-URLLC', guaranteed_bw_mbps=100, current_demand_mbps=150, priority_weight=2.0),
        Tenant('slice-mMTC',  guaranteed_bw_mbps= 50, current_demand_mbps=300, priority_weight=0.5),
    ]

    for overhead in [0.0, 200.0, 400.0, 700.0]:
        r = alloc.allocate(tenants, vnf_overhead_mbps=overhead)
        print(f"\nOverhead={overhead} Mbps  available={r.available:.0f}  status={r.solver_status}")
        for ta in r.allocations:
            sla = "✓" if ta.sla_satisfied else "✗"
            print(f"  {ta.tenant_id:<14} alloc={ta.alloc_mbps:6.1f}  "
                  f"floor={ta.guaranteed_mbps:.0f}  "
                  f"util={ta.utilisation_pct:.1f}%  SLA={sla}")

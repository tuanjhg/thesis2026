Phase	Duration	Deliverable	Can parallelize
1. M3 Architecture	Wk 1–1.5	Tier mapper, policy engine, SLA allocator	Start now
2. CLAMP Simulator	Wk 1.5–2	Frequency guard, SO request builder	After Phase 1
3. Docker VNFs	Wk 2–3.5	4 containerized VNFs + orchestrator	Parallel with 1+2
4. E2E Integration	Wk 3.5–4.5	Latency instrumentation (t_ai → t_sfc_active)	After 1,2,3
5. Evaluation	Wk 4.5–5.5	Run scenarios S1–S8, collect metrics	After 4
6. Docs	Wk 5.5–6	Thesis Chapter 4 + implementation guide	After 5
Critical Implementation Details
M3 (Orchestration):

5-tier policy framework:
[0.50–0.70) → Tier 1 (ALERT): increase telemetry sampling
[0.70–0.85) → Tier 2 (PREEMPT): pre-position VNF (no active steering yet)
[0.85–0.95) → Tier 3 (MITIGATE): insert VNF into SFC path
[0.95–1.00] → Tier 4 (ISOLATE): scrubbing + blackholing
SLA fairness: use scipy.optimize.linprog to preserve tenant bandwidth floors during mitigation
New files: 6 Python modules (~900 LOC) in pipeline/s4_orchestration/
M4 (NFV Enforcement):

4 Docker VNF containers running on testbed host
Scrubber (8 vCPU, 16 GB): stateful SYN proxy + rate limiting
Rate-limiter (2 vCPU, 2 GB): token-bucket per-flow
Analyzer (2 vCPU, 4 GB): packet capture (feeds M1 telemetry)
Blackhole (1 vCPU, 1 GB): iptables-based null-routing
Metrics: CPU%, RAM%, packets processed exported via /metrics endpoint
OpenFlow SFC steering: inject OVS rules to steer attack traffic through VNF chain
New files: 4 Dockerfiles + 11 Python modules (~1500 LOC) in docker/vnf-* and pipeline/s4_orchestration/
Latency Instrumentation (key novelty):

Timestamps at each stage:
t_ai_detection: AI output emitted
t_policy_decision: M3 tier decision made
t_so_request: SO instantiation request sent
t_vnf_active: container responds to health checks
t_sfc_updated: OVS rules installed
Derived metrics: detection_to_policy_ms, policy_to_vnf_active_ms, end_to_end_ms
Export to Prometheus for evaluation
Dependencies & Parallelization
✅ Can start in parallel:

Phase 1 (M3 architecture) + Phase 3 (Docker VNFs) — independent
Saves ~1 week vs. sequential
⛓️ Must be sequential:

Phase 1+2 → Phase 4 (integration needs tier logic + CLAMP simulator)
Phase 4 → Phase 5 (evaluation requires E2E pipeline)
Verification Strategy
Unit tests (per module):

Tier mapping correctness (all confidence ranges → correct tier)
SLA allocator fairness constraints
Frequency guard prevents VNF thrashing
Docker containers start/stop without errors
Integration tests:

M2 output → M3 policy → M4 VNF instantiation flow
OpenFlow SFC rule injection + traffic steering
End-to-end latency pipeline (all timestamps collected)
Evaluation (against 8 attack scenarios):

Latency CDF: p50, p95, p99 per component
NFV metrics: scrubber boot time distribution, CPU/RAM peaks
SLA fairness: 3-tenant scenario shows bandwidth enforcement
Novelty validation: Tier 2 (proactive) latency << Tier 3 (reactive)
Relevant Files to Create/Modify
New directories:

pipeline/s4_orchestration/ (M3 core)
docker/vnf-*/ (4 VNF containers)
evaluation/ (scenario runners + metrics)
tests/ (unit + integration tests)
New files: ~20 files, ~4200 LOC (manageable in 4–6 weeks)

Modified files:

docker-compose.yml (add 4 VNF services)
requirements-pipeline.txt (add scipy, docker SDK)
PAD_ONAP_Pipeline_Detailed.md (Chapter 4 references)
Success Criteria
✓ M3 policy engine correctly maps confidence → tiers
✓ M4 VNF containers instantiate/execute/terminate without errors
✓ E2E latency measured for all 8 scenarios (p95 ≤ 30s for Tier 3, ≤ 2s for Tier 2)
✓ NFV deployment metrics collected (CPU, RAM, instantiation time)
✓ SLA fairness validated (3-tenant scenario)
✓ Tier 2 latency benefit demonstrated vs. Tier 3
✓ All unit + integration + scenario tests passing
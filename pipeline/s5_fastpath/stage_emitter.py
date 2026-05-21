"""
Stage emitter — drop-in helper for M1/M2/M3 modules to report status to the
frontend without hard dependencies on it.

Each pipeline module wraps its hot path:

    from pipeline.s5_fastpath.stage_emitter import stage

    with stage("M1_collector", throughput_pps=samples_per_sec):
        publish_to_kafka(batch)

    with stage("M3_ai", tier_out=tier, confidence=conf):
        decision = inference.infer(features)

State transitions written:
  · entering  → status = "active"
  · normal exit → status = "done", latency_ms = elapsed
  · exception → status = "error", latency_ms = elapsed
"""

from __future__ import annotations

import contextlib
import time

from pipeline.s5_fastpath import scenario_state


@contextlib.contextmanager
def stage(name: str, **payload):
    """Context manager that marks a pipeline stage active → done/error."""
    scenario_state.mark_stage(name, "active", **payload)
    t0 = time.time()
    err = None
    try:
        yield
    except Exception as e:
        err = e
        raise
    finally:
        latency_ms = int((time.time() - t0) * 1000)
        if err is None:
            scenario_state.mark_stage(name, "done", latency_ms=latency_ms,
                                      **payload)
        else:
            scenario_state.mark_stage(name, "error", latency_ms=latency_ms,
                                      error=str(err))


def emit_traffic(*, inbound_pps: int = 0, return_pps: int = 0,
                 mitigated_pps: int = 0) -> None:
    """Update per-second traffic counters shown on topology edges."""
    with scenario_state.update() as s:
        s.setdefault("traffic", {})
        if inbound_pps:   s["traffic"]["inbound_pps"]   = inbound_pps
        if return_pps:    s["traffic"]["return_pps"]    = return_pps
        if mitigated_pps: s["traffic"]["mitigated_pps"] = mitigated_pps

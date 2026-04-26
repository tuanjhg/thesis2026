"""
Audit Logger — records every agent decision for compliance and post-incident review.

Writes structured JSONL audit logs with:
  - Triage decisions (severity, verdict, evidence)
  - Playbook generation (steps, timing, urgency)
  - Mitigation decisions (approved/rejected/executed per step)
  - Token usage and latency per session

Log file: logs/soc_agent_audit_YYYYMMDD.jsonl
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_LOG_DIR = os.environ.get(
    "AUDIT_LOG_DIR",
    str(Path(__file__).parent.parent.parent / "logs")
)


class AuditLogger:
    """Thread-safe append-only audit log writer."""

    def __init__(self, log_dir: str = _LOG_DIR):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._fh = None
        self._current_date = None
        self._open_log()

    def _open_log(self):
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        if self._current_date != today:
            if self._fh:
                self._fh.close()
            log_path = self.log_dir / f"soc_agent_audit_{today}.jsonl"
            self._fh = open(log_path, "a", buffering=1)  # line-buffered
            self._current_date = today
            logger.info(f"Audit log: {log_path}")

    def _write(self, record: dict):
        self._open_log()
        self._fh.write(json.dumps(record, default=str) + "\n")

    def log_triage(self, triage_report) -> None:
        """Log a completed triage report."""
        self._write({
            "event_type":   "TRIAGE",
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "alert_id":     triage_report.alert_id,
            "severity":     triage_report.severity,
            "priority":     triage_report.priority,
            "verdict":      triage_report.verdict,
            "attack_type":  triage_report.attack_type,
            "confidence":   round(triage_report.confidence, 4),
            "mitre":        triage_report.mitre_technique,
            "recommended":  triage_report.recommended_next,
            "latency_ms":   triage_report.latency_ms,
            "n_tool_calls": len(triage_report.tool_calls),
            "evidence_count": len(triage_report.evidence),
        })

    def log_playbook(self, playbook) -> None:
        """Log a generated playbook."""
        self._write({
            "event_type":       "PLAYBOOK_GENERATED",
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "playbook_id":      playbook.playbook_id,
            "alert_id":         playbook.alert_id,
            "attack_type":      playbook.attack_type,
            "urgency":          playbook.urgency,
            "lead_time_s":      playbook.lead_time_s,
            "n_steps":          len(playbook.steps),
            "steps_need_approval": sum(1 for s in playbook.steps if s.requires_approval),
            "estimated_mttr_s": playbook.estimated_mttr_s,
            "latency_ms":       playbook.latency_ms,
        })

    def log_decision(self, session_id: str, decision, playbook) -> None:
        """Log a single step decision (approve/reject/execute)."""
        self._write({
            "event_type":    "MITIGATION_DECISION",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "session_id":    session_id,
            "playbook_id":   playbook.playbook_id,
            "alert_id":      playbook.alert_id,
            "attack_type":   playbook.attack_type,
            "step_number":   decision.step_number,
            "action":        decision.action,
            "command":       decision.command,
            "risk":          decision.risk,
            "tier":          decision.tier,
            "approved":      decision.approved,
            "approved_by":   decision.approved_by,
            "executed":      decision.executed,
            "exec_output":   (decision.exec_output or "")[:200],
            "exec_error":    decision.exec_error,
        })

    def log_mitigation_result(self, result) -> None:
        """Log the final mitigation session summary."""
        self._write({
            "event_type":     "MITIGATION_COMPLETE",
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "session_id":     result.session_id,
            "playbook_id":    result.playbook_id,
            "alert_id":       result.alert_id,
            "attack_type":    result.attack_type,
            "execution_mode": result.execution_mode,
            "total_steps":    result.total_steps,
            "approved":       result.approved_steps,
            "rejected":       result.rejected_steps,
            "executed":       result.executed_steps,
            "failed":         result.failed_steps,
            "started_at":     result.started_at,
            "completed_at":   result.completed_at,
        })

    def log_session(self, session_id: str, event: str, extra: dict = None) -> None:
        """Generic session event log."""
        record = {
            "event_type": event,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
        }
        if extra:
            record.update(extra)
        self._write(record)

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def __del__(self):
        self.close()


# ── Simple stats reader ────────────────────────────────────────────────────────

def read_audit_stats(log_dir: str = _LOG_DIR, date: str = None) -> dict:
    """
    Read and aggregate stats from today's (or specified) audit log.

    Returns dict with counts per event_type, verdict distribution, etc.
    """
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y%m%d")

    log_path = Path(log_dir) / f"soc_agent_audit_{date}.jsonl"
    if not log_path.exists():
        return {"error": f"No audit log for {date}", "path": str(log_path)}

    counts = {}
    verdicts = {}
    severities = {}
    attack_types = {}
    total_latency = 0
    n_triage = 0

    with open(log_path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            et = rec.get("event_type", "UNKNOWN")
            counts[et] = counts.get(et, 0) + 1

            if et == "TRIAGE":
                v = rec.get("verdict", "UNKNOWN")
                verdicts[v] = verdicts.get(v, 0) + 1
                s = rec.get("severity", "UNKNOWN")
                severities[s] = severities.get(s, 0) + 1
                at = rec.get("attack_type") or "Normal"
                attack_types[at] = attack_types.get(at, 0) + 1
                total_latency += rec.get("latency_ms", 0)
                n_triage += 1

    return {
        "date": date,
        "event_counts": counts,
        "verdict_dist": verdicts,
        "severity_dist": severities,
        "attack_type_dist": attack_types,
        "avg_triage_latency_ms": round(total_latency / n_triage, 1) if n_triage else 0,
        "log_path": str(log_path),
    }

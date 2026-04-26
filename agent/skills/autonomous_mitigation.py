"""
Skill 3 — Autonomous Mitigation (human-in-the-loop)

Responsibilities:
  - Receive a GeneratedPlaybook from Skill 2
  - For each step, check if it requires_approval
  - Present pending steps to operator for approval (CLI or REST)
  - Execute approved steps via MitigationExecutor
  - Log every decision (approved / rejected / executed / failed)

Risk level: CONTROLLED — execution only after human approval per step.

Execution modes:
  DRY_RUN:  Generate commands, no execution (default for research)
  SIMULATE: Execute against testbed sandbox
  LIVE:     Execute against production (requires explicit --live flag)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    DRY_RUN  = "DRY_RUN"   # default — generate, don't execute
    SIMULATE = "SIMULATE"  # testbed sandbox
    LIVE     = "LIVE"      # production (requires --live)


# ── Decision record ────────────────────────────────────────────────────────────

@dataclass
class StepDecision:
    step_number:   int
    action:        str
    command:       Optional[str]
    tier:          Optional[int]
    risk:          str
    approved:      Optional[bool]      # None = pending
    approved_by:   Optional[str]       # "operator" | "auto" | None
    executed:      bool = False
    exec_output:   Optional[str] = None
    exec_error:    Optional[str] = None
    decided_at:    Optional[str] = None
    executed_at:   Optional[str] = None


@dataclass
class MitigationResult:
    """Full audit record for one mitigation run."""
    session_id:       str
    playbook_id:      str
    alert_id:         str
    attack_type:      str
    execution_mode:   str
    total_steps:      int
    approved_steps:   int
    rejected_steps:   int
    executed_steps:   int
    failed_steps:     int
    decisions:        list[StepDecision]
    started_at:       str
    completed_at:     Optional[str] = None
    notes:            str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        return (
            f"[{self.execution_mode}] {self.attack_type} | "
            f"approved={self.approved_steps}/{self.total_steps} | "
            f"executed={self.executed_steps} | failed={self.failed_steps}"
        )


# ── Executor ───────────────────────────────────────────────────────────────────

class MitigationExecutor:
    """
    Execute mitigation commands in the configured mode.
    DRY_RUN returns the command without executing.
    SIMULATE runs against testbed Docker environment.
    LIVE executes on the host (requires explicit flag).
    """

    # Commands allowed in LIVE mode without extra confirmation (low-risk only)
    _SAFE_COMMANDS = {
        "sysctl -w net.ipv4.tcp_syncookies=1",
    }

    def __init__(self, mode: ExecutionMode = ExecutionMode.DRY_RUN):
        self.mode = mode
        if mode == ExecutionMode.LIVE:
            logger.warning(
                "MitigationExecutor in LIVE mode — commands will execute on host. "
                "Ensure you have operator authorization."
            )

    def execute(self, command: str, step: StepDecision) -> tuple[bool, str]:
        """
        Execute a single command.
        Returns (success: bool, output: str)
        """
        if not command or not command.strip():
            return False, "Empty command"

        if self.mode == ExecutionMode.DRY_RUN:
            return True, f"[DRY_RUN] Would execute: {command}"

        if self.mode == ExecutionMode.SIMULATE:
            return self._simulate(command, step)

        if self.mode == ExecutionMode.LIVE:
            return self._live_execute(command, step)

        return False, f"Unknown mode: {self.mode}"

    def _simulate(self, command: str, step: StepDecision) -> tuple[bool, str]:
        """Run against testbed Docker container (mitigation-sandbox)."""
        sandbox_container = os.environ.get("MITIGATION_SANDBOX", "pad-mitigation-sandbox")
        docker_cmd = ["docker", "exec", sandbox_container, "sh", "-c", command]
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return True, result.stdout.strip() or "[OK]"
            return False, f"Exit {result.returncode}: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "Command timed out (10s)"
        except FileNotFoundError:
            return False, f"Docker not available — sandbox container '{sandbox_container}' not found"
        except Exception as e:
            return False, str(e)

    def _live_execute(self, command: str, step: StepDecision) -> tuple[bool, str]:
        """Execute on host — HIGH RISK mode."""
        if step.risk == "HIGH" and command not in self._SAFE_COMMANDS:
            return False, "HIGH risk command blocked in live mode — escalate to senior operator"
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return True, result.stdout.strip() or "[OK]"
            return False, f"Exit {result.returncode}: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "Command timed out (15s)"
        except Exception as e:
            return False, str(e)


# ── Human-in-the-loop approval ─────────────────────────────────────────────────

class HumanApprovalGate:
    """
    Handles human approval for steps that require it.
    Supports CLI interactive mode and auto-approve (for dry-run/testing).
    """

    def __init__(self, auto_approve: bool = False, timeout_s: int = 60):
        self.auto_approve = auto_approve
        self.timeout_s    = timeout_s

    def request_approval(self, step: StepDecision, playbook_id: str) -> tuple[bool, str]:
        """
        Request human approval for a step.
        Returns (approved: bool, approver: str)
        """
        if self.auto_approve:
            logger.info(f"[AUTO-APPROVE] Step {step.step_number}: {step.action}")
            return True, "auto"

        # CLI interactive approval
        print(f"\n{'─'*56}")
        print(f"APPROVAL REQUIRED — Playbook {playbook_id}")
        print(f"  Step {step.step_number}: {step.action}")
        if step.command:
            print(f"  Command: {step.command}")
        print(f"  Risk level: {step.risk}")
        if step.tier:
            print(f"  ONAP Tier: {step.tier}")
        print(f"  (auto-reject in {self.timeout_s}s)")
        print(f"{'─'*56}")

        try:
            import signal

            def _timeout_handler(signum, frame):
                raise TimeoutError

            # Timeout only available on Unix
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(self.timeout_s)

            answer = input("Approve? [y/N]: ").strip().lower()

            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)

            if answer in ("y", "yes"):
                return True, "operator"
            return False, "operator_rejected"

        except (TimeoutError, EOFError, KeyboardInterrupt):
            print("\n[TIMEOUT/INTERRUPT] Step rejected.")
            return False, "timeout"


# ── Skill runner ───────────────────────────────────────────────────────────────

def run_autonomous_mitigation(
    playbook,
    mode: ExecutionMode = ExecutionMode.DRY_RUN,
    auto_approve_low_risk: bool = True,
    audit_logger=None,
) -> MitigationResult:
    """
    Execute approved steps from a GeneratedPlaybook.

    Args:
        playbook:              GeneratedPlaybook from run_playbook_generator()
        mode:                  Execution mode (DRY_RUN / SIMULATE / LIVE)
        auto_approve_low_risk: Auto-approve LOW risk steps, ask for MEDIUM/HIGH
        audit_logger:          AuditLogger instance for recording decisions

    Returns:
        MitigationResult with full audit trail
    """
    import uuid
    from datetime import datetime, timezone

    session_id = f"mitigation_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    executor = MitigationExecutor(mode=mode)
    gate     = HumanApprovalGate(
        auto_approve=(mode == ExecutionMode.DRY_RUN),
    )

    decisions: list[StepDecision] = []
    approved_count = rejected_count = executed_count = failed_count = 0

    logger.info(
        f"[{session_id}] Starting mitigation: {playbook.attack_type} "
        f"mode={mode.value} steps={len(playbook.steps)}"
    )

    for step in playbook.steps:
        decision = StepDecision(
            step_number = step.step_number,
            action      = step.action,
            command     = step.command,
            tier        = step.tier,
            risk        = step.risk,
            approved    = None,
            approved_by = None,
        )

        # Determine if approval needed
        need_approval = step.requires_approval
        if auto_approve_low_risk and step.risk == "LOW":
            need_approval = False

        # Request approval if needed
        if need_approval:
            approved, approver = gate.request_approval(decision, playbook.playbook_id)
        else:
            approved, approver = True, "auto_low_risk"

        decision.approved    = approved
        decision.approved_by = approver
        decision.decided_at  = datetime.now(timezone.utc).isoformat()

        if not approved:
            rejected_count += 1
            logger.info(f"  [REJECTED] Step {step.step_number} by {approver}")
            decisions.append(decision)
            if audit_logger:
                audit_logger.log_decision(session_id, decision, playbook)
            continue

        approved_count += 1

        # Execute if command available
        if step.command:
            success, output = executor.execute(step.command, decision)
            decision.executed    = True
            decision.exec_output = output
            decision.executed_at = datetime.now(timezone.utc).isoformat()

            if success:
                executed_count += 1
                logger.info(f"  [OK] Step {step.step_number}: {output[:80]}")
            else:
                failed_count += 1
                decision.exec_error = output
                logger.warning(f"  [FAILED] Step {step.step_number}: {output[:120]}")
        else:
            # No command — just log the action
            decision.executed    = True
            decision.exec_output = f"[ACTION] {step.action} (no command)"
            executed_count += 1

        decisions.append(decision)

        if audit_logger:
            audit_logger.log_decision(session_id, decision, playbook)

        # Brief pause between steps
        time.sleep(0.1)

    result = MitigationResult(
        session_id      = session_id,
        playbook_id     = playbook.playbook_id,
        alert_id        = playbook.alert_id,
        attack_type     = playbook.attack_type,
        execution_mode  = mode.value,
        total_steps     = len(playbook.steps),
        approved_steps  = approved_count,
        rejected_steps  = rejected_count,
        executed_steps  = executed_count,
        failed_steps    = failed_count,
        decisions       = decisions,
        started_at      = now_iso,
        completed_at    = datetime.now(timezone.utc).isoformat(),
    )

    logger.info(f"[{session_id}] Done: {result.summary()}")
    return result

"""
Skill 2 — Playbook Generator (suggest-only)

Responsibilities:
  - Accept a TriageReport (from Skill 1) as input
  - Look up the matching SOC playbook from RAG KB
  - Enrich playbook steps with lead-time data (WHEN to trigger each step)
  - Generate a time-annotated, context-specific runbook
  - Output is a SUGGESTION ONLY — no execution

Risk level: SUGGEST-ONLY (no system changes)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, asdict, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Output schema ──────────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    step_number:   int
    t_offset_s:    Optional[int]   # seconds from NOW (None = no timing constraint)
    action:        str             # what to do
    command:       Optional[str]   # shell command or API call if applicable
    condition:     Optional[str]   # precondition (e.g. "if confidence >= 0.85")
    tier:          Optional[int]   # ONAP tier this step activates (None = pre-tier)
    risk:          str             # LOW | MEDIUM | HIGH
    requires_approval: bool        # True = must confirm before executing


@dataclass
class GeneratedPlaybook:
    """Time-annotated, context-specific response runbook."""
    playbook_id:        str
    alert_id:           str
    attack_type:        str
    confidence:         float
    lead_time_s:        Optional[int]  # seconds of warning available
    urgency:            str            # IMMEDIATE | PROACTIVE | MONITOR
    steps:              list[PlaybookStep]
    summary:            str
    estimated_mttr_s:   int            # estimated mean-time-to-respond
    evidence:           list[dict]
    latency_ms:         float
    tool_calls:         list[dict] = field(default_factory=list)
    raw_llm_output:     Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def print_runbook(self):
        print(f"\n{'='*64}")
        print(f"PLAYBOOK: {self.attack_type} | Urgency: {self.urgency}")
        print(f"Alert: {self.alert_id} | Lead time: {self.lead_time_s}s | MTTR: {self.estimated_mttr_s}s")
        print(f"Summary: {self.summary}")
        print(f"{'─'*64}")
        for step in self.steps:
            timing = f"T+{step.t_offset_s}s" if step.t_offset_s is not None else "T+?"
            approval = " [REQUIRES APPROVAL]" if step.requires_approval else ""
            print(f"  [{timing}] Step {step.step_number}: {step.action}{approval}")
            if step.command:
                print(f"           $ {step.command}")
            if step.condition:
                print(f"           Condition: {step.condition}")
        print(f"{'='*64}\n")


# ── Skill prompt ───────────────────────────────────────────────────────────────

PLAYBOOK_PROMPT_TEMPLATE = """Generate a time-annotated SOC response playbook for a confirmed attack.

Alert context:
{triage_json}

Your task:
1. Call `query_knowledge_base` with collection='playbooks' and query='{attack_type} response steps'.
2. Call `get_lead_time` for attack_type='{attack_type}' to know how much warning time is available.
3. Call `query_knowledge_base` with collection='lead_time' and query='{attack_type} lead time proactive'.
4. Generate a time-annotated playbook as JSON:

{{
  "urgency":           "IMMEDIATE|PROACTIVE|MONITOR",
  "lead_time_s":       <integer seconds or null>,
  "summary":           "<1 sentence: what is happening and what to do>",
  "estimated_mttr_s":  <integer>,
  "steps": [
    {{
      "step_number":       1,
      "t_offset_s":        0,
      "action":            "<what to do>",
      "command":           "<shell command or null>",
      "condition":         "<precondition or null>",
      "tier":              <ONAP tier int or null>,
      "risk":              "LOW|MEDIUM|HIGH",
      "requires_approval": false
    }}
  ],
  "evidence": [
    {{"source_tool": "query_knowledge_base", "key": "playbook_step", "value": "..."}}
  ]
}}

Timing rules:
- PROACTIVE: attack not yet at peak, forecast P(t+30s) > 0.50 → steps timed BEFORE attack
- IMMEDIATE: attack already at confidence > 0.85 → steps at T=0 and immediate
- MONITOR:   confidence < 0.75 → watch-and-wait

Step timing guidelines (relative to NOW):
- T+0s:   Enable SYN cookies / rate-limit rules (immediate, LOW risk, no approval)
- T+5s:   Verify rule active, check metric drop
- T+30s:  If still active → escalate (MEDIUM risk, approval required for T3)
- T+60s:  ONAP SO VNF instantiation if needed
- T+120s: Full scrubber active / verify mitigation effective

IMPORTANT: requires_approval=true for any step that changes firewall rules or activates VNFs.
Output ONLY the JSON object."""


def build_playbook_prompt(triage_report, attack_type: str) -> str:
    triage_json = json.dumps({
        "alert_id":       triage_report.alert_id,
        "severity":       triage_report.severity,
        "attack_type":    triage_report.attack_type,
        "confidence":     triage_report.confidence,
        "forecast_summary": triage_report.forecast_summary,
        "lead_time_note": triage_report.lead_time_note,
        "shap_explanation": triage_report.shap_explanation,
        "mitre_technique": triage_report.mitre_technique,
    }, indent=2)
    return PLAYBOOK_PROMPT_TEMPLATE.format(
        triage_json=triage_json,
        attack_type=attack_type,
    )


# ── Skill runner ───────────────────────────────────────────────────────────────

def run_playbook_generator(
    agent,
    triage_report,
) -> GeneratedPlaybook:
    """
    Generate a time-annotated response playbook based on a TriageReport.

    Args:
        agent:         SOCAgent instance
        triage_report: TriageReport from run_triage()

    Returns:
        GeneratedPlaybook dataclass
    """
    import uuid
    from datetime import datetime, timezone

    playbook_id = f"pb_{uuid.uuid4().hex[:8]}"
    attack_type = triage_report.attack_type or "Unknown"

    prompt = build_playbook_prompt(triage_report, attack_type)
    t0 = time.perf_counter()
    raw_result = agent.analyze(prompt)
    latency_ms = (time.perf_counter() - t0) * 1000

    pb_data = {k: v for k, v in raw_result.items()
               if k not in ("tool_calls", "latency_ms", "raw_response")}
    raw_text = raw_result.get("raw_response")

    # Parse steps list
    raw_steps = pb_data.get("steps", [])
    steps = []
    for i, s in enumerate(raw_steps):
        steps.append(PlaybookStep(
            step_number       = s.get("step_number", i + 1),
            t_offset_s        = s.get("t_offset_s"),
            action            = s.get("action", ""),
            command           = s.get("command"),
            condition         = s.get("condition"),
            tier              = s.get("tier"),
            risk              = s.get("risk", "MEDIUM"),
            requires_approval = bool(s.get("requires_approval", True)),
        ))

    return GeneratedPlaybook(
        playbook_id       = playbook_id,
        alert_id          = triage_report.alert_id,
        attack_type       = attack_type,
        confidence        = triage_report.confidence,
        lead_time_s       = pb_data.get("lead_time_s"),
        urgency           = pb_data.get("urgency", "IMMEDIATE"),
        steps             = steps,
        summary           = pb_data.get("summary", ""),
        estimated_mttr_s  = int(pb_data.get("estimated_mttr_s", 60)),
        evidence          = pb_data.get("evidence", []),
        latency_ms        = raw_result.get("latency_ms", latency_ms),
        tool_calls        = raw_result.get("tool_calls", []),
        raw_llm_output    = raw_text,
    )

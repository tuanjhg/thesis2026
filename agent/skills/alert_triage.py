"""
Skill 1 — Alert Triage Agent (read-only)

Responsibilities:
  - Receive raw flow features or a pre-computed AIOutputPayload
  - Call classify_flow + predict_horizon + RAG tools
  - Return a structured triage report: severity, priority, SHAP explanation, MITRE mapping
  - NO mitigation generated here — purely analysis and explanation

Risk level: READ-ONLY (safe to run without human approval)
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
class TriageReport:
    """Structured triage report from the Alert Triage skill."""
    alert_id:         str
    timestamp:        str
    severity:         str        # CRITICAL | HIGH | MEDIUM | LOW | NONE
    priority:         int        # 1 (highest) – 5 (lowest)
    verdict:          str        # ATTACK | SUSPICIOUS | NORMAL
    attack_type:      Optional[str]
    confidence:       float
    mitre_technique:  Optional[str]  # e.g. "T1498.001 Direct Network Flood"
    shap_explanation: str            # human-readable explanation of top SHAP features
    forecast_summary: str            # one-sentence forecast
    lead_time_note:   str            # how much time before escalation
    recommended_next: str            # ESCALATE_TO_PLAYBOOK | MONITOR | DISMISS
    evidence:         list[dict]     # grounded citations from tool calls
    latency_ms:       float
    tool_calls:       list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_line(self) -> str:
        return (
            f"[{self.severity}] {self.verdict} | {self.attack_type or 'Normal'} "
            f"conf={self.confidence:.2f} | {self.recommended_next} | {self.latency_ms:.0f}ms"
        )


# ── Skill prompt ───────────────────────────────────────────────────────────────

TRIAGE_PROMPT_TEMPLATE = """Perform an alert triage analysis on the following network flow.

{context}

Your task:
1. Call `classify_flow` with the features.
2. Call `predict_horizon` for the same features.
3. Call `search_threat_intel` to find the matching MITRE technique.
4. Call `query_knowledge_base` with collection='lead_time' to find lead-time context.
5. Produce a triage report as a JSON object with these fields:
{{
  "severity":         "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "priority":         1-5,
  "verdict":          "ATTACK|SUSPICIOUS|NORMAL",
  "attack_type":      "<string or null>",
  "confidence":       <float>,
  "mitre_technique":  "<T-ID and name or null>",
  "shap_explanation": "<plain-language explanation of top 3 SHAP features>",
  "forecast_summary": "<one sentence about P(attack) at t+30s and trend>",
  "lead_time_note":   "<how many seconds of warning we have, or 'no lead time'>",
  "recommended_next": "ESCALATE_TO_PLAYBOOK|MONITOR|DISMISS",
  "evidence":         [
    {{"source_tool": "classify_flow", "key": "attack_type", "value": "..."}},
    {{"source_tool": "classify_flow", "key": "confidence", "value": "..."}},
    {{"source_tool": "classify_flow", "key": "top_shap_feature", "value": "..."}},
    {{"source_tool": "predict_horizon", "key": "p_attack_30s", "value": "..."}},
    {{"source_tool": "search_threat_intel", "key": "mitre_id", "value": "..."}}
  ]
}}

Severity rules:
- CRITICAL: attack_class != 0 AND confidence >= 0.90 AND p_attack_30s >= 0.80
- HIGH:     attack_class != 0 AND confidence >= 0.75
- MEDIUM:   attack_class != 0 AND confidence >= 0.50
- LOW:      attack_class != 0 AND confidence < 0.50 (possible OOD)
- NONE:     attack_class == 0

Priority rules (1=highest):
- 1: CRITICAL + Amplification (highest collateral damage)
- 2: CRITICAL + UDP_Flood or SYN_Flood
- 3: HIGH
- 4: MEDIUM
- 5: LOW or NONE

SHAP explanation format:
"The model flagged this flow primarily because [feature1] is [value1] (contribution: [shap1]),
followed by [feature2] = [value2] (contribution: [shap2])."

Output ONLY the JSON object. No markdown, no prose."""


def build_triage_prompt(features: list[float], alert_id: str, extra_context: str = "") -> str:
    feat_str = ", ".join(f"{v:.4f}" for v in features)
    context = f"Alert ID: {alert_id}\nRaw features (17 values): [{feat_str}]"
    if extra_context:
        context += f"\nAdditional context: {extra_context}"
    return TRIAGE_PROMPT_TEMPLATE.format(context=context)


# ── Skill runner ───────────────────────────────────────────────────────────────

def run_triage(
    agent,
    features: list[float],
    alert_id: str = None,
    extra_context: str = "",
) -> TriageReport:
    """
    Run the Alert Triage skill using the given SOCAgent instance.

    Args:
        agent:         SOCAgent instance (already configured with model + API key)
        features:      17 raw flow features
        alert_id:      Optional alert identifier
        extra_context: Additional context string (e.g. source IP, time of day)

    Returns:
        TriageReport dataclass
    """
    import uuid
    from datetime import datetime, timezone

    if alert_id is None:
        alert_id = f"alert_{uuid.uuid4().hex[:8]}"

    prompt = build_triage_prompt(features, alert_id, extra_context)
    t0 = time.perf_counter()
    raw_result = agent.analyze(prompt)
    latency_ms = (time.perf_counter() - t0) * 1000

    # Parse the agent's JSON output
    report_data = {}
    if "raw_response" in raw_result:
        # Agent returned non-JSON — try to extract
        logger.warning(f"Triage response was not JSON: {raw_result.get('raw_response', '')[:200]}")
    else:
        report_data = {k: v for k, v in raw_result.items()
                       if k not in ("tool_calls", "latency_ms")}

    return TriageReport(
        alert_id         = alert_id,
        timestamp        = datetime.now(timezone.utc).isoformat(),
        severity         = report_data.get("severity", "UNKNOWN"),
        priority         = int(report_data.get("priority", 5)),
        verdict          = report_data.get("verdict", "UNKNOWN"),
        attack_type      = report_data.get("attack_type"),
        confidence       = float(report_data.get("confidence", 0.0)),
        mitre_technique  = report_data.get("mitre_technique"),
        shap_explanation = report_data.get("shap_explanation", ""),
        forecast_summary = report_data.get("forecast_summary", ""),
        lead_time_note   = report_data.get("lead_time_note", ""),
        recommended_next = report_data.get("recommended_next", "MONITOR"),
        evidence         = report_data.get("evidence", []),
        latency_ms       = raw_result.get("latency_ms", latency_ms),
        tool_calls       = raw_result.get("tool_calls", []),
    )

"""
PAD-ONAP SOC Agent — LLM-based analyst with 3-skill pipeline.

Skill pipeline:
  Skill 1 (Alert Triage)       — read-only, always safe
  Skill 2 (Playbook Generator) — suggest-only, no execution
  Skill 3 (Autonomous Mitigation) — human-in-the-loop execution

Usage:
  # Single alert — full pipeline
  python soc_agent.py --features 0.5 1200 ... (17 values)

  # Dry-run triage only (no playbook/mitigation)
  python soc_agent.py --features ... --skill triage

  # Replay test set
  python soc_agent.py --replay evaluation/test_windows.jsonl --out results.jsonl

  # Interactive chat
  python soc_agent.py --interactive

  # Audit stats
  python soc_agent.py --audit-stats

Environment variables:
  ANTHROPIC_API_KEY     — required
  INFERENCE_API_URL     — default http://localhost:8000
  AGENT_MODEL           — default claude-sonnet-4-6
  MITIGATION_MODE       — DRY_RUN | SIMULATE | LIVE (default DRY_RUN)
  AUDIT_LOG_DIR         — default logs/
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import anthropic

sys.path.insert(0, str(Path(__file__).parent))
from tools.ml_tools import TOOL_SCHEMAS, execute_tool
from prompts.system import SYSTEM_PROMPT
from skills.alert_triage import run_triage
from skills.playbook_generator import run_playbook_generator
from skills.autonomous_mitigation import run_autonomous_mitigation, ExecutionMode
from skills.audit_logger import AuditLogger, read_audit_stats

logger = logging.getLogger(__name__)

MODEL         = os.environ.get("AGENT_MODEL", "claude-sonnet-4-6")
MAX_TOOL_ROUNDS = 8


# ── Agent class ────────────────────────────────────────────────────────────────

class SOCAgent:
    """
    LLM-based SOC analyst with 3-skill pipeline.

    Each analyze() call is independent (stateless conversation).
    Skill pipeline: Triage → Playbook → Mitigation.
    All decisions are logged to the audit trail.
    """

    def __init__(
        self,
        model: str = MODEL,
        verbose: bool = False,
        audit: bool = True,
        mitigation_mode: ExecutionMode = ExecutionMode.DRY_RUN,
    ):
        self.client           = anthropic.Anthropic()
        self.model            = model
        self.verbose          = verbose
        self.mitigation_mode  = mitigation_mode
        self.audit_logger     = AuditLogger() if audit else None
        self._total_input_tokens  = 0
        self._total_output_tokens = 0

    # ── Low-level: raw tool-calling loop ──────────────────────────────────────

    def analyze(self, user_message: str) -> dict:
        """
        Run single-turn tool-calling loop.
        Returns parsed JSON dict from agent response.
        """
        t0 = time.perf_counter()
        messages = [{"role": "user", "content": user_message}]
        tool_call_log = []

        for round_idx in range(MAX_TOOL_ROUNDS):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages,
            )
            self._total_input_tokens  += response.usage.input_tokens
            self._total_output_tokens += response.usage.output_tokens

            if self.verbose:
                logger.debug(
                    f"[round {round_idx}] stop={response.stop_reason} "
                    f"blocks={len(response.content)}"
                )

            if response.stop_reason == "end_turn":
                text = _extract_text(response.content)
                return self._parse_response(text, tool_call_log, t0)

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    output = execute_tool(block.name, block.input)
                    tool_call_log.append({
                        "round": round_idx,
                        "tool":  block.name,
                        "input": block.input,
                        "output": output,
                    })
                    if self.verbose:
                        logger.debug(
                            f"  tool={block.name} → {json.dumps(output)[:180]}"
                        )
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     json.dumps(output),
                    })
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user",      "content": tool_results})
                continue

            logger.warning(f"Unexpected stop_reason: {response.stop_reason}")
            break

        return {
            "verdict": "ERROR",
            "error":   f"Exceeded {MAX_TOOL_ROUNDS} tool rounds",
            "tool_calls": tool_call_log,
            "latency_ms": (time.perf_counter() - t0) * 1000,
        }

    # ── Skill 1: Alert Triage ─────────────────────────────────────────────────

    def triage(self, features: list[float], alert_id: str = None, context: str = ""):
        """Run Skill 1 — Alert Triage. Returns TriageReport."""
        report = run_triage(self, features, alert_id=alert_id, extra_context=context)
        if self.audit_logger:
            self.audit_logger.log_triage(report)
        return report

    # ── Skill 2: Playbook Generator ───────────────────────────────────────────

    def generate_playbook(self, triage_report):
        """Run Skill 2 — Playbook Generator. Returns GeneratedPlaybook."""
        playbook = run_playbook_generator(self, triage_report)
        if self.audit_logger:
            self.audit_logger.log_playbook(playbook)
        return playbook

    # ── Skill 3: Autonomous Mitigation ────────────────────────────────────────

    def mitigate(self, playbook):
        """Run Skill 3 — Autonomous Mitigation. Returns MitigationResult."""
        result = run_autonomous_mitigation(
            playbook,
            mode=self.mitigation_mode,
            auto_approve_low_risk=True,
            audit_logger=self.audit_logger,
        )
        if self.audit_logger:
            self.audit_logger.log_mitigation_result(result)
        return result

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run_pipeline(
        self,
        features: list[float],
        alert_id: str = None,
        context:  str = "",
        skip_skills: list[str] = None,
    ) -> dict:
        """
        Run the full 3-skill pipeline for a single alert.

        Args:
            features:     17 raw flow features
            alert_id:     Optional alert ID
            context:      Additional context string
            skip_skills:  List of skills to skip: ["playbook", "mitigation"]

        Returns:
            dict with keys: triage, playbook, mitigation, pipeline_latency_ms
        """
        skip = set(skip_skills or [])
        t0 = time.perf_counter()

        # Skill 1: Triage
        triage = self.triage(features, alert_id=alert_id, context=context)
        print(f"\n[TRIAGE] {triage.summary_line()}")

        if triage.recommended_next == "DISMISS" or "playbook" in skip:
            return {
                "triage": triage.to_dict(),
                "playbook": None,
                "mitigation": None,
                "pipeline_latency_ms": (time.perf_counter() - t0) * 1000,
            }

        # Skill 2: Playbook (only for confirmed attacks)
        if triage.verdict in ("ATTACK", "SUSPICIOUS") and triage.attack_type:
            playbook = self.generate_playbook(triage)
            playbook.print_runbook()
        else:
            print("[PLAYBOOK] Skipped — no attack detected")
            return {
                "triage": triage.to_dict(),
                "playbook": None,
                "mitigation": None,
                "pipeline_latency_ms": (time.perf_counter() - t0) * 1000,
            }

        if "mitigation" in skip:
            return {
                "triage":    triage.to_dict(),
                "playbook":  playbook.to_dict(),
                "mitigation": None,
                "pipeline_latency_ms": (time.perf_counter() - t0) * 1000,
            }

        # Skill 3: Mitigation
        mitigation = self.mitigate(playbook)
        print(f"\n[MITIGATION] {mitigation.summary()}")

        return {
            "triage":     triage.to_dict(),
            "playbook":   playbook.to_dict(),
            "mitigation": mitigation.to_dict(),
            "pipeline_latency_ms": (time.perf_counter() - t0) * 1000,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def token_usage(self) -> dict:
        return {
            "total_input_tokens":  self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
        }

    def _parse_response(self, text: str, tool_calls: list, t0: float) -> dict:
        latency_ms = (time.perf_counter() - t0) * 1000
        try:
            clean = text.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            result = json.loads(clean.strip())
        except (json.JSONDecodeError, IndexError):
            result = {"raw_response": text, "parse_error": "Not valid JSON"}
        result["tool_calls"] = tool_calls
        result["latency_ms"] = round(latency_ms, 2)
        return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_text(content_blocks) -> str:
    return " ".join(b.text for b in content_blocks if hasattr(b, "text"))


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PAD-ONAP SOC Agent")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--features",     nargs=17, type=float, metavar="F")
    group.add_argument("--replay",       type=str, metavar="JSONL")
    group.add_argument("--interactive",  action="store_true")
    group.add_argument("--audit-stats",  action="store_true")

    parser.add_argument("--model",       default=MODEL)
    parser.add_argument("--skill",       default="all",
                        choices=["all", "triage", "playbook", "mitigation"],
                        help="Which skill(s) to run (default: all)")
    parser.add_argument("--mode",        default="DRY_RUN",
                        choices=["DRY_RUN", "SIMULATE", "LIVE"],
                        help="Mitigation execution mode (default: DRY_RUN)")
    parser.add_argument("--context",     default="", help="Extra context for triage")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--no-audit",    action="store_true")
    parser.add_argument("--out",         type=str, help="Output JSONL for results")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set.", file=sys.stderr)
        sys.exit(1)

    if args.audit_stats:
        stats = read_audit_stats()
        print(json.dumps(stats, indent=2))
        return

    mode = ExecutionMode(args.mode)
    if mode == ExecutionMode.LIVE:
        confirm = input("WARNING: LIVE mode will execute commands on this host. Confirm? [yes/N]: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    agent = SOCAgent(
        model=args.model,
        verbose=args.verbose,
        audit=not args.no_audit,
        mitigation_mode=mode,
    )

    skip = []
    if args.skill == "triage":
        skip = ["playbook", "mitigation"]
    elif args.skill == "playbook":
        skip = ["mitigation"]

    out_fh = open(args.out, "w") if args.out else None

    try:
        if args.features:
            result = agent.run_pipeline(
                features=args.features,
                context=args.context,
                skip_skills=skip,
            )
            _print_result(result)
            if out_fh:
                out_fh.write(json.dumps(result, default=str) + "\n")

        elif args.replay:
            path = Path(args.replay)
            if not path.exists():
                print(f"ERROR: File not found: {path}", file=sys.stderr)
                sys.exit(1)
            lines = path.read_text().strip().splitlines()
            print(f"Replaying {len(lines)} windows from {path} ...")
            for i, line in enumerate(lines):
                window = json.loads(line)
                features = window.get("features") or window.get("x")
                if features is None:
                    continue
                result = agent.run_pipeline(
                    features=features,
                    alert_id=f"replay_{i:04d}",
                    skip_skills=skip,
                )
                result["window_id"] = window.get("window_id", i)
                if out_fh:
                    out_fh.write(json.dumps(result, default=str) + "\n")
                time.sleep(0.3)

        elif args.interactive:
            print("PAD-ONAP SOC Agent — interactive mode. Type 'quit' to exit.\n")
            print("Commands: 'analyze <features...>' | or type any natural language query\n")
            while True:
                try:
                    msg = input("You: ").strip()
                    if msg.lower() in ("quit", "exit", "q"):
                        break
                    if not msg:
                        continue
                    if msg.startswith("analyze "):
                        # Parse features from message
                        parts = msg.split()[1:]
                        if len(parts) == 17:
                            features = [float(p) for p in parts]
                            result = agent.run_pipeline(features, skip_skills=skip)
                            _print_result(result)
                        else:
                            print(f"Need 17 features, got {len(parts)}")
                        continue
                    # Free-form query (raw analyze)
                    raw = agent.analyze(msg)
                    print(json.dumps(raw, indent=2, default=str))
                except (KeyboardInterrupt, EOFError):
                    break

    finally:
        if out_fh:
            out_fh.close()
        usage = agent.token_usage()
        print(f"\nToken usage: {usage['total_input_tokens']} in / {usage['total_output_tokens']} out")


def _print_result(result: dict):
    triage = result.get("triage") or {}
    pb     = result.get("playbook")
    mit    = result.get("mitigation")
    lat    = result.get("pipeline_latency_ms", 0)

    print(f"\n{'═'*60}")
    print(f"PIPELINE RESULT  ({lat:.0f}ms total)")
    print(f"  Triage:     {triage.get('verdict','?')} | {triage.get('attack_type','-')} "
          f"conf={triage.get('confidence',0):.2f} | {triage.get('recommended_next','-')}")
    if pb:
        print(f"  Playbook:   {pb.get('urgency','?')} | "
              f"{len(pb.get('steps',[]))} steps | MTTR={pb.get('estimated_mttr_s','?')}s")
    if mit:
        print(f"  Mitigation: [{mit.get('execution_mode','?')}] "
              f"approved={mit.get('approved_steps',0)}/{mit.get('total_steps',0)} "
              f"executed={mit.get('executed_steps',0)}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()

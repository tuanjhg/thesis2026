"""
Tool definitions for the LLM SOC Agent.
Each tool maps directly to an Inference API endpoint or local utility.

Tools exposed:
  classify_flow          — Call XGBoost via Inference API
  predict_horizon        — Call Transformer+LSTM via Inference API
  get_lead_time          — Read lead-time analysis results
  query_knowledge_base   — Semantic search over RAG KB (attack patterns, MITRE, playbooks)
  search_threat_intel    — Lookup MITRE ATT&CK technique by ID or keyword
  generate_mitigation    — Generate iptables/BGP mitigation script
  reset_buffer           — Reset transformer rolling buffer
"""

import json
import os
import sys
from pathlib import Path
import requests
from typing import Any

INFERENCE_API = os.environ.get("INFERENCE_API_URL", "http://localhost:8000")

# Allow importing rag module
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Tool schemas (Anthropic tool_use format) ──────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "classify_flow",
        "description": (
            "Classify a single 5-second network flow window using XGBoost. "
            "Returns attack_class (0=Normal,1=UDP_Flood,2=SYN_Flood,3=HTTP_Flood,"
            "4=ICMP_Flood,5=Amplification,6=Slow_rate), confidence score (0-1), "
            "per-class probabilities, and SHAP top-5 feature contributions. "
            "ALWAYS call this before making any verdict about an alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "features": {
                    "type": "array",
                    "items": {"type": "number"},
                    "minItems": 17,
                    "maxItems": 17,
                    "description": (
                        "17 raw flow features in order: pkt_rate, byte_rate, avg_pkt_size, "
                        "pkt_size_std, proto_dist_tcp, proto_dist_udp, proto_dist_icmp, "
                        "proto_dist_other, syn_ratio, fin_ratio, rst_ratio, psh_ratio, "
                        "src_ip_entropy, dst_ip_entropy, src_port_entropy, dst_port_entropy, "
                        "new_flows_rate"
                    ),
                }
            },
            "required": ["features"],
        },
    },
    {
        "name": "predict_horizon",
        "description": (
            "Forecast probability of DDoS attack at 4 future horizons (t+30s, t+60s, t+90s, "
            "t+120s) using the Transformer+LSTM model. Uses last 12 windows in rolling buffer — "
            "returns zeros until buffer is full. Use this to decide WHEN to pre-position "
            "mitigation, not IF (use classify_flow for that)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "features": {
                    "type": "array",
                    "items": {"type": "number"},
                    "minItems": 17,
                    "maxItems": 17,
                    "description": "Same 17-feature vector as classify_flow.",
                }
            },
            "required": ["features"],
        },
    },
    {
        "name": "get_lead_time",
        "description": (
            "Retrieve proactive lead-time analysis results from the evaluation dataset. "
            "Returns how many seconds before attack the Transformer+LSTM trigger fires, "
            "and which horizon (30/60/90/120s) first exceeded threshold. "
            "Use this to communicate response urgency to the operator."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_type": {
                    "type": "string",
                    "enum": ["UDP_Flood", "SYN_Flood", "HTTP_Flood", "ICMP_Flood", "Amplification", "Slow_rate"],
                    "description": "Attack type to look up lead-time stats for.",
                }
            },
            "required": ["attack_type"],
        },
    },
    {
        "name": "generate_mitigation",
        "description": (
            "Generate a mitigation script (iptables rules or BGP FlowSpec) for the detected "
            "attack. Returns a human-readable script string and risk_level. "
            "REQUIRES confidence >= 0.85 from classify_flow before calling. "
            "Output is a SUGGESTION only — never auto-execute without human approval."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_type": {
                    "type": "string",
                    "enum": ["UDP_Flood", "SYN_Flood", "HTTP_Flood", "ICMP_Flood", "Amplification", "Slow_rate"],
                    "description": "Detected attack type.",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence from classify_flow. Must be >= 0.85.",
                },
                "top_features": {
                    "type": "object",
                    "description": "SHAP top features from classify_flow (used to tailor rules).",
                },
            },
            "required": ["attack_type", "confidence"],
        },
    },
    {
        "name": "query_knowledge_base",
        "description": (
            "Semantic search over the RAG knowledge base. Use this to look up: "
            "(1) past attack patterns and scenarios — collection='attack_patterns'; "
            "(2) MITRE ATT&CK techniques for DDoS — collection='mitre_attack'; "
            "(3) proactive lead-time stats per attack type — collection='lead_time'; "
            "(4) step-by-step SOC response playbooks — collection='playbooks'. "
            "Use this to enrich your analysis with historical context and best practices."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language query, e.g. 'SYN flood lead time proactive trigger'",
                },
                "collection": {
                    "type": "string",
                    "enum": ["attack_patterns", "mitre_attack", "lead_time", "playbooks"],
                    "description": "Which knowledge collection to search.",
                },
                "n_results": {
                    "type": "integer",
                    "default": 3,
                    "description": "Number of results to return (1-5).",
                },
            },
            "required": ["query", "collection"],
        },
    },
    {
        "name": "search_threat_intel",
        "description": (
            "Look up a specific MITRE ATT&CK technique by ID (e.g. 'T1498', 'T1498.001') "
            "or search by keyword (e.g. 'UDP flood amplification'). "
            "Returns technique description, detection guidance, and mitigation references."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Technique ID like 'T1498' or keyword like 'SYN flood TCP'",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "reset_buffer",
        "description": (
            "Reset the Transformer+LSTM rolling window buffer. "
            "Call this when switching between different attack scenarios or after a long idle period."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


# ── Tool executor ─────────────────────────────────────────────────────────────

def execute_tool(tool_name: str, tool_input: dict) -> dict[str, Any]:
    """Dispatch tool call to Inference API or local handler. Returns JSON-serializable dict."""
    try:
        if tool_name == "classify_flow":
            return _classify_flow(tool_input)
        elif tool_name == "predict_horizon":
            return _predict_horizon(tool_input)
        elif tool_name == "get_lead_time":
            return _get_lead_time(tool_input)
        elif tool_name == "query_knowledge_base":
            return _query_knowledge_base(tool_input)
        elif tool_name == "search_threat_intel":
            return _search_threat_intel(tool_input)
        elif tool_name == "generate_mitigation":
            return _generate_mitigation(tool_input)
        elif tool_name == "reset_buffer":
            return _reset_buffer()
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except requests.ConnectionError:
        return {"error": f"Inference API unavailable at {INFERENCE_API}. Start it with: python -m agent.api.inference_api"}
    except Exception as e:
        return {"error": str(e)}


def _classify_flow(inp: dict) -> dict:
    resp = requests.post(f"{INFERENCE_API}/classify_flow", json=inp, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _predict_horizon(inp: dict) -> dict:
    resp = requests.post(f"{INFERENCE_API}/predict_horizon", json=inp, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _reset_buffer() -> dict:
    resp = requests.post(f"{INFERENCE_API}/reset_buffer", timeout=5)
    resp.raise_for_status()
    return resp.json()


def _query_knowledge_base(inp: dict) -> dict:
    query      = inp.get("query", "")
    collection = inp.get("collection", "attack_patterns")
    n_results  = int(inp.get("n_results", 3))
    try:
        from rag.knowledge_base import query_knowledge_base
        results = query_knowledge_base(query, collection=collection, n_results=n_results)
        return {"collection": collection, "query": query, "results": results}
    except ImportError as e:
        return {"error": f"RAG not available: {e}. Run: pip install chromadb sentence-transformers"}
    except Exception as e:
        return {"error": str(e), "hint": "Run python agent/build_index.py first to build the KB"}


def _search_threat_intel(inp: dict) -> dict:
    query = inp.get("query", "").strip()
    try:
        from rag.knowledge_base import query_knowledge_base
        # If looks like a technique ID, search by ID first
        if query.upper().startswith("T") and any(c.isdigit() for c in query):
            results = query_knowledge_base(
                f"MITRE {query.upper()} technique",
                collection="mitre_attack",
                n_results=2,
            )
        else:
            results = query_knowledge_base(query, collection="mitre_attack", n_results=3)
        return {"query": query, "technique_results": results}
    except ImportError as e:
        return {"error": f"RAG not available: {e}"}
    except Exception as e:
        return {"error": str(e)}


# Lead-time results path (from evaluation outputs)
_LEAD_TIME_PATHS = [
    os.path.join(os.path.dirname(__file__), "../../evaluation/lead_time_analysis.json"),
    os.path.join(os.path.dirname(__file__), "../../evaluation/proactive_lead_time_results.json"),
]

def _get_lead_time(inp: dict) -> dict:
    attack_type = inp.get("attack_type", "")
    for path in _LEAD_TIME_PATHS:
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            # Try direct key lookup, then search nested
            if attack_type in data:
                return {"attack_type": attack_type, "lead_time_stats": data[attack_type], "source": path}
            # Search for any dict entry matching attack type
            for k, v in data.items():
                if isinstance(v, dict) and attack_type.lower() in k.lower():
                    return {"attack_type": attack_type, "lead_time_stats": v, "source": path}
            # Return all if specific type not found
            return {"attack_type": attack_type, "available_data": data, "note": "exact match not found"}
    return {
        "attack_type": attack_type,
        "error": "Lead-time analysis file not found. Run scripts/proactive_lead_time.py first.",
        "searched_paths": _LEAD_TIME_PATHS,
    }


# Mitigation templates (rule-based, not ML)
_MITIGATION_TEMPLATES = {
    "SYN_Flood": {
        "script_type": "iptables",
        "commands": [
            "# SYN Flood mitigation — SYN cookie + rate limit",
            "sysctl -w net.ipv4.tcp_syncookies=1",
            "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
        ],
        "risk_level": "medium",
        "estimated_false_positive_impact": "May drop ~0.1% legitimate new TCP connections",
    },
    "UDP_Flood": {
        "script_type": "iptables",
        "commands": [
            "# UDP Flood mitigation — rate limit per source",
            "iptables -A INPUT -p udp -m hashlimit --hashlimit-name udp_flood "
            "--hashlimit-above 100/sec --hashlimit-mode srcip -j DROP",
        ],
        "risk_level": "low",
        "estimated_false_positive_impact": "May throttle high-rate UDP services (DNS, video)",
    },
    "HTTP_Flood": {
        "script_type": "iptables + nginx",
        "commands": [
            "# HTTP Flood mitigation — connection rate limit",
            "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j DROP",
            "iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j DROP",
            "# nginx: add 'limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;' to server block",
        ],
        "risk_level": "medium",
        "estimated_false_positive_impact": "May block clients behind NAT with many connections",
    },
    "ICMP_Flood": {
        "script_type": "iptables",
        "commands": [
            "# ICMP Flood mitigation — rate limit",
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
        ],
        "risk_level": "low",
        "estimated_false_positive_impact": "Reduces ping responses; no service impact",
    },
    "Amplification": {
        "script_type": "bgp_flowspec",
        "commands": [
            "# Amplification mitigation — BGP FlowSpec + source validation",
            "# Add to router: ip flowspec local-install",
            "# flowspec rule: drop UDP src-port 53,123,19 dst-ip <victim-ip>",
            "iptables -A INPUT -p udp --sport 53 -j DROP   # DNS amp",
            "iptables -A INPUT -p udp --sport 123 -j DROP  # NTP amp",
            "iptables -A INPUT -p udp --sport 19 -j DROP   # Chargen amp",
        ],
        "risk_level": "high",
        "estimated_false_positive_impact": "Blocks all DNS/NTP responses — verify with ops before applying",
    },
    "Slow_rate": {
        "script_type": "nginx",
        "commands": [
            "# Slow-rate mitigation — connection timeout tuning",
            "# In nginx.conf:",
            "# client_body_timeout 10;",
            "# client_header_timeout 10;",
            "# keepalive_timeout 5 5;",
            "# send_timeout 10;",
        ],
        "risk_level": "low",
        "estimated_false_positive_impact": "May disconnect slow legitimate clients",
    },
}


def _generate_mitigation(inp: dict) -> dict:
    attack_type = inp.get("attack_type", "")
    confidence  = float(inp.get("confidence", 0.0))
    top_features = inp.get("top_features", {})

    if confidence < 0.85:
        return {
            "error": f"Confidence {confidence:.3f} < 0.85 threshold. Mitigation generation refused.",
            "advice": "Gather more windows or escalate to human analyst.",
        }

    template = _MITIGATION_TEMPLATES.get(attack_type)
    if not template:
        return {"error": f"No mitigation template for attack type: {attack_type}"}

    # Annotate dominant features in script comments
    script_lines = list(template["commands"])
    if top_features:
        top_str = ", ".join(f"{k}={v:.3f}" for k, v in list(top_features.items())[:3])
        script_lines.insert(1, f"# Top SHAP indicators: {top_str}")

    return {
        "attack_type": attack_type,
        "script_type": template["script_type"],
        "script": "\n".join(script_lines),
        "risk_level": template["risk_level"],
        "false_positive_impact": template["estimated_false_positive_impact"],
        "confidence_used": confidence,
        "status": "PENDING_HUMAN_APPROVAL",
        "warning": "DO NOT execute without operator review and approval.",
    }

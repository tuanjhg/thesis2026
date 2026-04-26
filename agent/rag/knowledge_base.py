"""
RAG Knowledge Base for the SOC Agent.

Stores and retrieves:
  1. Attack scenario patterns (from evaluation scenarios S1-S8)
  2. MITRE ATT&CK DDoS tactics (T1498, T1499, TA0040)
  3. Lead-time analysis results per attack type
  4. Mitigation playbooks

Uses ChromaDB (local, on-prem) with sentence-transformers embeddings.
No external API calls — suitable for air-gapped security environments.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy imports — only needed after build_index is called
_chroma = None
_embedder = None

KB_DIR = os.environ.get(
    "KB_DIR",
    str(Path(__file__).parent / "kb_store")
)
EMBED_MODEL = os.environ.get("EMBED_MODEL", "all-MiniLM-L6-v2")

COLLECTIONS = {
    "attack_patterns": "Attack scenario patterns with feature signatures",
    "mitre_attack":    "MITRE ATT&CK DDoS techniques and mitigations",
    "lead_time":       "Proactive lead-time statistics per attack type",
    "playbooks":       "Step-by-step SOC response playbooks",
}


# ── Init ───────────────────────────────────────────────────────────────────────

def _get_client():
    global _chroma
    if _chroma is None:
        try:
            import chromadb
            _chroma = chromadb.PersistentClient(path=KB_DIR)
        except ImportError:
            raise ImportError(
                "chromadb not installed. Run: pip install chromadb sentence-transformers"
            )
    return _chroma


def _get_embedder():
    global _embedder
    if _embedder is None:
        try:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer(EMBED_MODEL)
        except ImportError:
            raise ImportError(
                "sentence-transformers not installed. Run: pip install sentence-transformers"
            )
    return _embedder


def _embed(texts: list[str]) -> list[list[float]]:
    return _get_embedder().encode(texts, show_progress_bar=False).tolist()


# ── Query ──────────────────────────────────────────────────────────────────────

def query_knowledge_base(
    query: str,
    collection: str = "attack_patterns",
    n_results: int = 3,
) -> list[dict]:
    """
    Semantic search over a named collection.

    Args:
        query:      Natural language query
        collection: One of attack_patterns, mitre_attack, lead_time, playbooks
        n_results:  Number of results to return

    Returns:
        List of {id, document, metadata, distance} dicts
    """
    client = _get_client()
    try:
        col = client.get_collection(collection)
    except Exception:
        return [{"error": f"Collection '{collection}' not found. Run build_index.py first."}]

    query_emb = _embed([query])
    results = col.query(
        query_embeddings=query_emb,
        n_results=min(n_results, col.count()),
        include=["documents", "metadatas", "distances"],
    )

    out = []
    for i, doc in enumerate(results["documents"][0]):
        out.append({
            "id":       results["ids"][0][i],
            "document": doc,
            "metadata": results["metadatas"][0][i],
            "distance": round(results["distances"][0][i], 4),
        })
    return out


def collection_stats() -> dict:
    """Return count of documents in each collection."""
    client = _get_client()
    stats = {}
    for name in COLLECTIONS:
        try:
            col = client.get_collection(name)
            stats[name] = col.count()
        except Exception:
            stats[name] = 0
    return stats


# ── Build index ────────────────────────────────────────────────────────────────

def build_index(project_root: str = None, force: bool = False) -> dict:
    """
    Build all ChromaDB collections from project data.

    Args:
        project_root: Path to project root (default: auto-detect)
        force:        Delete and rebuild existing collections

    Returns:
        Dict with count of documents indexed per collection
    """
    if project_root is None:
        project_root = str(Path(__file__).parent.parent.parent)

    root = Path(project_root)
    client = _get_client()
    counts = {}

    counts["attack_patterns"] = _index_attack_patterns(client, root, force)
    counts["mitre_attack"]    = _index_mitre_attack(client, force)
    counts["lead_time"]       = _index_lead_time(client, root, force)
    counts["playbooks"]       = _index_playbooks(client, force)

    logger.info(f"Knowledge base built: {counts}")
    return counts


def _get_or_create(client, name: str, force: bool):
    if force:
        try:
            client.delete_collection(name)
        except Exception:
            pass
    try:
        return client.get_collection(name)
    except Exception:
        return client.create_collection(name)


def _index_attack_patterns(client, root: Path, force: bool) -> int:
    """Index 8 evaluation scenarios as attack pattern documents."""
    col = _get_or_create(client, "attack_patterns", force)
    if col.count() > 0 and not force:
        logger.info(f"attack_patterns: {col.count()} docs (skip rebuild)")
        return col.count()

    docs, ids, metas = [], [], []

    # Build from scenarios.py knowledge (static descriptions + feature signatures)
    scenarios = [
        {
            "id": "S1_normal_baseline",
            "name": "Normal Traffic Baseline",
            "attack_type": "Normal",
            "description": (
                "Pure normal traffic — no attack. Low packet rate (50-200 pkt/s), "
                "balanced entropy (2.5-3.5 bits), mixed TCP/UDP, "
                "low SYN ratio (<0.05), normal flow duration."
            ),
            "key_features": {
                "pkt_rate": "50-200", "syn_ratio": "<0.05",
                "src_ip_entropy": "2.5-3.5", "proto_dist_udp": "0.1-0.3"
            },
            "tier": 0,
            "mitigation": "NONE",
        },
        {
            "id": "S2_sudden_udp_flood",
            "name": "Sudden UDP Flood",
            "attack_type": "UDP_Flood",
            "description": (
                "Sudden high-rate UDP flood. Packet rate spikes to 5000-20000 pkt/s, "
                "proto_dist_udp=0.85-1.0, low src_ip_entropy (0.0-0.5 — spoofed IPs), "
                "small packets (64-128 bytes). Escalates to Tier 3 reactive scrubber. "
                "No proactive trigger (too sudden for forecast buffer)."
            ),
            "key_features": {
                "pkt_rate": "5000-20000", "proto_dist_udp": "0.85-1.0",
                "src_ip_entropy": "0.0-0.5", "avg_pkt_size": "64-128"
            },
            "tier": 3,
            "mitigation": "iptables UDP rate-limit + BGP blackhole",
        },
        {
            "id": "S3_gradual_syn_ramp",
            "name": "Gradual SYN Flood Ramp",
            "attack_type": "SYN_Flood",
            "description": (
                "SYN flood that ramps up gradually over 30 windows. Allows Transformer+LSTM "
                "forecast to predict attack 30s before threshold. syn_ratio rises 0.0→0.95, "
                "proto_dist_tcp=0.8-1.0, low src entropy (spoofed SYNs), fin_ratio near 0. "
                "Triggers proactive Tier 2 pre-positioning (latency ~500ms vs 6000ms reactive)."
            ),
            "key_features": {
                "syn_ratio": "0.7-0.99", "proto_dist_tcp": "0.8-1.0",
                "src_ip_entropy": "0.0-0.3", "fin_ratio": "<0.01"
            },
            "tier": 2,
            "mitigation": "SYN cookie + iptables rate-limit",
        },
        {
            "id": "S4_http_flood_ood",
            "name": "HTTP Flood (Out-of-Distribution)",
            "attack_type": "HTTP_Flood",
            "description": (
                "HTTP flood — NOT in CICDDoS2019 training data. Appears as normal-ish traffic "
                "with slightly elevated pkt_rate (1000-5000), all-TCP, many new connections. "
                "Model correctly returns low confidence → at most Tier 1 alert, no T3 escalation. "
                "Demonstrates graceful OOD handling."
            ),
            "key_features": {
                "pkt_rate": "1000-5000", "proto_dist_tcp": "0.9-1.0",
                "new_flows_rate": "50-200", "confidence": "<0.70"
            },
            "tier": 1,
            "mitigation": "nginx rate-limit + connection limit",
        },
        {
            "id": "S5_icmp_burst_ood",
            "name": "ICMP Burst (Out-of-Distribution)",
            "attack_type": "ICMP_Flood",
            "description": (
                "Short ICMP burst (20 windows) — NOT in CICDDoS2019 training data. "
                "proto_dist_icmp=0.7-1.0, large reflected packets (512-1500 bytes). "
                "Model treats as OOD → Tier 0 or at most Tier 1. No false T3."
            ),
            "key_features": {
                "proto_dist_icmp": "0.7-1.0", "avg_pkt_size": "512-1500",
                "pkt_rate": "2000-8000"
            },
            "tier": 0,
            "mitigation": "iptables ICMP rate-limit",
        },
        {
            "id": "S6_multi_attack",
            "name": "Multi-Attack: UDP then SYN",
            "attack_type": "UDP_Flood + SYN_Flood",
            "description": (
                "Two consecutive attack phases: UDP flood (Tier 3) then cooldown then SYN flood (Tier 2). "
                "Tests tier switching and hysteresis. System correctly de-escalates between phases. "
                "proactive_count=48 for SYN phase."
            ),
            "key_features": {
                "phase1_pkt_rate": "5000-20000", "phase1_proto_dist_udp": "0.85-1.0",
                "phase2_syn_ratio": "0.7-0.99", "phase2_proto_dist_tcp": "0.8-1.0"
            },
            "tier": 3,
            "mitigation": "Phase 1: UDP rate-limit; Phase 2: SYN cookie",
        },
        {
            "id": "S7_sla_fairness",
            "name": "SLA Fairness Under Attack",
            "attack_type": "SYN_Flood",
            "description": (
                "Moderate SYN flood (intensity=1.2) with 3 tenants. "
                "Tests LP-based bandwidth allocation under VNF overhead. "
                "URLLC tenant floor maintained. proactive_count=78 (T2 triggered 78 times)."
            ),
            "key_features": {
                "syn_ratio": "0.7-0.99", "tenants": "3",
                "tier": "2", "proactive_count": "78"
            },
            "tier": 2,
            "mitigation": "SYN cookie + LP bandwidth reallocation",
        },
        {
            "id": "S8_proactive_vs_reactive",
            "name": "Proactive T2 vs Reactive T3 Latency",
            "attack_type": "SYN_Flood + UDP_Flood",
            "description": (
                "KEY NOVELTY SCENARIO. Phase 1: moderate SYN flood triggers proactive Tier 2 "
                "in ~500ms via forecast P(t+30s)>0.5. Phase 2: strong UDP flood triggers "
                "reactive Tier 3 in ~6000ms. Demonstrates 11.9x latency advantage of "
                "proactive pre-positioning over reactive scrubbing."
            ),
            "key_features": {
                "t2_latency_p95": "505ms", "t3_latency_p95": "6006ms",
                "advantage_factor": "11.9x", "proactive_count": "30"
            },
            "tier": 3,
            "mitigation": "T2: SYN cookie pre-positioned; T3: UDP BGP blackhole",
        },
    ]

    for sc in scenarios:
        doc_text = (
            f"Attack: {sc['name']} | Type: {sc['attack_type']} | "
            f"Tier: {sc['tier']} | {sc['description']} | "
            f"Mitigation: {sc['mitigation']}"
        )
        docs.append(doc_text)
        ids.append(sc["id"])
        metas.append({
            "attack_type": sc["attack_type"],
            "tier": str(sc["tier"]),
            "mitigation": sc["mitigation"],
            "scenario_id": sc["id"],
        })

    # Also index evaluation result summaries if available
    results_dir = root / "evaluation" / "results"
    for summary_file in results_dir.glob("*_summary.json"):
        try:
            data = json.loads(summary_file.read_text())
            doc_text = (
                f"Evaluation result for {data.get('scenario', summary_file.stem)}: "
                f"n_windows={data.get('n_windows')}, "
                f"max_tier={data.get('max_tier_reached')}, "
                f"proactive_count={data.get('proactive_count')}, "
                f"pass_fail={data.get('pass_fail')}, "
                f"T2_p95={data.get('tier2_latency_ms', {}).get('p95')}ms, "
                f"T3_p95={data.get('tier3_latency_ms', {}).get('p95')}ms"
            )
            sid = f"result_{data.get('scenario', summary_file.stem)}"
            if sid not in ids:
                docs.append(doc_text)
                ids.append(sid)
                metas.append({
                    "attack_type": data.get("scenario", ""),
                    "tier": str(data.get("max_tier_reached", 0)),
                    "source": "evaluation_results",
                    "pass_fail": data.get("pass_fail", ""),
                })
        except Exception as e:
            logger.warning(f"Could not parse {summary_file}: {e}")

    embeddings = _embed(docs)
    col.add(documents=docs, ids=ids, metadatas=metas, embeddings=embeddings)
    logger.info(f"attack_patterns: indexed {len(docs)} documents")
    return len(docs)


def _index_mitre_attack(client, force: bool) -> int:
    """Index relevant MITRE ATT&CK techniques for DDoS/Impact."""
    col = _get_or_create(client, "mitre_attack", force)
    if col.count() > 0 and not force:
        logger.info(f"mitre_attack: {col.count()} docs (skip rebuild)")
        return col.count()

    techniques = [
        {
            "id": "T1498",
            "name": "Network Denial of Service",
            "tactic": "TA0040 Impact",
            "description": (
                "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or "
                "block the availability of targeted resources to users. Direct network floods "
                "and amplification/reflection attacks are sub-techniques. "
                "Data sources: Network Traffic Flow, Network Traffic Content. "
                "Mitigation: Filter network traffic (M1037), Limit access to resource over network (M1035)."
            ),
            "subtechniques": ["T1498.001 Direct Network Flood", "T1498.002 Reflection Amplification"],
            "detections": "Monitor for network traffic patterns indicating unusual packet rates or protocols.",
        },
        {
            "id": "T1498.001",
            "name": "Direct Network Flood",
            "tactic": "TA0040 Impact",
            "description": (
                "Adversaries may attempt to cause a DoS by directly sending a high-volume of network traffic "
                "to a target. UDP floods, SYN floods, and ICMP floods are common examples. "
                "Indicators: pkt_rate spike, single-protocol dominance, low entropy IP addresses (spoofed). "
                "SHAP features: pkt_rate, proto_dist_udp/tcp, src_ip_entropy."
            ),
            "subtechniques": [],
            "detections": "Monitor pkt_rate, proto_dist_*, syn_ratio for anomalies.",
        },
        {
            "id": "T1498.002",
            "name": "Reflection Amplification",
            "tactic": "TA0040 Impact",
            "description": (
                "Adversaries use third-party servers to amplify DoS traffic. UDP protocols like DNS (port 53), "
                "NTP (port 123), Chargen (port 19) used. Large reflected packets typical (512-1500 bytes). "
                "Indicators: large avg_pkt_size, high byte_rate vs pkt_rate ratio, specific UDP src ports. "
                "Mitigation: Block amplification vectors with BGP FlowSpec DROP UDP src-port 53,123,19."
            ),
            "subtechniques": [],
            "detections": "Monitor avg_pkt_size, byte_rate/pkt_rate ratio, UDP port distribution.",
        },
        {
            "id": "T1499",
            "name": "Endpoint Denial of Service",
            "tactic": "TA0040 Impact",
            "description": (
                "Adversaries may target application layer resources to cause DoS. HTTP floods, "
                "Slowloris slow-rate attacks are examples. Often harder to distinguish from legitimate "
                "traffic. Indicators: high new_flows_rate, all-TCP, low to moderate pkt_rate. "
                "Out-of-distribution for CICDDoS2019-trained models — expect low confidence classification."
            ),
            "subtechniques": ["T1499.001 OS Exhaustion Flood", "T1499.002 Service Exhaustion Flood",
                               "T1499.003 Application Exhaustion Flood"],
            "detections": "Monitor new_flows_rate, TCP connection patterns, application response times.",
        },
        {
            "id": "M1037",
            "name": "Filter Network Traffic (Mitigation)",
            "tactic": "Mitigation",
            "description": (
                "Use network appliances or services to filter ingress/egress traffic. "
                "Implementation: iptables rate limiting (--hashlimit, -m limit), BGP FlowSpec DROP rules, "
                "SYN cookies (net.ipv4.tcp_syncookies=1), nginx connection limits. "
                "Apply after classification confidence >= 0.85 and human approval."
            ),
            "subtechniques": [],
            "detections": "N/A — this is a mitigation, not a detection.",
        },
        {
            "id": "TA0040",
            "name": "Impact Tactic",
            "tactic": "TA0040 Impact",
            "description": (
                "The adversary is trying to manipulate, interrupt, or destroy your systems and data. "
                "Impact techniques include: Network DoS (T1498), Endpoint DoS (T1499), "
                "Data Destruction, Defacement. For DDoS defense, focus on T1498 and T1499. "
                "Response: detect with ML classifier, pre-position with Transformer forecast, "
                "mitigate with ONAP Tier 2/3 automation."
            ),
            "subtechniques": [],
            "detections": "Correlate network flow anomalies with service availability metrics.",
        },
    ]

    docs, ids, metas = [], [], []
    for t in techniques:
        doc_text = (
            f"MITRE {t['id']}: {t['name']} | Tactic: {t['tactic']} | "
            f"{t['description']} | Detection: {t['detections']}"
        )
        docs.append(doc_text)
        ids.append(t["id"])
        metas.append({
            "technique_id": t["id"],
            "name": t["name"],
            "tactic": t["tactic"],
        })

    embeddings = _embed(docs)
    col.add(documents=docs, ids=ids, metadatas=metas, embeddings=embeddings)
    logger.info(f"mitre_attack: indexed {len(docs)} documents")
    return len(docs)


def _index_lead_time(client, root: Path, force: bool) -> int:
    """Index lead-time analysis results per attack type and scenario."""
    col = _get_or_create(client, "lead_time", force)
    if col.count() > 0 and not force:
        logger.info(f"lead_time: {col.count()} docs (skip rebuild)")
        return col.count()

    docs, ids, metas = [], [], []

    # Derived from evaluation results (S3, S6, S7, S8 have proactive data)
    lead_time_data = [
        {
            "id": "lt_syn_flood",
            "attack_type": "SYN_Flood",
            "description": (
                "SYN Flood lead-time analysis: Transformer+LSTM forecast fires "
                "P(t+30s) > 0.50 approximately 30-60 seconds before attack reaches "
                "classification confidence threshold. S3 scenario: 67 proactive triggers. "
                "S7 scenario: 78 proactive triggers. S8: T2 pre-positioned in 505ms "
                "vs T3 reactive in 6006ms — 11.9x advantage. "
                "Proactive trigger requires: P(t+30s) > 0.50 AND XGBoost conf > 0.75 AND class != Normal."
            ),
            "lead_time_sec": 30,
            "proactive_window_count": {"S3": 67, "S7": 78, "S8": 30},
            "tier2_latency_p95_ms": 505.51,
            "tier3_latency_p95_ms": 6006.0,
        },
        {
            "id": "lt_udp_flood",
            "attack_type": "UDP_Flood",
            "description": (
                "UDP Flood lead-time analysis: Sudden floods typically have no proactive trigger "
                "(attack appears without ramp-up, Transformer buffer has insufficient signal). "
                "S2 scenario: proactive_count=0 — escalated directly to Tier 3 reactive (6006ms). "
                "Recommendation: rule-based fast-path for sudden high-rate floods. "
                "Lead time is effectively 0 for sudden floods; ~30s for gradual UDP ramp-up."
            ),
            "lead_time_sec": 0,
            "proactive_window_count": {"S2": 0, "S6_udp_phase": 0},
            "tier3_latency_p95_ms": 6006.02,
        },
        {
            "id": "lt_multi_attack",
            "attack_type": "UDP_Flood + SYN_Flood",
            "description": (
                "Multi-attack scenario (S6) lead-time: UDP phase has no proactive trigger (sudden). "
                "SYN phase after cooldown: 48 proactive triggers. System correctly transitions "
                "T3→T2 as attack type changes. E2E latency p95=5729ms (dominated by T3 UDP phase), "
                "T2 p95=505ms (SYN proactive phase)."
            ),
            "lead_time_sec": 30,
            "proactive_window_count": {"S6_syn_phase": 48},
            "tier2_latency_p95_ms": 505.04,
            "tier3_latency_p95_ms": 6004.53,
        },
        {
            "id": "lt_http_flood_ood",
            "attack_type": "HTTP_Flood",
            "description": (
                "HTTP Flood lead-time: NOT in CICDDoS2019 training data (OOD). "
                "Model returns low confidence (<0.70) → proactive_count=0 in S4. "
                "No Tier 2 or Tier 3 escalation. Lead time concept does not apply. "
                "Recommendation: supplement training data with HTTP flood samples for future work."
            ),
            "lead_time_sec": None,
            "proactive_window_count": {"S4": 0},
            "note": "OOD attack type — model not trained on this class",
        },
    ]

    # Also try loading from actual lead_time_analysis files
    for path_candidate in [
        root / "evaluation" / "lead_time_analysis.json",
        root / "evaluation" / "proactive_lead_time_results.json",
    ]:
        if path_candidate.exists():
            try:
                file_data = json.loads(path_candidate.read_text())
                doc_text = f"Lead-time analysis from {path_candidate.name}: {json.dumps(file_data)[:800]}"
                docs.append(doc_text)
                ids.append(f"file_{path_candidate.stem}")
                metas.append({"source": str(path_candidate), "type": "file"})
            except Exception as e:
                logger.warning(f"Could not parse {path_candidate}: {e}")

    for lt in lead_time_data:
        doc_text = (
            f"Lead-time for {lt['attack_type']}: {lt['description']} "
            f"| lead_time_sec={lt.get('lead_time_sec')} "
            f"| proactive_windows={lt.get('proactive_window_count')}"
        )
        docs.append(doc_text)
        ids.append(lt["id"])
        metas.append({
            "attack_type": lt["attack_type"],
            "lead_time_sec": str(lt.get("lead_time_sec", "N/A")),
        })

    embeddings = _embed(docs)
    col.add(documents=docs, ids=ids, metadatas=metas, embeddings=embeddings)
    logger.info(f"lead_time: indexed {len(docs)} documents")
    return len(docs)


def _index_playbooks(client, force: bool) -> int:
    """Index SOC response playbooks per attack type."""
    col = _get_or_create(client, "playbooks", force)
    if col.count() > 0 and not force:
        logger.info(f"playbooks: {col.count()} docs (skip rebuild)")
        return col.count()

    playbooks = [
        {
            "id": "pb_syn_flood",
            "attack_type": "SYN_Flood",
            "title": "SYN Flood Response Playbook",
            "steps": [
                "1. DETECT: classify_flow returns SYN_Flood, syn_ratio > 0.70, confidence >= 0.85",
                "2. FORECAST: predict_horizon P(t+30s) > 0.50 → pre-position Tier 2",
                "3. IMMEDIATE (T=0s): Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                "4. RATE-LIMIT (T=5s): iptables SYN rate limit --limit 1/s --limit-burst 3",
                "5. MONITOR: Watch syn_ratio and confidence for 5 windows",
                "6. ESCALATE (if sustained): Activate Tier 3 scrubber via ONAP SO",
                "7. DE-ESCALATE: If syn_ratio < 0.10 for 3 consecutive windows → restore Tier 0",
            ],
            "expected_latency": "T2 pre-position: ~500ms | T3 reactive: ~6000ms",
            "false_positive_risk": "Medium — SYN cookies may affect slow clients",
        },
        {
            "id": "pb_udp_flood",
            "attack_type": "UDP_Flood",
            "title": "UDP Flood Response Playbook",
            "steps": [
                "1. DETECT: classify_flow returns UDP_Flood, proto_dist_udp > 0.85, pkt_rate > 5000",
                "2. NOTE: Sudden UDP floods have no proactive trigger — react immediately",
                "3. IMMEDIATE (T=0s): iptables hashlimit per source: --hashlimit-above 100/sec",
                "4. IF src_ip_entropy < 0.5 (spoofed): Add null-route for top source prefixes",
                "5. ESCALATE (T3): Activate reactive scrubber — BGP blackhole if volumetric",
                "6. MONITOR: Watch byte_rate and pkt_rate for decrease",
                "7. DE-ESCALATE: If UDP ratio < 0.30 for 3 consecutive windows → restore Tier 0",
            ],
            "expected_latency": "T3 reactive: ~6000ms (no proactive path for sudden floods)",
            "false_positive_risk": "Low — high pkt_rate + high UDP ratio is clear signal",
        },
        {
            "id": "pb_amplification",
            "attack_type": "Amplification",
            "title": "Amplification Attack Response Playbook",
            "steps": [
                "1. DETECT: classify_flow returns Amplification, avg_pkt_size > 512, byte_rate high",
                "2. IDENTIFY: Check src UDP ports — DNS(53), NTP(123), Chargen(19), SSDP(1900)",
                "3. IMMEDIATE: BGP FlowSpec DROP rules for amplification ports",
                "   iptables -A INPUT -p udp --sport 53 -j DROP",
                "   iptables -A INPUT -p udp --sport 123 -j DROP",
                "4. CAUTION: Risk high — DNS/NTP blocking affects legitimate traffic",
                "5. NARROW SCOPE: If possible, scope to victim destination IP only",
                "6. NOTIFY: Upstream provider for BGP-level mitigation",
            ],
            "expected_latency": "T2 with pre-position or T3 reactive depending on ramp speed",
            "false_positive_risk": "High — verify with ops before blocking DNS/NTP",
        },
        {
            "id": "pb_http_flood",
            "attack_type": "HTTP_Flood",
            "title": "HTTP Flood Response Playbook (OOD)",
            "steps": [
                "1. DETECT: HTTP flood is OOD — expect low confidence (<0.70) from classifier",
                "2. TRIAGE: Monitor new_flows_rate and TCP connection counts at app layer",
                "3. RATE-LIMIT: nginx limit_req_zone — 10 req/s per IP",
                "4. CONNECTION LIMIT: iptables --connlimit-above 50 per source IP",
                "5. ESCALATE TO ANALYST: Low ML confidence — needs human review",
                "6. NOTE: Retrain model with HTTP flood samples for future automation",
            ],
            "expected_latency": "Manual — no automated T2/T3 path for HTTP flood",
            "false_positive_risk": "Medium — connection limits may affect NAT'ed users",
        },
        {
            "id": "pb_deescalation",
            "attack_type": "All",
            "title": "De-escalation and Recovery Playbook",
            "steps": [
                "1. CONDITION: Attack class returns to Normal for 3+ consecutive windows",
                "2. VERIFY: confidence(Normal) > 0.80 AND pkt_rate < 300 AND syn_ratio < 0.05",
                "3. TIER 3→2: Remove scrubber rules, restore BGP routes",
                "4. TIER 2→0: Remove rate-limit rules, restore SYN defaults",
                "5. VERIFY SLA: Check tenant bandwidth allocation returned to normal",
                "6. LOG: Record incident duration, max_tier, proactive_count, SHAP features",
                "7. REVIEW: Analyze SHAP evidence for false positive/negative patterns",
            ],
            "expected_latency": "Policy hysteresis: 3 windows × 5s = 15s minimum de-escalation delay",
            "false_positive_risk": "N/A — this is recovery",
        },
    ]

    docs, ids, metas = [], [], []
    for pb in playbooks:
        doc_text = (
            f"Playbook: {pb['title']} for {pb['attack_type']} | "
            f"Steps: {' '.join(pb['steps'])} | "
            f"Latency: {pb['expected_latency']} | "
            f"FP Risk: {pb['false_positive_risk']}"
        )
        docs.append(doc_text)
        ids.append(pb["id"])
        metas.append({
            "attack_type": pb["attack_type"],
            "title": pb["title"],
        })

    embeddings = _embed(docs)
    col.add(documents=docs, ids=ids, metadatas=metas, embeddings=embeddings)
    logger.info(f"playbooks: indexed {len(docs)} documents")
    return len(docs)

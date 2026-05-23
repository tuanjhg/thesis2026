"""
Scenario catalog — rich metadata for the frontend picker and runner.

Topology sizing is mutable at runtime via set_k():
  · k=2 → 2 hosts  (h0, h1)              attacker=h0, victim=h1
  · k=4 → 16 hosts (h0..h15)             attacker=h0, victim=h15
  · k=6 → 54 hosts                       attacker=h0, victim=h53

Initial value is taken from PAD_K env var (default 4). Backend exposes
POST /api/topology/k to switch live without restarting the server.
"""

from __future__ import annotations

import copy
import os
import threading

DEFAULT_ATTACK_ID = "S3"

# ─────────────────────────────────────────────────────────────────────────────
# Module state (mutable via set_k)
# ─────────────────────────────────────────────────────────────────────────────
_lock = threading.RLock()
PAD_K: int = 4                    # runtime-resolved below
N_HOSTS: int = 16
SCENARIOS: list[dict] = []


# Raw catalog — `attacker`, `victim`, `rate_pps_target` get rewritten per-k
_RAW_SCENARIOS: list[dict] = [
    {
        "id": "S1",
        "name": "Baseline benign",
        "description": "Pure benign iperf3 UDP. Pipeline must NOT misclassify as attack.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "BENIGN",
        "tool": "iperf3",
        "attack_cmd": "iperf3 -c 10.3.1.4 -u -b 50M -t %D",
        "expected_tier": 0,
        "tier_label": "T0",
        "expected_mitigation": "none — verify false-positive rate",
        "rate_pps_target_k4": 4000,
        "duration_s": 30,
        "color": "#059669",
        "profile": {
            "attack_type": "Benign UDP (sanity)",
            "intensity": "Low",
            "target_service": "Demo Web Service",
            "duration_min": 0.5,
        },
    },
    {
        "id": "S2",
        "name": "SYN flood — low rate",
        "description": "5 kpps SYN to victim:80. Ratelimit should engage at edge.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "SYN",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 -i u200 10.3.1.4",
        "expected_tier": 2,
        "tier_label": "T2",
        "expected_mitigation": "T2 → Ryu ratelimit + SO instantiate ratelimiter VNF",
        "rate_pps_target_k4": 5000,
        "duration_s": 30,
        "color": "#F97316",
        "profile": {
            "attack_type": "SYN Flood (low)",
            "intensity": "Medium",
            "target_service": "Demo Web Service",
            "duration_min": 0.5,
        },
    },
    {
        "id": "S3",
        "name": "Volumetric UDP Flood",
        "description": "High-rate UDP flood with spoofed sources. Scrubber must engage.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "UDP_FLOOD",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood --udp -p 80 --rand-source 10.3.1.4",
        "expected_tier": 3,
        "tier_label": "T3",
        "expected_mitigation": "T3 → Ryu redirect to scrubber + SO instantiate scrubber VNF",
        "rate_pps_target_k4": 50000,
        "duration_s": 30,
        "color": "#DC2626",
        "profile": {
            "attack_type": "Volumetric UDP Flood",
            "intensity": "High",
            "target_service": "Demo Web Service",
            "duration_min": 5,
        },
    },
    {
        "id": "S4",
        "name": "DNS Amplification",
        "description": "Reflected DNS (port 53) amplification, spoofed source.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "DNS_AMP",
        "tool": "hping3",
        "attack_cmd": "hping3 --udp -p 53 --flood --rand-source 10.3.1.4",
        "expected_tier": 3,
        "tier_label": "T3",
        "expected_mitigation": "T3 → scrubber drops by UDP/53 signature",
        "rate_pps_target_k4": 30000,
        "duration_s": 30,
        "color": "#DC2626",
        "profile": {
            "attack_type": "Reflected DNS Amplification",
            "intensity": "High",
            "target_service": "Demo Web Service",
            "duration_min": 2,
        },
    },
    {
        "id": "S5",
        "name": "Multi-vector",
        "description": "SYN + UDP + ICMP from 3 attackers concurrently.",
        "attacker_kind": "multi", "victim_kind": "last_host",
        "attack_type": "MULTI",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 10.3.1.4",
        "expected_tier": 4,
        "tier_label": "T4",
        "expected_mitigation": "T4 → strict filtering + blackhole",
        "rate_pps_target_k4": 80000,
        "duration_s": 30,
        "color": "#DC2626",
        "profile": {
            "attack_type": "Multi-vector (SYN+UDP+ICMP)",
            "intensity": "Critical",
            "target_service": "Demo Web Service",
            "duration_min": 2,
        },
    },
    {
        "id": "S6",
        "name": "Carpet bombing",
        "description": "Random destination /24 sweep — many victims, low per-flow rate.",
        "attacker_kind": "single", "victim_kind": "last_pod_cidr",
        "attack_type": "CARPET",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 --rand-dest 10.3.0.0/16",
        "expected_tier": 4,
        "tier_label": "T4",
        "expected_mitigation": "T4 → Ryu /24 aggregate drop rule",
        "rate_pps_target_k4": 60000,
        "duration_s": 30,
        "color": "#DC2626",
        "profile": {
            "attack_type": "Carpet Bombing /16",
            "intensity": "Critical",
            "target_service": "Demo Web Service (subnet)",
            "duration_min": 3,
        },
    },
    {
        "id": "S7",
        "name": "Slow-rate",
        "description": "1 packet / ms — Transformer/LSTM time-series branch.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "SLOW_RATE",
        "tool": "hping3",
        "attack_cmd": "hping3 -S -p 80 -i u1000 10.3.1.4",
        "expected_tier": 1,
        "tier_label": "T1",
        "expected_mitigation": "T1 → monitor only, watchlist after conf > 0.6",
        "rate_pps_target_k4": 1000,
        "duration_s": 60,
        "color": "#06B6D4",
        "profile": {
            "attack_type": "Slow-rate (Slowloris-style)",
            "intensity": "Low",
            "target_service": "Demo Web Service",
            "duration_min": 1,
        },
    },
    {
        "id": "S8",
        "name": "Burst on/off",
        "description": "10s flood / 10s silence — tests tier oscillation.",
        "attacker_kind": "single", "victim_kind": "last_host",
        "attack_type": "BURST",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 10.3.1.4",
        "expected_tier": 2,
        "tier_label": "T2",
        "expected_mitigation": "T2 cycles ↔ T0; rule idle_timeout 30s for stability",
        "rate_pps_target_k4": 20000,
        "duration_s": 60,
        "color": "#F97316",
        "profile": {
            "attack_type": "Burst on/off",
            "intensity": "Medium",
            "target_service": "Demo Web Service",
            "duration_min": 1,
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Resolution helpers
# ─────────────────────────────────────────────────────────────────────────────
def _build_for_k(k: int) -> tuple[list[dict], int]:
    """Materialise a fresh SCENARIOS list with attacker/victim/rate set per k."""
    if k < 2 or k % 2 != 0:
        raise ValueError(f"PAD_K must be an even integer ≥ 2 (got {k})")
    n_hosts = k * (k // 2) * (k // 2)

    def host(i: int) -> str:
        return f"h{min(i, n_hosts - 1)}"

    h_attacker = host(0)
    h_victim   = host(n_hosts - 1)
    h_attackers_multi = ",".join(host(i) for i in [0, k, 2 * k])

    # Rate scale: k=4 → 1.0,  k=2 → 0.4,  k=6 → ~1.6,  k=8 → ~2.3
    scale = max(0.2, (n_hosts / 16))

    out: list[dict] = []
    for raw in _RAW_SCENARIOS:
        s = copy.deepcopy(raw)
        s["attacker"] = (h_attackers_multi if s["attacker_kind"] == "multi"
                                            and n_hosts >= 9
                         else h_attacker)
        s["victim"] = (f"pod{k - 1}-cidr"
                       if s["victim_kind"] == "last_pod_cidr" else h_victim)
        s["rate_pps_target"] = int(s["rate_pps_target_k4"] * scale)
        # Strip internal fields from public API
        s.pop("attacker_kind", None)
        s.pop("victim_kind", None)
        s.pop("rate_pps_target_k4", None)
        out.append(s)
    return out, n_hosts


# ─────────────────────────────────────────────────────────────────────────────
# Public API — re-bindable
# ─────────────────────────────────────────────────────────────────────────────
def set_k(k: int) -> dict:
    """Switch the topology size at runtime. Mutates PAD_K, N_HOSTS, SCENARIOS."""
    global PAD_K, N_HOSTS, SCENARIOS
    with _lock:
        sc, nh = _build_for_k(k)
        PAD_K = k
        N_HOSTS = nh
        SCENARIOS.clear()
        SCENARIOS.extend(sc)
    return topology_info()


def by_id(scenario_id: str) -> dict | None:
    with _lock:
        for s in SCENARIOS:
            if s["id"] == scenario_id:
                return s
    return None


def topology_info() -> dict:
    with _lock:
        return {
            "k": PAD_K,
            "n_core":  (PAD_K // 2) ** 2,
            "n_agg":   PAD_K * (PAD_K // 2),
            "n_edge":  PAD_K * (PAD_K // 2),
            "n_hosts": N_HOSTS,
            "attacker_default": f"h0",
            "victim_default":   f"h{N_HOSTS - 1}",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap from PAD_K env (one-shot at import)
# ─────────────────────────────────────────────────────────────────────────────
set_k(int(os.environ.get("PAD_K", "4")))

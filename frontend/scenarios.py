"""
Scenario catalog — rich metadata for the frontend picker and runner.

Each scenario carries an attack_profile that maps directly to the UI's
"Scenario Profile" panel in systemdesign.md §6.3.
"""

from __future__ import annotations

# Default attack scenario for the "Start Attack" button in the left panel
DEFAULT_ATTACK_ID = "S3"

SCENARIOS: list[dict] = [
    {
        "id": "S1",
        "name": "Baseline benign",
        "description": "Pure benign iperf3 UDP. Pipeline must NOT misclassify as attack.",
        "attacker": "h0", "victim": "h15", "attack_type": "BENIGN",
        "tool": "iperf3",
        "attack_cmd": "iperf3 -c 10.3.1.4 -u -b 50M -t %D",
        "expected_tier": 0,
        "tier_label": "T0",
        "expected_mitigation": "none — verify false-positive rate",
        "rate_pps_target": 4000,
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
        "attacker": "h0", "victim": "h15", "attack_type": "SYN",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 -i u200 10.3.1.4",
        "expected_tier": 2,
        "tier_label": "T2",
        "expected_mitigation": "T2 → Ryu ratelimit + SO instantiate ratelimiter VNF",
        "rate_pps_target": 5000,
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
        "attacker": "h0", "victim": "h15", "attack_type": "UDP_FLOOD",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood --udp -p 80 --rand-source 10.3.1.4",
        "expected_tier": 3,
        "tier_label": "T3",
        "expected_mitigation": "T3 → Ryu redirect to scrubber + SO instantiate scrubber VNF",
        "rate_pps_target": 50000,
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
        "attacker": "h0", "victim": "h15", "attack_type": "DNS_AMP",
        "tool": "hping3",
        "attack_cmd": "hping3 --udp -p 53 --flood --rand-source 10.3.1.4",
        "expected_tier": 3,
        "tier_label": "T3",
        "expected_mitigation": "T3 → scrubber drops by UDP/53 signature",
        "rate_pps_target": 30000,
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
        "attacker": "h0,h4,h8", "victim": "h15", "attack_type": "MULTI",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 10.3.1.4",
        "expected_tier": 4,
        "tier_label": "T4",
        "expected_mitigation": "T4 → strict filtering + blackhole",
        "rate_pps_target": 80000,
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
        "attacker": "h0", "victim": "pod3-cidr", "attack_type": "CARPET",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 --rand-dest 10.3.0.0/16",
        "expected_tier": 4,
        "tier_label": "T4",
        "expected_mitigation": "T4 → Ryu /24 aggregate drop rule",
        "rate_pps_target": 60000,
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
        "attacker": "h0", "victim": "h15", "attack_type": "SLOW_RATE",
        "tool": "hping3",
        "attack_cmd": "hping3 -S -p 80 -i u1000 10.3.1.4",
        "expected_tier": 1,
        "tier_label": "T1",
        "expected_mitigation": "T1 → monitor only, watchlist after conf > 0.6",
        "rate_pps_target": 1000,
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
        "attacker": "h0", "victim": "h15", "attack_type": "BURST",
        "tool": "hping3",
        "attack_cmd": "hping3 --flood -S -p 80 10.3.1.4",
        "expected_tier": 2,
        "tier_label": "T2",
        "expected_mitigation": "T2 cycles ↔ T0; rule idle_timeout 30s for stability",
        "rate_pps_target": 20000,
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


def by_id(scenario_id: str) -> dict | None:
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None

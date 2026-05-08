"""
Evaluation Scenarios — Spec §7.2 (PAD-ONAP v3, 5 scenarios)
===========================================================

Replaces evaluation/scenarios.py for spec-aligned runs.  Each scenario emits a
sequence of `(track_a_features_22, track_b_features_6, attack_label)` tuples
that drive the orchestrator end-to-end.

Mapping to Spec §7.2:

  S1 — DrDoS suite (per-class, run separately)
        Attack types: DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS,
                      DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP
        Goal: Track A per-class coverage, all reflection labels

  S2 — Exploitation classes A/B  (Syn flood + UDP-lag, run separately)
        Goal: AI disabled vs AI enabled comparison

  S3 — Application-layer (WebDDoS HTTP flood)
        Goal: Track A application-layer detection

  S4 — Volumetric ramp A/B (slow ramp 100 Mbps → 10 Gbps over 20 min)
        Goal: Track B forecast-driven Tier 2 pre-positioning,
              AI vs no-AI comparison

  S5 — Multi-tenant SLA isolation
        3 tenants, one under attack; verify Gold/Silver/Bronze SLA preservation

Each scenario has both `enabled` (M2 Track A + Track B drive policy) and
`disabled` (static threshold rules: pkt_rate > X or syn_count > Y → Tier 3)
helpers so A/B testing is one switch.
"""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.s3_ai.inference_layer import (
    TRACK_A_FEATURES, TRACK_B_FEATURES,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic feature generators (Track A 22-dim + Track B 6-dim)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WindowSample:
    timestamp_s:        float
    track_a:            np.ndarray            # shape (22,)
    track_b:            Optional[np.ndarray]  # shape (6,) when minute-aligned
    attack_label_id:    int                   # 0..11 (CICDDoS taxonomy)
    attack_label_name:  str
    is_attack:          bool


def _zero_track_a() -> np.ndarray:
    return np.zeros(len(TRACK_A_FEATURES), dtype=np.float32)


def _zero_track_b() -> np.ndarray:
    return np.zeros(len(TRACK_B_FEATURES), dtype=np.float32)


def _benign_track_a(rng) -> np.ndarray:
    """One 5-second flow window of normal traffic."""
    a = _zero_track_a()
    a[TRACK_A_FEATURES.index('flow_duration')]            = 5.0
    a[TRACK_A_FEATURES.index('total_fwd_packets')]        = rng.uniform(50,  200)
    a[TRACK_A_FEATURES.index('total_bwd_packets')]        = rng.uniform(40,  180)
    a[TRACK_A_FEATURES.index('total_length_fwd_packets')] = rng.uniform(10_000, 80_000)
    a[TRACK_A_FEATURES.index('total_length_bwd_packets')] = rng.uniform(8_000,  60_000)
    a[TRACK_A_FEATURES.index('fwd_packet_length_mean')]   = rng.uniform(400, 1200)
    a[TRACK_A_FEATURES.index('bwd_packet_length_mean')]   = rng.uniform(300, 1100)
    a[TRACK_A_FEATURES.index('fwd_packet_length_max')]    = rng.uniform(1000, 1500)
    a[TRACK_A_FEATURES.index('flow_bytes_per_sec')]       = a[3] / 5.0
    a[TRACK_A_FEATURES.index('flow_packets_per_sec')]     = (a[1] + a[2]) / 5.0
    a[TRACK_A_FEATURES.index('flow_iat_mean')]            = rng.uniform(20, 80)
    a[TRACK_A_FEATURES.index('flow_iat_std')]             = rng.uniform(5, 25)
    a[TRACK_A_FEATURES.index('protocol')]                 = 6.0    # TCP
    a[TRACK_A_FEATURES.index('syn_flag_count')]           = rng.uniform(0, 3)
    a[TRACK_A_FEATURES.index('ack_flag_count')]           = rng.uniform(50, 180)
    a[TRACK_A_FEATURES.index('init_win_bytes_fwd')]       = 65535
    a[TRACK_A_FEATURES.index('init_win_bytes_bwd')]       = 65535
    a[TRACK_A_FEATURES.index('min_seg_size_fwd')]         = 32
    return a


def _attack_track_a(rng, attack_name: str, intensity: float = 1.0) -> np.ndarray:
    """Synthetic Track A flow window for a given CICDDoS attack class."""
    a = _benign_track_a(rng)

    if attack_name == 'Syn':
        a[TRACK_A_FEATURES.index('protocol')]              = 6
        a[TRACK_A_FEATURES.index('total_fwd_packets')]     = rng.uniform(20_000, 80_000) * intensity
        a[TRACK_A_FEATURES.index('total_bwd_packets')]     = rng.uniform(0, 50)   # one-way SYN
        a[TRACK_A_FEATURES.index('syn_flag_count')]        = rng.uniform(20_000, 80_000) * intensity
        a[TRACK_A_FEATURES.index('ack_flag_count')]        = rng.uniform(0, 100)
        a[TRACK_A_FEATURES.index('fwd_packet_length_mean')] = 60
        a[TRACK_A_FEATURES.index('bwd_packet_length_mean')] = 0
        a[TRACK_A_FEATURES.index('flow_iat_mean')]         = 0.05
    elif attack_name == 'UDP-lag':
        a[TRACK_A_FEATURES.index('protocol')]              = 17
        a[TRACK_A_FEATURES.index('total_fwd_packets')]     = rng.uniform(10_000, 30_000) * intensity
        a[TRACK_A_FEATURES.index('flow_iat_mean')]         = rng.uniform(50, 150)
        a[TRACK_A_FEATURES.index('flow_iat_std')]          = rng.uniform(80, 200)
    elif attack_name == 'WebDDoS':
        a[TRACK_A_FEATURES.index('protocol')]              = 6
        a[TRACK_A_FEATURES.index('total_fwd_packets')]     = rng.uniform(2_000, 8_000) * intensity
        a[TRACK_A_FEATURES.index('total_bwd_packets')]     = rng.uniform(2_000, 8_000) * intensity
        a[TRACK_A_FEATURES.index('fwd_psh_flags')]         = rng.uniform(2_000, 8_000) * intensity
        a[TRACK_A_FEATURES.index('fwd_packet_length_mean')] = rng.uniform(200, 800)
    elif attack_name.startswith('DrDoS_'):
        # Reflection attacks: amplified UDP responses, large packets
        a[TRACK_A_FEATURES.index('protocol')]                = 17
        a[TRACK_A_FEATURES.index('total_bwd_packets')]       = rng.uniform(40_000, 200_000) * intensity
        a[TRACK_A_FEATURES.index('total_length_bwd_packets')] = rng.uniform(5e7, 2e8) * intensity
        a[TRACK_A_FEATURES.index('bwd_packet_length_mean')]  = rng.uniform(900, 1450)
        a[TRACK_A_FEATURES.index('fwd_packet_length_mean')]  = rng.uniform(60, 200)
        a[TRACK_A_FEATURES.index('flow_iat_mean')]           = rng.uniform(0.05, 0.3)

    # Recompute derived rates
    total_pkts  = a[TRACK_A_FEATURES.index('total_fwd_packets')] + a[TRACK_A_FEATURES.index('total_bwd_packets')]
    total_bytes = (a[TRACK_A_FEATURES.index('total_length_fwd_packets')]
                 + a[TRACK_A_FEATURES.index('total_length_bwd_packets')])
    a[TRACK_A_FEATURES.index('flow_packets_per_sec')] = total_pkts / 5.0
    a[TRACK_A_FEATURES.index('flow_bytes_per_sec')]   = total_bytes / 5.0
    return a


def _track_b_from_minute(samples_in_minute: list[np.ndarray]) -> np.ndarray:
    """Aggregate the last minute of Track A windows into 6-dim Track B."""
    if not samples_in_minute:
        return _zero_track_b()
    pkts = sum(
        s[TRACK_A_FEATURES.index('total_fwd_packets')] +
        s[TRACK_A_FEATURES.index('total_bwd_packets')]
        for s in samples_in_minute
    )
    byts = sum(
        s[TRACK_A_FEATURES.index('total_length_fwd_packets')] +
        s[TRACK_A_FEATURES.index('total_length_bwd_packets')]
        for s in samples_in_minute
    )
    syn = sum(s[TRACK_A_FEATURES.index('syn_flag_count')] for s in samples_in_minute)
    aps = float(np.mean(
        [s[TRACK_A_FEATURES.index('fwd_packet_length_mean')] for s in samples_in_minute]
    ))
    # Rough cardinality proxies (real numbers come from gNMI in production)
    src_card = max(1.0, syn / 50.0)
    dst_card = max(1.0, pkts / 500.0)
    return np.array([
        float(pkts), float(byts),
        float(src_card), float(dst_card),
        float(aps), float(syn),
    ], dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario builders
# ─────────────────────────────────────────────────────────────────────────────

CICDDOS_NAME_TO_ID = {
    'BENIGN': 0,
    'DrDoS_DNS': 1, 'DrDoS_LDAP': 2, 'DrDoS_MSSQL': 3, 'DrDoS_NetBIOS': 4,
    'DrDoS_NTP': 5, 'DrDoS_SNMP': 6, 'DrDoS_SSDP': 7, 'DrDoS_UDP': 8,
    'Syn': 9, 'UDP-lag': 10, 'WebDDoS': 11,
}


def scenario_s1_drdos(
    attack_class: str,
    duration_s: int = 300,
    benign_lead_s: int = 60,
    intensity_gbps: float = 1.0,
    seed: int = 0,
) -> Iterable[WindowSample]:
    """
    Spec §7.2 S1 — single DrDoS class, 5 minutes, 1 Gbps.
    `attack_class` ∈ DrDoS_DNS, DrDoS_LDAP, ..., DrDoS_UDP
    """
    if not attack_class.startswith('DrDoS_'):
        raise ValueError(f'S1 expects a DrDoS_* class, got {attack_class}')
    yield from _scenario_block(
        attack_name=attack_class, duration_s=duration_s,
        benign_lead_s=benign_lead_s, intensity=intensity_gbps, seed=seed,
    )


def scenario_s2_exploitation(
    attack_class: str = 'Syn',
    duration_s: int = 300,
    benign_lead_s: int = 60,
    seed: int = 0,
) -> Iterable[WindowSample]:
    """Spec §7.2 S2 — Syn flood (500k pps) or UDP-lag (200k pps)."""
    if attack_class not in ('Syn', 'UDP-lag'):
        raise ValueError(f'S2 attack_class must be Syn or UDP-lag, got {attack_class}')
    intensity = 1.0  # built into _attack_track_a
    yield from _scenario_block(
        attack_name=attack_class, duration_s=duration_s,
        benign_lead_s=benign_lead_s, intensity=intensity, seed=seed,
    )


def scenario_s3_webddos(
    duration_s: int = 300, benign_lead_s: int = 60, seed: int = 0,
) -> Iterable[WindowSample]:
    """Spec §7.2 S3 — HTTP flood (100 k rps), 5 minutes."""
    yield from _scenario_block(
        attack_name='WebDDoS', duration_s=duration_s,
        benign_lead_s=benign_lead_s, intensity=1.0, seed=seed,
    )


def scenario_s4_volumetric_ramp(
    duration_s: int = 40 * 60,        # 40 min total
    ramp_start_s: int = 10 * 60,      # benign for 10 min
    ramp_end_s:   int = 30 * 60,      # ramp 100 Mbps → 10 Gbps over 20 min
    attack_class: str = 'DrDoS_UDP',
    seed: int = 0,
) -> Iterable[WindowSample]:
    """
    Spec §7.2 S4 — slow ramp from 100 Mbps to 10 Gbps over 20 minutes.
    Drives Track B forecast-triggered Tier 2 pre-positioning.
    """
    rng = np.random.default_rng(seed)
    minute_buf: list[np.ndarray] = []
    last_minute_t = 0.0
    for t in range(0, duration_s, 5):              # 5-second windows
        if t < ramp_start_s:
            sample = _benign_track_a(rng)
            label, label_id = 'BENIGN', 0
        elif t > ramp_end_s:
            sample = _attack_track_a(rng, attack_class, intensity=10.0)
            label, label_id = attack_class, CICDDOS_NAME_TO_ID[attack_class]
        else:
            frac = (t - ramp_start_s) / max(1, ramp_end_s - ramp_start_s)
            scale = 0.1 + frac * 9.9                # 0.1× → 10× (100 Mbps → 10 Gbps)
            sample = _attack_track_a(rng, attack_class, intensity=scale)
            label, label_id = attack_class, CICDDOS_NAME_TO_ID[attack_class]
        minute_buf.append(sample)
        track_b = None
        if t - last_minute_t >= 60:
            track_b = _track_b_from_minute(minute_buf[-12:])
            last_minute_t = t
        yield WindowSample(
            timestamp_s       = float(t),
            track_a           = sample,
            track_b           = track_b,
            attack_label_id   = label_id,
            attack_label_name = label,
            is_attack         = (label != 'BENIGN'),
        )


def scenario_s5_multitenant(
    duration_s: int = 300, benign_lead_s: int = 60,
    attacked_tenant: str = 'slice-IoT', attack_class: str = 'DrDoS_UDP',
    seed: int = 0,
) -> Iterable[tuple[str, WindowSample]]:
    """
    Spec §7.2 S5 — 3 tenants, one under attack.  Yields `(tenant_id, sample)`
    pairs so the caller can drive a per-tenant SLAAllocator.allocate() loop.
    """
    rng = np.random.default_rng(seed)
    tenants = ['slice-finance', 'slice-eMBB', attacked_tenant]
    for sample in _scenario_block(
        attack_name=attack_class, duration_s=duration_s,
        benign_lead_s=benign_lead_s, intensity=1.0, seed=seed,
    ):
        # Only the attacked tenant gets the attack feature vector; others
        # see benign traffic in parallel.
        for tenant in tenants:
            if tenant == attacked_tenant:
                yield tenant, sample
            else:
                yield tenant, WindowSample(
                    timestamp_s       = sample.timestamp_s,
                    track_a           = _benign_track_a(rng),
                    track_b           = sample.track_b,
                    attack_label_id   = 0,
                    attack_label_name = 'BENIGN',
                    is_attack         = False,
                )


def _scenario_block(
    *, attack_name: str, duration_s: int, benign_lead_s: int,
    intensity: float, seed: int,
) -> Iterable[WindowSample]:
    """Shared backbone for S1/S2/S3 — benign lead-in, then attack."""
    rng           = np.random.default_rng(seed)
    minute_buf    = []
    last_minute_t = 0.0
    label_id      = CICDDOS_NAME_TO_ID[attack_name]
    for t in range(0, duration_s, 5):
        if t < benign_lead_s:
            sample = _benign_track_a(rng)
            label, lbl_id, is_atk = 'BENIGN', 0, False
        else:
            sample = _attack_track_a(rng, attack_name, intensity=intensity)
            label, lbl_id, is_atk = attack_name, label_id, True
        minute_buf.append(sample)
        track_b = None
        if t - last_minute_t >= 60:
            track_b = _track_b_from_minute(minute_buf[-12:])
            last_minute_t = t
        yield WindowSample(
            timestamp_s       = float(t),
            track_a           = sample,
            track_b           = track_b,
            attack_label_id   = lbl_id,
            attack_label_name = label,
            is_attack         = is_atk,
        )


# ─────────────────────────────────────────────────────────────────────────────
# AI-disabled baseline — static threshold rules (Spec §7.2 A/B definition)
# ─────────────────────────────────────────────────────────────────────────────

def static_threshold_tier(track_a: np.ndarray) -> int:
    """
    AI-disabled baseline policy: simple thresholds on packet rate / SYN rate.
      Tier 3 if pkt_rate > 50_000 OR syn_rate > 30_000
      Tier 2 if pkt_rate > 10_000 OR syn_rate >  5_000
      Tier 1 if pkt_rate >  2_000
      Tier 0 otherwise
    """
    pps = float(track_a[TRACK_A_FEATURES.index('flow_packets_per_sec')])
    syn = float(track_a[TRACK_A_FEATURES.index('syn_flag_count')]) / 5.0
    if pps > 50_000 or syn > 30_000:
        return 3
    if pps > 10_000 or syn >  5_000:
        return 2
    if pps >  2_000:
        return 1
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Catalog
# ─────────────────────────────────────────────────────────────────────────────

SCENARIO_CATALOG = {
    'S1_DrDoS_DNS':     ('S1', lambda: scenario_s1_drdos('DrDoS_DNS')),
    'S1_DrDoS_LDAP':    ('S1', lambda: scenario_s1_drdos('DrDoS_LDAP')),
    'S1_DrDoS_MSSQL':   ('S1', lambda: scenario_s1_drdos('DrDoS_MSSQL')),
    'S1_DrDoS_NetBIOS': ('S1', lambda: scenario_s1_drdos('DrDoS_NetBIOS')),
    'S1_DrDoS_NTP':     ('S1', lambda: scenario_s1_drdos('DrDoS_NTP')),
    'S1_DrDoS_SNMP':    ('S1', lambda: scenario_s1_drdos('DrDoS_SNMP')),
    'S1_DrDoS_SSDP':    ('S1', lambda: scenario_s1_drdos('DrDoS_SSDP')),
    'S1_DrDoS_UDP':     ('S1', lambda: scenario_s1_drdos('DrDoS_UDP')),
    'S2_Syn':           ('S2', lambda: scenario_s2_exploitation('Syn')),
    'S2_UDP-lag':       ('S2', lambda: scenario_s2_exploitation('UDP-lag')),
    'S3_WebDDoS':       ('S3', scenario_s3_webddos),
    'S4_Volumetric':    ('S4', scenario_s4_volumetric_ramp),
    'S5_MultiTenant':   ('S5', scenario_s5_multitenant),
}


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    for name, (tag, fn) in SCENARIO_CATALOG.items():
        n = sum(1 for _ in fn())
        logger.info(f'  {name:<22} {tag}  windows={n}')

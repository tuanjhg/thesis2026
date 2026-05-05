"""
run_baseline_real.py — ONAP rule-based baseline on REAL ONAP (no AI)
======================================================================
Mirror of run_s2_real.py with one substitution: the detector is
``threshold_decide()`` from ``evaluation/baseline_threshold.py`` — the
legacy ONAP-style rule-set (pkt_rate>10k → T3, udp_frac>0.85 → T3,
syn_ratio>0.60 → T3, etc.). NO ML, NO forecast. Same downstream stack
(CLAMPReal / SOReal / OVSSFCReal) so latency and tier outputs are
directly comparable to s2_real_onap.json.

Feature stream is consumed from the SAME NetFlow collector endpoint
that LiveInferenceRunner uses (default ``http://localhost:7070``).
This guarantees apples-to-apples comparison: identical traffic feed,
identical 17-feature representation, identical ONAP downstream — only
the detector differs.

Output: evaluation/results/s2_baseline_real_onap.json

Usage:
    export PAD_ONAP_STUB=false
    # In another terminal: start collector
    python testbed/netflow_collector/collector.py --mode synthetic \\
        --gnmi http://localhost:8888 --api-port 7070
    # Run baseline
    python onap/scripts/run_baseline_real.py \\
        --attack-mode gnmi --gnmi-url http://localhost:8888 \\
        --bridge br-pad --src-ip 10.0.0.1 --vnf-port 9001
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from onap.scripts.onap_e2e_lib import (
    CLAMPReal, E2ERecord, ONAPSOReal, OVSSFCReal,
    publish_to_dmaap, wait_vnf_active,
)
from pipeline.s3_ai.live_pipeline import fetch_latest, features_dict_to_array
from evaluation.baseline_threshold import threshold_decide
from pipeline.s4_orchestration.tier_mapper import Tier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("baseline_real")

SCENARIO       = "S2_baseline_rule_based"
DEVICE_ID      = "r1"
VNF_PROFILE    = "vnfd-scrubber-v1"
NORMAL_DUR_S   = 30
ATTACK_DUR_S   = 60
COOLDOWN_S     = 15
DETECT_TIMEOUT_S = 90    # threshold may need sustain — give it more time than AI


# ─────────────────────────────────────────────────────────────────────────────
# Threshold rule poller
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RuleEvent:
    t:             float
    tier:          int
    reason:        str
    pkt_rate:      float
    syn_ratio:     float
    udp_frac:      float
    src_entropy:   float
    raw_features:  dict = field(default_factory=dict)


class ThresholdPoller:
    """
    Polls the same /flows/latest endpoint LiveInferenceRunner uses, then
    runs threshold_decide() per window. Requires `sustain_windows`
    consecutive trips at >= min_alert_tier before firing — emulates
    DCAE-TCAGen2 / Holmes correlation behaviour.
    """

    def __init__(
        self,
        collector_url:   str  = "http://localhost:7070",
        interval_s:      float = 5.0,
        sustain_windows: int  = 3,
        min_alert_tier:  int  = int(Tier.MITIGATE),  # T3
    ):
        self.collector_url   = collector_url.rstrip("/")
        self.interval_s      = interval_s
        self.sustain_windows = sustain_windows
        self.min_alert_tier  = min_alert_tier
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock    = threading.Lock()
        self._latest: Optional[RuleEvent] = None
        self._history: List[RuleEvent]    = []

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="threshold-poller")
        self._thread.start()
        logger.info(f"Threshold poller started — {self.collector_url} every "
                    f"{self.interval_s}s, sustain={self.sustain_windows}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    @property
    def latest(self) -> Optional[RuleEvent]:
        with self._lock:
            return self._latest

    def wait_for_tier(self, min_tier: int, timeout_s: float,
                      after: Optional[float] = None) -> Optional[RuleEvent]:
        """Block until `sustain_windows` consecutive events ≥ min_tier seen
        after `after` wall-clock (defaults to now)."""
        deadline = time.time() + timeout_s
        if after is None:
            after = time.time()
        consecutive = 0
        last_seen_t = -1.0
        while time.time() < deadline:
            ev = self.latest
            if ev is not None and ev.t > after and ev.t > last_seen_t:
                last_seen_t = ev.t
                if ev.tier >= min_tier:
                    consecutive += 1
                    if consecutive >= self.sustain_windows:
                        return ev
                else:
                    consecutive = 0
            time.sleep(0.2)
        return None

    def _loop(self) -> None:
        last_ts = None
        misses  = 0
        while not self._stop.is_set():
            t0 = time.time()
            try:
                raw = fetch_latest(self.collector_url)
            except Exception as e:
                logger.warning(f"collector fetch error: {e}")
                raw = None
            if raw is None:
                misses += 1
                if misses == 5:
                    logger.warning(f"collector at {self.collector_url} not responding")
            else:
                misses = 0
                ts    = raw.get("timestamp")
                feats = raw.get("features", {})
                if ts != last_ts and feats:
                    last_ts = ts
                    try:
                        x  = features_dict_to_array(feats)
                        td = threshold_decide(x)
                        ev = RuleEvent(
                            t=time.time(), tier=int(td.tier),
                            reason=td.reason,
                            pkt_rate    = float(feats.get("pkt_rate", 0)),
                            syn_ratio   = float(feats.get("syn_ratio", 0)),
                            udp_frac    = float(feats.get("proto_dist_udp", 0)),
                            src_entropy = float(feats.get("src_ip_entropy", 0)),
                            raw_features= feats,
                        )
                        with self._lock:
                            self._latest = ev
                            self._history.append(ev)
                        marker = "★" if ev.tier >= self.min_alert_tier else " "
                        logger.info(
                            f"[rule] T{ev.tier} {marker} pkt_rate={ev.pkt_rate:.0f} "
                            f"udp={ev.udp_frac:.2f} syn={ev.syn_ratio:.2f} "
                            f"ent={ev.src_entropy:.2f} | {ev.reason}"
                        )
                    except Exception as e:
                        logger.exception(f"rule eval error: {e}")
            elapsed = time.time() - t0
            time.sleep(max(0.0, self.interval_s - elapsed))


# ─────────────────────────────────────────────────────────────────────────────
# Attack injection helpers (copied from run_s2_real.py for self-containment)
# ─────────────────────────────────────────────────────────────────────────────
def _start_gnmi_flood(gnmi_url: str):
    import urllib.request, json as _j
    req = urllib.request.Request(
        f"{gnmi_url}/attack/start",
        data=_j.dumps({"type": "udp_flood", "target": DEVICE_ID}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        logger.info(f"[gNMI] UDP flood started on {DEVICE_ID}")
    except Exception as e:
        logger.error(f"[gNMI] start flood failed: {e}")


def _stop_gnmi_flood(gnmi_url: str):
    import urllib.request, json as _j
    req = urllib.request.Request(
        f"{gnmi_url}/attack/stop", data=_j.dumps({}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5); logger.info("[gNMI] attack stopped")
    except Exception as e:
        logger.error(f"[gNMI] stop failed: {e}")


def _start_mininet_flood(bridge: str, src_ip: str):
    import subprocess
    ssh = os.environ.get("OVS_SSH_HOST")
    cmd = f"hping3 --udp --flood -p 80 {src_ip}"
    if ssh:
        cmd = f"ssh ubuntu@{ssh} 'sudo hping3 --udp --flood -p 80 {src_ip} &'"
    logger.info(f"[Mininet] starting flood: {cmd}")
    subprocess.Popen(cmd, shell=True)


def _stop_mininet_flood():
    import subprocess
    ssh = os.environ.get("OVS_SSH_HOST")
    cmd = "sudo pkill hping3"
    if ssh:
        cmd = f"ssh ubuntu@{ssh} 'sudo pkill hping3'"
    subprocess.run(cmd, shell=True)
    logger.info("[Mininet] hping3 stopped")


def _publish_rule_payload(ev: RuleEvent, tier: int) -> dict:
    """DMaaP payload mirroring AIOutputPayload schema for downstream parity."""
    import datetime, uuid
    return {
        "event_id":      uuid.uuid4().hex[:12],
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "schema_version": "2.0",
        "detector":      "rule_based",
        "detection": {
            "attack_type":  "RuleBased",
            "confidence":   0.0,
            "reason":       ev.reason,
            "tier":         tier,
        },
        "forecast":          {"p_attack_30s": 0.0, "proactive_trigger": False},
        "proactive_trigger": {"triggered": False, "tier": 0},
        "suggested_tier":    tier,
        "device_id":         DEVICE_ID,
        "raw_features":      ev.raw_features,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main scenario
# ─────────────────────────────────────────────────────────────────────────────
def run_baseline(
    attack_mode:     str  = "gnmi",
    gnmi_url:        str  = "http://localhost:8080",
    bridge:          str  = "r1",
    src_ip:          str  = "10.1.0.1",
    vnf_port:        int  = 4,
    dry_run:         bool = False,
    cleanup:         bool = True,
    collector_url:   str  = "http://localhost:7070",
    sustain_windows: int  = 3,
    detect_timeout_s: float = DETECT_TIMEOUT_S,
) -> E2ERecord:

    rec = E2ERecord(scenario=SCENARIO, vnf_profile=VNF_PROFILE,
                    detector="rule_based")
    so    = ONAPSOReal()
    clamp = CLAMPReal()
    sfc   = OVSSFCReal()
    poller: Optional[ThresholdPoller] = None

    sep = "═" * 62
    print(f"\n{sep}")
    print(f"  PAD-ONAP E2E — {SCENARIO} (NO AI; rule-based detector)")
    print(f"  Mode: {'DRY-RUN' if dry_run else 'REAL ONAP (PAD_ONAP_STUB=false)'}")
    print(f"  Attack: {attack_mode.upper()} │ Bridge: {bridge} │ VNF port: {vnf_port}")
    print(f"  Sustain windows (Holmes-style): {sustain_windows}")
    print(f"{sep}\n")

    # ── 1. Preflight ──────────────────────────────────────────────────────────
    logger.info("Phase 1: Preflight checks...")
    checks = {"ONAP SO": so.health(), "Policy PAP": clamp.health()}
    all_ok = True
    for n, ok in checks.items():
        logger.info(f"  {n:<14} {'✅ OK' if ok else '❌ FAIL'}")
        all_ok = all_ok and ok

    if not all_ok and not dry_run:
        logger.error("Preflight failed — run preflight_check.py for details")
        rec.error = "Preflight failed"
        return rec

    if dry_run:
        logger.info("[DRY-RUN] preflight only")
        rec.t_attack_start = rec.t_trigger = rec.t_policy_push = \
            rec.t_so_request = rec.t_vnf_active = rec.t_sfc_rule = time.time()
        return rec

    try:
        # ── 2. Start threshold poller ────────────────────────────────────────
        logger.info("Phase 2a: starting threshold poller (rule-based detector)...")
        poller = ThresholdPoller(
            collector_url=collector_url, interval_s=5.0,
            sustain_windows=sustain_windows,
        )
        poller.start()

        logger.info(f"Phase 2b: Normal traffic baseline ({NORMAL_DUR_S}s)...")
        time.sleep(NORMAL_DUR_S)

        # ── 3. Inject attack ─────────────────────────────────────────────────
        logger.info(f"Phase 3: Injecting UDP flood ({ATTACK_DUR_S}s)...")
        rec.t_attack_start = time.time()
        if attack_mode == "gnmi":
            _start_gnmi_flood(gnmi_url)
        else:
            _start_mininet_flood(bridge, src_ip)

        # ── 4. Wait for rule trip ────────────────────────────────────────────
        logger.info(f"Phase 4: Waiting threshold to trip T3 "
                    f"(timeout {detect_timeout_s}s, sustain={sustain_windows})...")
        ev = poller.wait_for_tier(
            min_tier=int(Tier.MITIGATE),
            timeout_s=detect_timeout_s,
            after=rec.t_attack_start,
        )
        if ev is None:
            logger.error("Threshold never tripped T3 — stock ONAP would stay quiet")
            rec.error = "Threshold detection timeout"
            _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
            poller.stop()
            return rec

        rec.t_trigger      = ev.t
        rec.detector_label = f"rule:{ev.reason}"
        rec.detector_evidence = {
            "tier":        ev.tier,
            "pkt_rate":    ev.pkt_rate,
            "syn_ratio":   ev.syn_ratio,
            "udp_frac":    ev.udp_frac,
            "src_entropy": ev.src_entropy,
            "reason":      ev.reason,
            "sustain_windows": sustain_windows,
        }
        logger.info(f"  Rule trip: T{ev.tier} | {ev.reason} | "
                    f"latency {(ev.t - rec.t_attack_start)*1000:.0f}ms from attack start")

        publish_to_dmaap(_publish_rule_payload(ev, ev.tier))

        # ── 5. Policy push T3 ────────────────────────────────────────────────
        logger.info("Phase 5: Pushing T3 operational policy to Policy PAP...")
        ok = clamp.push_policy(tier=3, attack_type="RuleBased",
                               device_id=DEVICE_ID, confidence=0.0)
        rec.t_policy_push = time.time()
        if not ok:
            rec.error = "Policy PAP push failed"
            _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
            poller.stop()
            return rec
        logger.info(f"  Policy T3 deployed in "
                    f"{(rec.t_policy_push - rec.t_trigger)*1000:.0f}ms")

        # ── 6. SO instantiate scrubber ───────────────────────────────────────
        logger.info(f"Phase 6: SO instantiate VNF ({VNF_PROFILE})...")
        instance_id = so.instantiate(VNF_PROFILE, DEVICE_ID)
        rec.t_so_request = time.time()
        if not instance_id:
            rec.error = "SO instantiate failed"
            _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
            poller.stop()
            return rec

        # ── 7. Wait VNF active ───────────────────────────────────────────────
        logger.info("Phase 7: Polling SO until VNF ACTIVE...")
        try:
            rec.t_vnf_active = wait_vnf_active(so, instance_id, timeout_s=120)
            logger.info(f"  VNF ACTIVE in "
                        f"{(rec.t_vnf_active - rec.t_so_request)*1000:.0f}ms ✅")
        except (TimeoutError, RuntimeError) as e:
            rec.error = str(e)
            _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id)
            poller.stop()
            return rec

        # ── 8. SFC rule ──────────────────────────────────────────────────────
        logger.info(f"Phase 8: Installing OVS SFC rule ({bridge} → port {vnf_port})...")
        ok = sfc.install(bridge=bridge, src_ip=f"{src_ip}/32",
                         vnf_port=vnf_port, tier=3, device_id=DEVICE_ID)
        rec.t_sfc_rule = time.time()
        if not ok:
            logger.warning("OVS rule install failed (check OVS_SSH_HOST or bridge name)")
            rec.error = "SFC ovs-ofctl failed"
        else:
            logger.info(f"  SFC rule installed in "
                        f"{(rec.t_sfc_rule - rec.t_vnf_active)*1000:.0f}ms ✅")

        # ── 9. Hold ──────────────────────────────────────────────────────────
        remaining = ATTACK_DUR_S - (time.time() - rec.t_attack_start)
        logger.info(f"Phase 9: Holding attack {remaining:.0f}s (scrubber active)...")
        time.sleep(max(0, remaining))

        # ── 10. Stop attack ──────────────────────────────────────────────────
        if attack_mode == "gnmi":
            _stop_gnmi_flood(gnmi_url)
        else:
            _stop_mininet_flood()
        time.sleep(COOLDOWN_S)

        if cleanup:
            logger.info("Cleanup...")
            _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id)

    except Exception as e:
        logger.exception(f"Scenario error: {e}")
        rec.error = str(e)
    finally:
        if poller is not None:
            poller.stop()

    return rec


def _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id):
    if attack_mode == "gnmi":
        _stop_gnmi_flood(gnmi_url)
    else:
        _stop_mininet_flood()
    if instance_id:
        so.terminate(instance_id)
    clamp.revoke_policy(3, DEVICE_ID)
    sfc.remove(DEVICE_ID)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    p = argparse.ArgumentParser(description="ONAP rule-based baseline (no AI)")
    p.add_argument("--attack-mode", default="gnmi", choices=["gnmi", "mininet"])
    p.add_argument("--gnmi-url",    default="http://localhost:8080")
    p.add_argument("--bridge",      default="r1")
    p.add_argument("--src-ip",      default="10.1.0.1")
    p.add_argument("--vnf-port",    type=int, default=4)
    p.add_argument("--dry-run",     action="store_true")
    p.add_argument("--no-cleanup",  action="store_true")
    p.add_argument("--collector-url",   default="http://localhost:7070")
    p.add_argument("--sustain-windows", type=int, default=3,
                   help="Consecutive windows tier ≥ T3 needed to trip — "
                        "emulates DCAE/Holmes correlation. 1 = per-window.")
    p.add_argument("--detect-timeout-s", type=float, default=DETECT_TIMEOUT_S)
    p.add_argument("--out",         default=None)
    args = p.parse_args()

    if os.environ.get("PAD_ONAP_STUB", "true").lower() != "false" and not args.dry_run:
        print("\n⚠️  PAD_ONAP_STUB chưa set thành 'false'!")
        print("   export PAD_ONAP_STUB=false  ← bắt buộc trước khi chạy thật\n")
        sys.exit(1)

    rec = run_baseline(
        attack_mode      = args.attack_mode,
        gnmi_url         = args.gnmi_url,
        bridge           = args.bridge,
        src_ip           = args.src_ip,
        vnf_port         = args.vnf_port,
        dry_run          = args.dry_run,
        cleanup          = not args.no_cleanup,
        collector_url    = args.collector_url,
        sustain_windows  = args.sustain_windows,
        detect_timeout_s = args.detect_timeout_s,
    )
    rec.print_table()

    out = Path(args.out) if args.out else \
          _ROOT / "evaluation" / "results" / "s2_baseline_real_onap.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(rec)
    payload["detection_lat_ms"]      = rec.detection_lat_ms
    payload["pipeline_e2e_ms"]       = rec.pipeline_e2e_ms
    payload["time_to_mitigation_ms"] = rec.time_to_mitigation_ms
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  Result saved → {out}")

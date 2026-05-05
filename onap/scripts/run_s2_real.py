"""
run_s2_real.py — S2: UDP Flood Đột Ngột — ONAP OOM thật (PAD_ONAP_STUB=false)
==============================================================================
Kịch bản S2: Normal (30s) → UDP flood đột ngột → Tier T3 Reactive MITIGATE

Luồng end-to-end:
  1. Preflight: kiểm tra SO / Policy / DMaaP alive
  2. Khởi động gNMI simulator UDP flood (hoặc Mininet hping3)
  3. NetFlow Collector → feature extractor → InferenceEngine
  4. AI detect UDP_Flood conf ≥ 0.85 → AIOutputPayload publish → DMaaP
  5. CLAMPReal.push_policy(tier=3, attack_type=UDP_Flood)
  6. ONAPSOReal.instantiate("vnfd-scrubber-v1")  ← SO API thật
  7. wait_vnf_active() poll đến ACTIVE            ← ~6s boot
  8. OVSSFCReal.install() → ovs-ofctl thật        ← OVS rule
  9. Thu latency (AI→Policy→SO→VNF→SFC), in bảng kết quả
  10. Cleanup: terminate VNF, revoke policy, remove SFC

Cách chạy:
  export PAD_ONAP_STUB=false
  export ONAP_HOST=<k8s-node-ip>
  export PAD_SERVICE_MODEL_UUID=<uuid-từ-SDC>
  python onap/scripts/run_s2_real.py

  # Với Mininet real traffic thay gNMI simulator:
  python onap/scripts/run_s2_real.py --attack-mode mininet --bridge r1 --src-ip 10.1.0.1 --vnf-port 4

  # Dry-run (kiểm tra preflight nhưng không gọi ONAP thật):
  python onap/scripts/run_s2_real.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from onap.scripts.onap_e2e_lib import (
    ONAPSOReal, CLAMPReal, OVSSFCReal,
    E2ERecord, wait_vnf_active, publish_to_dmaap,
)
from onap.scripts.ai_runtime import LiveInferenceRunner, TierEvent

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt= "%H:%M:%S",
)
logger = logging.getLogger("s2_real")

SCENARIO      = "S2_sudden_udp_flood"
DEVICE_ID     = "r1"
ATTACK_TYPE   = "UDP_Flood"
VNF_PROFILE   = "vnfd-scrubber-v1"
CONFIDENCE    = 0.92
TIER          = 3
NORMAL_DUR_S  = 30    # giây traffic bình thường trước khi inject
ATTACK_DUR_S  = 60    # giây giữ attack
COOLDOWN_S    = 15    # giây sau khi dừng attack trước cleanup


# ─────────────────────────────────────────────────────────────────────────────
# Attack injection helpers
# ─────────────────────────────────────────────────────────────────────────────
def _start_gnmi_flood(gnmi_url: str):
    import urllib.request, json as _json
    body = _json.dumps({"type": "udp_flood", "target": DEVICE_ID}).encode()
    req  = urllib.request.Request(
        f"{gnmi_url}/attack/start", data=body,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        logger.info(f"[gNMI] UDP flood started on {DEVICE_ID}")
    except Exception as e:
        logger.error(f"[gNMI] start flood failed: {e}")


def _stop_gnmi_flood(gnmi_url: str):
    import urllib.request, json as _json
    body = _json.dumps({}).encode()
    req  = urllib.request.Request(
        f"{gnmi_url}/attack/stop", data=body,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        logger.info("[gNMI] attack stopped")
    except Exception as e:
        logger.error(f"[gNMI] stop failed: {e}")


def _start_mininet_flood(bridge: str, src_ip: str):
    """hping3 UDP flood trong Mininet (chạy subprocess hoặc via SSH)."""
    import subprocess
    ssh_host = os.environ.get("OVS_SSH_HOST")
    cmd = f"hping3 --udp --flood -p 80 {src_ip}"
    if ssh_host:
        cmd = f"ssh ubuntu@{ssh_host} 'sudo hping3 --udp --flood -p 80 {src_ip} &'"
    logger.info(f"[Mininet] starting flood: {cmd}")
    subprocess.Popen(cmd, shell=True)


def _stop_mininet_flood():
    import subprocess
    ssh_host = os.environ.get("OVS_SSH_HOST")
    cmd = "sudo pkill hping3"
    if ssh_host:
        cmd = f"ssh ubuntu@{ssh_host} 'sudo pkill hping3'"
    subprocess.run(cmd, shell=True)
    logger.info("[Mininet] hping3 stopped")


DETECT_TIMEOUT_S = 60   # giới hạn chờ AI tier ≥ 3 sau khi flood bắt đầu


# ─────────────────────────────────────────────────────────────────────────────
# Main scenario
# ─────────────────────────────────────────────────────────────────────────────
def run_s2(
    attack_mode:   str   = "gnmi",
    gnmi_url:      str   = "http://localhost:8080",
    bridge:        str   = "r1",
    src_ip:        str   = "10.1.0.1",
    vnf_port:      int   = 4,
    dry_run:       bool  = False,
    cleanup:       bool  = True,
    collector_url: str   = "http://localhost:7070",
    model_dir:     str   = "pad_onap_v3/models",
    data_dir:      str   = "pad_onap_v3/processed",
    device:        str   = "cpu",
) -> E2ERecord:

    rec = E2ERecord(scenario=SCENARIO, vnf_profile=VNF_PROFILE)
    so     = ONAPSOReal()
    clamp  = CLAMPReal()
    sfc    = OVSSFCReal()
    runner: "LiveInferenceRunner | None" = None

    sep = "═" * 62
    print(f"\n{sep}")
    print(f"  PAD-ONAP E2E — {SCENARIO}")
    print(f"  Mode: {'DRY-RUN' if dry_run else 'REAL ONAP (PAD_ONAP_STUB=false)'}")
    print(f"  Attack: {attack_mode.upper()}  │  Bridge: {bridge}  │  VNF port: {vnf_port}")
    print(f"{sep}\n")

    # ── 1. Preflight ──────────────────────────────────────────────────────────
    logger.info("Phase 1: Preflight checks...")
    checks = {
        "ONAP SO":     so.health(),
        "Policy PAP":  clamp.health(),
    }
    all_ok = True
    for name, ok in checks.items():
        status = "✅ OK" if ok else "❌ FAIL"
        logger.info(f"  {name:<16} {status}")
        if not ok:
            all_ok = False

    if not all_ok and not dry_run:
        logger.error("Preflight failed — run preflight_check.py for details")
        logger.error("Tip: python onap/scripts/preflight_check.py")
        rec.error = "Preflight failed"
        return rec

    if dry_run:
        logger.info("[DRY-RUN] preflight complete — exiting without calling ONAP")
        rec.t_trigger = rec.t_policy_push = rec.t_so_request = \
            rec.t_vnf_active = rec.t_sfc_rule = time.time()
        return rec

    # ── 2. Start trained AI runtime (XGBoost + Transformer) ──────────────────
    logger.info("Phase 2a: Loading trained AI engine + starting collector poller...")
    runner = LiveInferenceRunner(
        collector_url=collector_url, model_dir=model_dir,
        data_dir=data_dir, device=device, interval_s=5.0,
    )
    runner.start()

    # Buffer fill — Transformer needs 12 windows of context before stable forecast
    logger.info(f"Phase 2b: Normal baseline {NORMAL_DUR_S}s (filling AI rolling buffer)...")
    time.sleep(NORMAL_DUR_S)

    # ── 3. Inject attack ──────────────────────────────────────────────────────
    logger.info(f"Phase 3: Injecting UDP flood ({ATTACK_DUR_S}s)...")
    t_attack_start = time.time()
    rec.t_attack_start = t_attack_start
    rec.detector = "ai"
    if attack_mode == "gnmi":
        _start_gnmi_flood(gnmi_url)
    else:
        _start_mininet_flood(bridge, src_ip)

    # ── 4. AI detection — block on real model output ─────────────────────────
    logger.info(f"Phase 4: Waiting trained AI to flag tier ≥ {TIER} "
                f"(timeout {DETECT_TIMEOUT_S}s)...")
    ev: TierEvent | None = runner.wait_for_tier(
        min_tier=TIER, timeout_s=DETECT_TIMEOUT_S, after=t_attack_start,
    )
    if ev is None:
        logger.error(f"AI never reached tier ≥ {TIER} within {DETECT_TIMEOUT_S}s "
                     f"— check collector feed / model")
        rec.error = "AI detection timeout"
        runner.stop()
        _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
        if runner is not None: runner.stop()
        return rec

    rec.t_trigger      = ev.t
    rec.detector_label = f"{ev.attack_type} conf={ev.confidence:.3f} P30={ev.p_attack_30s:.3f}"
    rec.detector_evidence = {
        "tier": ev.tier, "confidence": ev.confidence,
        "p_attack_30s": ev.p_attack_30s, "attack_type": ev.attack_type,
        "window_id": ev.window_id,
    }
    ai_payload         = ev.payload
    logger.info(f"  AI detect: {ev.attack_type}  conf={ev.confidence:.3f}  "
                f"P30={ev.p_attack_30s:.3f}  → T{ev.tier} "
                f"(latency {(ev.t - t_attack_start)*1000:.0f}ms from attack start)")

    # Publish real payload to DMaaP
    logger.info("  Publishing real AIOutputPayload → DMaaP...")
    publish_to_dmaap(ai_payload)

    # ── 5. Policy push ────────────────────────────────────────────────────────
    logger.info(f"Phase 5: Pushing T{ev.tier} operational policy to Policy PAP...")
    ok = clamp.push_policy(
        tier=ev.tier, attack_type=ev.attack_type,
        device_id=DEVICE_ID, confidence=ev.confidence,
    )
    rec.t_policy_push = time.time()
    if not ok:
        logger.error("Policy push failed — aborting")
        rec.error = "Policy PAP push failed"
        _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
        if runner is not None: runner.stop()
        return rec
    logger.info(f"  Policy T{ev.tier} deployed in "
                f"{(rec.t_policy_push - rec.t_trigger)*1000:.0f}ms")

    # ── 6. SO instantiate VNF ────────────────────────────────────────────────
    logger.info(f"Phase 6: SO instantiate VNF ({VNF_PROFILE})...")
    instance_id = so.instantiate(VNF_PROFILE, DEVICE_ID)
    rec.t_so_request = time.time()
    if not instance_id:
        logger.error("SO instantiate returned None — aborting")
        rec.error = "SO instantiate failed"
        _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, None)
        if runner is not None: runner.stop()
        return rec
    logger.info(f"  instance_id = {instance_id}")

    # ── 7. Poll VNF ACTIVE ───────────────────────────────────────────────────
    logger.info("Phase 7: Polling SO until VNF ACTIVE...")
    try:
        rec.t_vnf_active = wait_vnf_active(so, instance_id, timeout_s=120)
        logger.info(f"  VNF ACTIVE in {(rec.t_vnf_active - rec.t_so_request)*1000:.0f}ms ✅")
    except (TimeoutError, RuntimeError) as e:
        logger.error(f"  VNF failed: {e}")
        rec.error = str(e)
        _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id)
        if runner is not None: runner.stop()
        return rec

    # ── 8. SFC steering rule ──────────────────────────────────────────────────
    logger.info(f"Phase 8: Installing OVS SFC rule ({bridge} → port {vnf_port})...")
    ok = sfc.install(
        bridge=bridge, src_ip=f"{src_ip}/32",
        vnf_port=vnf_port, tier=ev.tier, device_id=DEVICE_ID,
    )
    rec.t_sfc_rule = time.time()
    if not ok:
        logger.warning("OVS rule install failed (check OVS_SSH_HOST or bridge name)")
        rec.error = "SFC ovs-ofctl failed"
    else:
        logger.info(f"  SFC rule installed in {(rec.t_sfc_rule - rec.t_vnf_active)*1000:.0f}ms ✅")

    # Verify OVS rules
    flows = sfc.dump_flows(bridge)
    if flows:
        logger.info(f"  OVS flows on {bridge}:\n" +
                    "\n".join(f"    {l}" for l in flows.splitlines()[:5]))

    # ── 9. Hold attack + observe ──────────────────────────────────────────────
    remaining = ATTACK_DUR_S - 5   # đã chờ 5s ở bước 4
    logger.info(f"Phase 9: Holding attack {remaining}s (scrubber active)...")
    time.sleep(max(0, remaining))

    # ── 10. Stop attack ───────────────────────────────────────────────────────
    logger.info("Phase 10: Stopping attack...")
    if attack_mode == "gnmi":
        _stop_gnmi_flood(gnmi_url)
    else:
        _stop_mininet_flood()
    time.sleep(COOLDOWN_S)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    if cleanup:
        logger.info("Cleanup: terminating VNF + revoking policy + removing SFC...")
        _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id)

    if runner is not None:
        runner.stop()

    return rec


def _cleanup(attack_mode, gnmi_url, so, clamp, sfc, bridge, instance_id):
    if attack_mode == "gnmi":
        _stop_gnmi_flood(gnmi_url)
    else:
        _stop_mininet_flood()
    if instance_id:
        so.terminate(instance_id)
    clamp.revoke_policy(TIER, DEVICE_ID)
    sfc.remove(DEVICE_ID)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PAD-ONAP E2E — S2 UDP Flood (real ONAP)")
    parser.add_argument("--attack-mode", default="gnmi",
                        choices=["gnmi", "mininet"],
                        help="gnmi = gNMI simulator | mininet = hping3 thật")
    parser.add_argument("--gnmi-url",    default="http://localhost:8080")
    parser.add_argument("--bridge",      default="r1",   help="OVS bridge name")
    parser.add_argument("--src-ip",      default="10.1.0.1", help="Attacker IP/subnet")
    parser.add_argument("--vnf-port",    type=int, default=4, help="OVS port for VNF")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Chỉ preflight, không gọi ONAP thật")
    parser.add_argument("--no-cleanup",  action="store_true",
                        help="Giữ VNF sau khi chạy xong (debug)")
    parser.add_argument("--collector-url", default="http://localhost:7070",
                        help="NetFlow feature collector HTTP endpoint")
    parser.add_argument("--model-dir",     default="pad_onap_v3/models",
                        help="Thư mục chứa XGBoost + Transformer đã train")
    parser.add_argument("--data-dir",      default="pad_onap_v3/processed",
                        help="Thư mục chứa scaler.pkl (fallback)")
    parser.add_argument("--device",        default="cpu",
                        choices=["cpu", "cuda"], help="Device cho Transformer")
    args = parser.parse_args()

    if os.environ.get("PAD_ONAP_STUB", "true").lower() != "false" and not args.dry_run:
        print("\n⚠️  PAD_ONAP_STUB chưa set thành 'false'!")
        print("   export PAD_ONAP_STUB=false  ← bắt buộc trước khi chạy kịch bản thật")
        print("   Hoặc: python run_s2_real.py --dry-run\n")
        sys.exit(1)

    rec = run_s2(
        attack_mode   = args.attack_mode,
        gnmi_url      = args.gnmi_url,
        bridge        = args.bridge,
        src_ip        = args.src_ip,
        vnf_port      = args.vnf_port,
        dry_run       = args.dry_run,
        cleanup       = not args.no_cleanup,
        collector_url = args.collector_url,
        model_dir     = args.model_dir,
        data_dir      = args.data_dir,
        device        = args.device,
    )
    rec.print_table()

    # Save JSON result
    import json
    from dataclasses import asdict
    out = Path(_ROOT) / "evaluation" / "results" / "s2_real_onap.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(rec)
    payload["detection_lat_ms"]      = rec.detection_lat_ms
    payload["pipeline_e2e_ms"]       = rec.pipeline_e2e_ms
    payload["time_to_mitigation_ms"] = rec.time_to_mitigation_ms
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  Result saved → {out}")

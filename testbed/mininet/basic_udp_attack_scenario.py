#!/usr/bin/env python3
"""
Bounded Mininet UDP-flood scenario for PAD-ONAP local testbed checks.

This is a lightweight WSL/Linux runner for the period before a full
ONAP/Kubernetes deployment is available. It creates a two-host OVS standalone
topology, measures baseline connectivity, runs a bounded hping3 UDP flood, and
writes JSON metrics. The output is a simulated Mininet testbed result, not a
real ONAP/Kubernetes result.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if sys.platform != "linux" or os.geteuid() != 0:
    print("[ERROR] Run inside Linux as root, for example: sudo python3 basic_udp_attack_scenario.py")
    sys.exit(1)

from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


ROOT = Path(__file__).resolve().parents[2]
RESULT_ROOT = ROOT / "results" / "mock_orchestration"
METADATA_ROOT = ROOT / "results" / "metadata"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def _parse_ping(output: str) -> dict[str, Any]:
    loss_pct = None
    rtt: dict[str, float] = {}
    for line in output.splitlines():
        if "packet loss" in line:
            try:
                loss_pct = float(line.split("%")[0].split()[-1])
            except ValueError:
                loss_pct = None
        if "rtt" in line or "round-trip" in line:
            try:
                values = line.split("=")[-1].strip().split()[0].split("/")
                keys = ["min_ms", "avg_ms", "max_ms", "mdev_ms"]
                rtt = {key: float(value) for key, value in zip(keys, values[:4])}
            except ValueError:
                rtt = {}
    return {"loss_pct": loss_pct, "rtt": rtt, "raw": output.strip()}


def _parse_iperf3(output: str) -> dict[str, Any]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"bandwidth_mbps": None, "retransmits": None, "raw": output.strip()}
    end = data.get("end", {})
    received = end.get("sum_received", {})
    sent = end.get("sum_sent", {})
    bps = received.get("bits_per_second")
    return {
        "bandwidth_mbps": round(bps / 1_000_000, 3) if bps else None,
        "retransmits": sent.get("retransmits"),
    }


def _run_iperf3(src, dst, seconds: int) -> dict[str, Any]:
    server = dst.popen(["iperf3", "-s", "-1", "-J"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    client_output = src.cmd(f"timeout {seconds + 4}s iperf3 -c {dst.IP()} -t {seconds} -J")
    try:
        server.communicate(timeout=seconds + 6)
    except subprocess.TimeoutExpired:
        server.kill()
    return _parse_iperf3(client_output)


def run_scenario(run_id: str, duration_s: int, iperf_seconds: int) -> dict[str, Any]:
    output_dir = RESULT_ROOT / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    METADATA_ROOT.mkdir(parents=True, exist_ok=True)

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    s1 = net.addSwitch("s1", protocols="OpenFlow13", failMode="standalone")
    attacker = net.addHost("attacker", ip="10.0.0.1/24")
    victim = net.addHost("victim", ip="10.0.0.2/24")
    net.addLink(attacker, s1, bw=100, delay="2ms")
    net.addLink(victim, s1, bw=100, delay="2ms")

    started_at = _utc_now()
    results: dict[str, Any] = {
        "run_id": run_id,
        "result_type": "simulated_testbed_result",
        "mode": "mininet_basic_udp_attack",
        "timestamp_utc": started_at,
        "topology": {
            "hosts": ["attacker", "victim"],
            "switches": ["s1"],
            "link_bandwidth_mbps": 100,
            "link_delay": "2ms",
        },
        "attack": {
            "tool": "hping3",
            "traffic": "udp_flood",
            "attacker": "attacker",
            "victim": "victim",
            "duration_s": duration_s,
        },
        "measurements": {},
        "notes": [
            "Mininet emulation only; this is not real ONAP/Kubernetes execution.",
            "No ML model was trained or evaluated by this scenario.",
        ],
    }

    try:
        info("*** Starting basic PAD-ONAP Mininet UDP attack scenario\n")
        net.start()
        time.sleep(1)

        results["measurements"]["pingall_loss_pct"] = net.pingAll(timeout="2")
        results["measurements"]["baseline_ping"] = _parse_ping(attacker.cmd(f"ping -c 5 -i 0.2 {victim.IP()}"))
        results["measurements"]["baseline_iperf3"] = _run_iperf3(attacker, victim, iperf_seconds)

        flood = attacker.popen(
            ["timeout", f"{duration_s}s", "hping3", "--udp", "--flood", "-p", "80", victim.IP()],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(max(1, min(2, duration_s)))
        attack_started = time.monotonic()
        results["measurements"]["during_attack_ping"] = _parse_ping(attacker.cmd(f"ping -c 5 -i 0.2 {victim.IP()}"))
        flood.wait(timeout=duration_s + 5)
        results["measurements"]["attack_process_runtime_s"] = round(time.monotonic() - attack_started, 3)

        time.sleep(1)
        results["measurements"]["post_attack_ping"] = _parse_ping(attacker.cmd(f"ping -c 5 -i 0.2 {victim.IP()}"))
        results["measurements"]["post_attack_iperf3"] = _run_iperf3(attacker, victim, iperf_seconds)
    finally:
        attacker.cmd("pkill hping3 2>/dev/null || true")
        victim.cmd("pkill iperf3 2>/dev/null || true")
        net.stop()

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    metadata = {
        "run_id": run_id,
        "timestamp_utc": started_at,
        "mode": "mininet_basic_udp_attack",
        "git_commit": _git_commit(),
        "source_file": str(summary_path.relative_to(ROOT)).replace("\\", "/"),
        "notes": "Simulated Mininet UDP-flood testbed result; not real ONAP/K8s.",
    }
    (METADATA_ROOT / f"{run_id}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a bounded Mininet UDP-flood scenario.")
    parser.add_argument("--run-id", default=f"mininet-basic-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--iperf-seconds", type=int, default=3)
    args = parser.parse_args()

    setLogLevel("info")
    results = run_scenario(args.run_id, args.duration, args.iperf_seconds)
    m = results["measurements"]
    print(json.dumps({
        "run_id": results["run_id"],
        "result_type": results["result_type"],
        "pingall_loss_pct": m.get("pingall_loss_pct"),
        "baseline_ping_avg_ms": m.get("baseline_ping", {}).get("rtt", {}).get("avg_ms"),
        "during_attack_ping_loss_pct": m.get("during_attack_ping", {}).get("loss_pct"),
        "post_attack_ping_avg_ms": m.get("post_attack_ping", {}).get("rtt", {}).get("avg_ms"),
        "baseline_iperf3_mbps": m.get("baseline_iperf3", {}).get("bandwidth_mbps"),
        "post_attack_iperf3_mbps": m.get("post_attack_iperf3", {}).get("bandwidth_mbps"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

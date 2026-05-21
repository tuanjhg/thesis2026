#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib import request

if os.name != "nt" and os.geteuid() != 0:
    print("Run with sudo: sudo -E python3 scripts/run_fastpath_fattree_k4_report.py", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mininet.log import setLogLevel
from testbed.mininet.fat_tree_topology import attacker_victim, build_fat_tree


SCENARIOS = {
    "S1": {"tier": 0, "attack_type": "BENIGN", "kind": "iperf_udp"},
    "S2": {"tier": 2, "attack_type": "SYN_LOW", "kind": "syn_low"},
    "S3": {"tier": 3, "attack_type": "SYN_HIGH", "kind": "syn_rand"},
    "S4": {"tier": 3, "attack_type": "UDP_AMP", "kind": "udp_rand"},
    "S5": {"tier": 4, "attack_type": "MULTI", "kind": "multi_syn"},
    "S6": {"tier": 4, "attack_type": "CARPET", "kind": "carpet"},
    "S7": {"tier": 2, "attack_type": "SLOW_RATE", "kind": "slow_rate"},
    "S8": {"tier": 3, "attack_type": "BURST", "kind": "burst"},
}


def _http_json(method: str, url: str, payload: dict | None = None, timeout: float = 5.0) -> tuple[dict, float]:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(url, data=data, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    t0 = time.perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
    return json.loads(body or "{}"), (time.perf_counter() - t0) * 1000.0


def _loss_pct(ping_output: str) -> float | None:
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", ping_output)
    return float(m.group(1)) if m else None


def _run_payload(kind: str, hosts: dict, victim_ip: str, duration: int) -> str:
    h0 = hosts["h0"]
    h1 = hosts.get("h1", h0)
    h2 = hosts.get("h2", h0)
    h15 = hosts["h15"]

    if kind == "iperf_udp":
        h15.cmd("pkill -f iperf3 2>/dev/null")
        h15.cmd("iperf3 -s -D")
        time.sleep(0.4)
        out = h0.cmd(f"iperf3 -c {victim_ip} -u -b 20M -t {duration} -J")
        h15.cmd("pkill -f iperf3 2>/dev/null")
        return out
    if kind == "syn_low":
        return h0.cmd(f"timeout {duration}s hping3 -S -p 80 -i u1000 {victim_ip}")
    if kind == "syn_rand":
        return h0.cmd(f"timeout {duration}s hping3 -S --flood -p 80 --rand-source {victim_ip}")
    if kind == "udp_rand":
        return h0.cmd(f"timeout {duration}s hping3 --udp --flood -p 53 --rand-source {victim_ip}")
    if kind == "multi_syn":
        h0.cmd(f"timeout {duration}s hping3 -S -p 80 -i u100 {victim_ip} >/tmp/pad_s5_h0.log 2>&1 &")
        h1.cmd(f"timeout {duration}s hping3 -S -p 80 -i u100 {victim_ip} >/tmp/pad_s5_h1.log 2>&1 &")
        time.sleep(duration + 0.5)
        return h0.cmd("cat /tmp/pad_s5_h0.log 2>/dev/null") + h1.cmd("cat /tmp/pad_s5_h1.log 2>/dev/null")
    if kind == "carpet":
        return h0.cmd(
            f"timeout {duration}s hping3 -I {h0.defaultIntf().name} "
            "-S --flood -p 80 --rand-dest 10.3.0.0/16"
        )
    if kind == "slow_rate":
        return h0.cmd(f"timeout {duration}s hping3 -S -p 80 -i u1000 {victim_ip}")
    if kind == "burst":
        h0.cmd(f"timeout 2s hping3 -S --flood -p 80 {victim_ip} >/tmp/pad_s8_1.log 2>&1 &")
        time.sleep(max(1, duration // 2))
        h2.cmd(f"timeout 2s hping3 -S --flood -p 80 {victim_ip} >/tmp/pad_s8_2.log 2>&1 &")
        time.sleep(2.5)
        return h0.cmd("cat /tmp/pad_s8_1.log 2>/dev/null") + h2.cmd("cat /tmp/pad_s8_2.log 2>/dev/null")
    raise ValueError(kind)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--ryu-url", default="http://127.0.0.1:8080")
    parser.add_argument("--out-dir", default=str(ROOT / "results" / "fastpath_fattree"))
    args = parser.parse_args()

    setLogLevel("warning")
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "run_id": run_id,
        "topology": {"k": 4, "expected_switches": 20, "expected_hosts": 16},
        "ryu_url": args.ryu_url,
        "scenario_duration_s": args.duration,
        "scenarios": [],
    }

    net = None
    try:
        _http_json("GET", f"{args.ryu_url}/pad/stats")
        net = build_fat_tree(k=4, use_remote_ctrl=True)
        net.start()
        time.sleep(5)
        net.staticArp()
        pingall_loss = net.pingAll(timeout="2")
        attacker, victim = attacker_victim(net)
        hosts = {h.name: h for h in net.hosts}
        summary["topology"].update({
            "actual_switches": len(net.switches),
            "actual_hosts": len(net.hosts),
            "attacker": attacker.name,
            "attacker_ip": attacker.IP(),
            "victim": victim.name,
            "victim_ip": victim.IP(),
            "pingall_loss_pct": pingall_loss,
        })

        topo, _ = _http_json("GET", f"{args.ryu_url}/pad/topology")
        summary["ryu_topology_seen"] = {
            "switches": len(topo.get("switches", [])),
            "links": len(topo.get("links", [])),
            "hosts": len(topo.get("hosts", [])),
        }

        for sid, spec in SCENARIOS.items():
            _http_json("DELETE", f"{args.ryu_url}/pad/tier")
            pre_ping = attacker.cmd(f"ping -c 3 -W 1 {victim.IP()}")
            payload = {
                "src_ip": attacker.IP(),
                "dst_ip": victim.IP(),
                "tier": spec["tier"],
                "attack_type": spec["attack_type"],
                "redirect_to": "10.244.5.42" if spec["tier"] == 3 else "",
            }
            tier_resp, post_ms = _http_json("POST", f"{args.ryu_url}/pad/tier", payload)
            traffic_out = _run_payload(spec["kind"], hosts, victim.IP(), args.duration)
            time.sleep(0.5)
            flows, _ = _http_json("GET", f"{args.ryu_url}/pad/flows")
            stats, _ = _http_json("GET", f"{args.ryu_url}/pad/stats")
            post_ping = attacker.cmd(f"ping -c 3 -W 1 {victim.IP()}")
            cleared, _ = _http_json("DELETE", f"{args.ryu_url}/pad/tier")
            net.get("h0").cmd("pkill -f hping3 2>/dev/null")
            net.get("h1").cmd("pkill -f hping3 2>/dev/null")
            net.get("h2").cmd("pkill -f hping3 2>/dev/null")

            row = {
                "scenario": sid,
                "attack_type": spec["attack_type"],
                "target_tier": spec["tier"],
                "fastpath_action": tier_resp.get("action"),
                "fastpath_post_latency_ms": round(post_ms, 2),
                "installed_switches": len(tier_resp.get("installed_on_dpids", [])),
                "flow_count": flows.get("count", 0),
                "pre_ping_loss_pct": _loss_pct(pre_ping),
                "post_ping_loss_pct": _loss_pct(post_ping),
                "cleared_rules": cleared.get("cleared"),
                "stats_switches": len(stats.get("switches", {})),
                "traffic_output_head": traffic_out.strip().splitlines()[:5],
            }
            row["pass"] = (
                pingall_loss == 0.0
                and row["stats_switches"] >= 20
                and (row["target_tier"] == 0 or row["installed_switches"] >= 20)
            )
            summary["scenarios"].append(row)
            print(f"{sid}: action={row['fastpath_action']} installed={row['installed_switches']} pass={row['pass']}")

    finally:
        if net is not None:
            try:
                for h in net.hosts:
                    h.cmd("pkill -f hping3 2>/dev/null; pkill -f iperf3 2>/dev/null")
                net.stop()
            except Exception:
                pass

    json_path = out_dir / "fastpath_fattree_k4_results.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    passed = sum(1 for s in summary["scenarios"] if s["pass"])
    total = len(summary["scenarios"])
    lines = [
        f"# Fastpath Ryu + Mininet Fat-Tree k=4 Report",
        "",
        f"- Run ID: `{run_id}`",
        f"- Topology: k=4, switches={summary['topology'].get('actual_switches')}, hosts={summary['topology'].get('actual_hosts')}",
        f"- Attacker/Victim: `{summary['topology'].get('attacker')} ({summary['topology'].get('attacker_ip')})` -> `{summary['topology'].get('victim')} ({summary['topology'].get('victim_ip')})`",
        f"- Ryu topology seen: switches={summary.get('ryu_topology_seen', {}).get('switches')}, links={summary.get('ryu_topology_seen', {}).get('links')}, hosts={summary.get('ryu_topology_seen', {}).get('hosts')}",
        f"- Pingall loss: {summary['topology'].get('pingall_loss_pct')}%",
        f"- Result: **{passed}/{total} scenarios passed**",
        "",
        "| Scenario | Attack | Tier | Action | POST ms | Installed switches | Flow count | Pass |",
        "|---|---:|---:|---|---:|---:|---:|---|",
    ]
    for s in summary["scenarios"]:
        lines.append(
            f"| {s['scenario']} | {s['attack_type']} | T{s['target_tier']} | "
            f"{s['fastpath_action']} | {s['fastpath_post_latency_ms']} | "
            f"{s['installed_switches']} | {s['flow_count']} | {'PASS' if s['pass'] else 'FAIL'} |"
        )
    lines.extend(["", f"JSON detail: `{json_path}`", ""])
    md_path = out_dir / "fastpath_fattree_k4_report.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(md_path)


if __name__ == "__main__":
    main()

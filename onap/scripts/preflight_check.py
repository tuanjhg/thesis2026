"""
preflight_check.py — PAD-ONAP Real ONAP Connectivity Check
===========================================================
Run BEFORE switching PAD_ONAP_STUB=false to verify all
ONAP components are reachable and healthy.

Usage:
  python onap/scripts/preflight_check.py
  python onap/scripts/preflight_check.py --host <k8s-node-ip>

Exit code: 0 = all checks pass, 1 = one or more failed
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import List

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[ERROR] pip install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_HOST        = os.environ.get("ONAP_HOST", "localhost")
SO_PORT             = int(os.environ.get("ONAP_SO_PORT",         "30080"))
DMAAP_PORT          = int(os.environ.get("ONAP_DMAAP_PORT",      "30904"))
POLICY_PORT         = int(os.environ.get("ONAP_POLICY_PORT",     "30969"))
SDN_PORT            = int(os.environ.get("ONAP_SDN_PORT",        "30282"))
SO_USER             = os.environ.get("PAD_ONAP_SO_USER",         "so_admin")
SO_PASS             = os.environ.get("PAD_ONAP_SO_PASS",         "demo123456!")
POLICY_USER         = os.environ.get("PAD_ONAP_POLICY_USER",     "healthcheck")
POLICY_PASS         = os.environ.get("PAD_ONAP_POLICY_PASS",     "zb!XztG34")
DMAAP_TOPIC         = os.environ.get("PAD_DMAAP_TOPIC",          "PAD_ONAP_AI_SIGNALS")
BYPASS_DMAAP        = os.environ.get("PAD_BYPASS_DMAAP",         "false").lower() == "true"
TIMEOUT             = 10


# ── Result helpers ────────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    name:    str
    passed:  bool
    detail:  str
    time_ms: float = 0.0

results: List[CheckResult] = []

def check(name: str):
    """Decorator for check functions."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                passed, detail = fn(*args, **kwargs)
            except Exception as exc:
                passed, detail = False, f"Exception: {exc}"
            elapsed = (time.perf_counter() - t0) * 1000
            r = CheckResult(name, passed, detail, round(elapsed, 1))
            results.append(r)
            status = "PASS" if passed else "FAIL"
            print(f"  [{status}] {name:<45} {detail}  ({elapsed:.0f}ms)")
        return wrapper
    return decorator


# ── Individual checks ─────────────────────────────────────────────────────────
@check("ONAP SO — health endpoint")
def check_so_health(host):
    url = f"http://{host}:{SO_PORT}/manage/health"
    r = requests.get(url, auth=(SO_USER, SO_PASS),
                     timeout=TIMEOUT, verify=False)
    if r.status_code == 200:
        return True, "HTTP 200"
    return False, f"HTTP {r.status_code}"

@check("ONAP SO — API version")
def check_so_api(host):
    url = f"http://{host}:{SO_PORT}/onap/so/infra/orchestrationRequests/v7"
    r = requests.get(url, auth=(SO_USER, SO_PASS),
                     timeout=TIMEOUT, verify=False)
    # 200 or 400 (no requestId) both mean API is reachable
    if r.status_code in (200, 400, 404):
        return True, f"HTTP {r.status_code} (API reachable)"
    return False, f"HTTP {r.status_code}"

@check("ONAP DMaaP — Message Router health")
def check_dmaap_health(host):
    url = f"http://{host}:{DMAAP_PORT}/topics"
    r = requests.get(url, timeout=TIMEOUT, verify=False)
    if r.status_code == 200:
        topics = r.json().get("topics", [])
        return True, f"MR up, {len(topics)} topics"
    return False, f"HTTP {r.status_code}"

@check("ONAP DMaaP — PAD topic exists or can be created")
def check_dmaap_topic(host):
    # Try to read topic info (404 = does not exist yet, will be auto-created on first publish)
    url = f"http://{host}:{DMAAP_PORT}/topics/{DMAAP_TOPIC}"
    r = requests.get(url, timeout=TIMEOUT, verify=False)
    if r.status_code == 200:
        return True, "topic exists"
    if r.status_code == 404:
        return True, "topic will be auto-created on first publish"
    return False, f"HTTP {r.status_code}"

@check("ONAP DMaaP — publish test event")
def check_dmaap_publish(host):
    url = f"http://{host}:{DMAAP_PORT}/events/{DMAAP_TOPIC}"
    payload = json.dumps([{"test": "preflight", "ts": time.time()}])
    r = requests.post(url, data=payload,
                      headers={"Content-Type": "application/json"},
                      timeout=TIMEOUT, verify=False)
    if r.status_code in (200, 207):
        return True, f"publish OK (HTTP {r.status_code})"
    return False, f"HTTP {r.status_code}: {r.text[:80]}"

@check("ONAP Policy PAP — health endpoint")
def check_policy_health(host):
    url = f"http://{host}:{POLICY_PORT}/policy/pap/v1/healthcheck"
    r = requests.get(url, auth=(POLICY_USER, POLICY_PASS),
                     timeout=TIMEOUT, verify=False)
    if r.status_code == 200:
        body = r.json()
        healthy = body.get("healthy", False)
        return healthy, f"healthy={healthy}"
    return False, f"HTTP {r.status_code}"

@check("ONAP Policy PAP — PDP groups")
def check_policy_pdp(host):
    url = f"http://{host}:{POLICY_PORT}/policy/pap/v1/pdps"
    r = requests.get(url, auth=(POLICY_USER, POLICY_PASS),
                     timeout=TIMEOUT, verify=False)
    if r.status_code == 200:
        groups = r.json().get("groups", [])
        return True, f"{len(groups)} PDP group(s) registered"
    return False, f"HTTP {r.status_code}"

@check("ONAP SDNR/ODL — connectivity (optional)")
def check_sdnr(host):
    url = f"http://{host}:{SDN_PORT}/rests/data/network-topology"
    try:
        r = requests.get(url, auth=("admin", "admin"),
                         timeout=5, verify=False)
        if r.status_code in (200, 401):
            return True, f"SDNR reachable (HTTP {r.status_code})"
        return True, f"SDNR HTTP {r.status_code} (non-critical)"
    except Exception as e:
        return True, f"SDNR unreachable (non-critical): {e}"

@check("PAD-ONAP models — Track A (XGBoost) + Track B (LSTM/Transformer) artefacts")
def check_models():
    model_dir = os.environ.get("PAD_MODEL_DIR", "pad_onap_v3/models")

    # Track A — accept either spec-mode artefact or legacy v3 artefact
    xgb_candidates = [
        "xgboost_track_a.json",     # spec mode (Phase 1 trainer output)
        "xgboost_v3.json",          # legacy v3 (still loadable in legacy mode)
        "xgboost_7class_v2.json",   # legacy v2 (fallback)
    ]
    # Track B — accept stacked-LSTM or transformer artefact
    lstm_candidates = [
        "lstm_track_b.pt",          # spec mode
        "transformer_v3.pt",        # legacy v3
        "transformer_lstm_v2.pth",  # legacy v2
    ]
    # Scaler (Track A) — required by the inference engine
    scaler_candidates = [
        "scaler_track_a.pkl",       # spec mode
        "scaler.pkl",               # legacy fallback
    ]

    found_xgb    = next((c for c in xgb_candidates   if os.path.exists(os.path.join(model_dir, c))), None)
    found_lstm   = next((c for c in lstm_candidates  if os.path.exists(os.path.join(model_dir, c))), None)
    found_scaler = next((c for c in scaler_candidates if os.path.exists(os.path.join(model_dir, c))), None)

    missing = []
    if found_xgb    is None: missing.append(f"XGBoost ({'/'.join(xgb_candidates)})")
    if found_lstm   is None: missing.append(f"LSTM/Transformer ({'/'.join(lstm_candidates)})")
    if found_scaler is None: missing.append(f"Scaler ({'/'.join(scaler_candidates)})")
    if missing:
        return False, f"Missing in {model_dir}: {missing}"
    return True, f"xgb={found_xgb}  lstm={found_lstm}  scaler={found_scaler}"


@check("PAD-ONAP environment — deploy mode")
def check_stub_flag():
    # New canonical env: PAD_DEPLOY_MODE = stub | helm | onap
    mode = os.environ.get("PAD_DEPLOY_MODE", "").lower()
    if mode in ("onap", "helm"):
        return True, f"PAD_DEPLOY_MODE={mode} (real orchestration path)"
    if mode == "stub":
        return False, "PAD_DEPLOY_MODE=stub (CNF lifecycle will not hit ONAP)"
    # Fallback to legacy flag
    legacy = os.environ.get("PAD_ONAP_STUB", "true").lower()
    if legacy == "false":
        return True, "PAD_ONAP_STUB=false (legacy real-mode flag honoured)"
    return False, ("Neither PAD_DEPLOY_MODE nor PAD_ONAP_STUB are set "
                   "for real-mode operation")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="PAD-ONAP pre-flight check")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="ONAP host / K8s node IP (default: ONAP_HOST env or localhost)")
    args = parser.parse_args()
    host = args.host

    print("=" * 65)
    print("  PAD-ONAP Real ONAP Pre-Flight Check")
    print(f"  Target host: {host}")
    print("=" * 65)

    print("\n[ONAP SO]")
    check_so_health(host)
    check_so_api(host)

    print("\n[ONAP DMaaP]")
    if BYPASS_DMAAP:
        print("  [SKIP] PAD_BYPASS_DMAAP=true — skipping DMaaP checks")
    else:
        check_dmaap_health(host)
        check_dmaap_topic(host)
        check_dmaap_publish(host)

    print("\n[ONAP Policy]")
    check_policy_health(host)
    check_policy_pdp(host)

    print("\n[ONAP SDNR (optional)]")
    check_sdnr(host)

    print("\n[Local PAD-ONAP]")
    check_models()
    check_stub_flag()

    # ── Summary ───────────────────────────────────────────────────────────────
    passed = sum(1 for r in results if r.passed)
    total  = len(results)
    failed = [r for r in results if not r.passed]

    print("\n" + "=" * 65)
    print(f"  Results: {passed}/{total} checks passed")
    if failed:
        print(f"\n  FAILED checks:")
        for r in failed:
            print(f"    - {r.name}: {r.detail}")
        print("\n  Fix the FAILED checks before setting PAD_ONAP_STUB=false")
    else:
        print("\n  All checks PASSED.")
        print("  Ready to deploy: set PAD_ONAP_STUB=false and restart pipeline.")
    print("=" * 65)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()

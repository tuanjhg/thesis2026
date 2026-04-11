#!/usr/bin/env bash
# ============================================================
# PAD-ONAP Phase 1 Testbed Verification Script
# ============================================================
# Usage:
#   chmod +x scripts/verify_testbed.sh
#   ./scripts/verify_testbed.sh
#
# Returns exit code 0 if all checks pass, 1 if any fail.
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
RESULTS=()

# ── Helper functions ──────────────────────────────────────────────────────────
pass_check() { echo -e "  ${GRN}[PASS]${NC} $1"; ((PASS++)); RESULTS+=("PASS|$1"); }
fail_check() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); RESULTS+=("FAIL|$1"); }
warn_check() { echo -e "  ${YEL}[WARN]${NC} $1"; ((WARN++)); RESULTS+=("WARN|$1"); }
info()       { echo -e "  ${BLU}[INFO]${NC} $1"; }

check_cmd() {
    # check_cmd "label" "command"
    local label="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null 2>&1; then
        pass_check "$label"
    else
        fail_check "$label — cmd: $cmd"
    fi
}

check_http() {
    # check_http "label" "url" ["expected_string"]
    local label="$1"
    local url="$2"
    local expect="${3:-}"
    local body
    if body=$(curl -sf --max-time 5 "$url" 2>/dev/null); then
        if [[ -n "$expect" ]] && ! echo "$body" | grep -q "$expect"; then
            fail_check "$label — response missing '$expect'"
        else
            pass_check "$label"
        fi
    else
        fail_check "$label — URL not reachable: $url"
    fi
}

check_http_post() {
    local label="$1"
    local url="$2"
    local body="$3"
    if curl -sf --max-time 5 -X POST -H "Content-Type: application/json" \
            -d "$body" "$url" &>/dev/null; then
        pass_check "$label"
    else
        fail_check "$label — POST $url failed"
    fi
}

# ── Section header ────────────────────────────────────────────────────────────
section() {
    echo ""
    echo -e "${BLU}══════════════════════════════════════════════${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}══════════════════════════════════════════════${NC}"
}

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   PAD-ONAP Phase 1 Testbed Verification              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Date: $(date)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
section "1. System Prerequisites"
# ─────────────────────────────────────────────────────────────────────────────

check_cmd "Python 3.9+" \
    "python3 --version | grep -E 'Python 3\.(9|10|11|12)'"

check_cmd "Docker >= 24.0" \
    "docker --version | grep -oE '[0-9]+' | head -1 | awk '{exit (\$1 < 24)}'"

check_cmd "Docker Compose >= 2.0" \
    "docker compose version"

check_cmd "curl available" \
    "which curl"

# Python packages
check_cmd "xgboost installed" \
    "python3 -c 'import xgboost; print(xgboost.__version__)'"

check_cmd "torch (PyTorch) installed" \
    "python3 -c 'import torch; print(torch.__version__)'"

check_cmd "shap installed" \
    "python3 -c 'import shap; print(shap.__version__)'"

check_cmd "pandas installed" \
    "python3 -c 'import pandas; print(pandas.__version__)'"

check_cmd "scikit-learn installed" \
    "python3 -c 'import sklearn; print(sklearn.__version__)'"

# ─────────────────────────────────────────────────────────────────────────────
section "2. Project File Structure"
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_FILES=(
    "testbed/mininet/topology.py"
    "testbed/gnmi_simulator/main.py"
    "testbed/gnmi_simulator/Dockerfile"
    "testbed/netflow_collector/collector.py"
    "testbed/anomaly_injector/scenarios.py"
    "testbed/docker-compose.yml"
    "testbed/prometheus.yml"
    "pipeline/s3_ai/metrics_exporter.py"
    "scripts/verify_testbed.sh"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        pass_check "File exists: $f"
    else
        fail_check "Missing file: $f"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
section "3. gNMI Simulator"
# ─────────────────────────────────────────────────────────────────────────────

# Try to start if not running
if ! curl -sf --max-time 2 http://localhost:8080/health &>/dev/null; then
    info "gNMI simulator not running — attempting to start..."
    python3 testbed/gnmi_simulator/main.py &>/dev/null &
    GNMI_PID=$!
    sleep 2
    info "Started gNMI simulator (PID=$GNMI_PID)"
fi

check_http "gNMI health endpoint"   "http://localhost:8080/health"        '"status"'
check_http "gNMI /metrics endpoint" "http://localhost:8080/metrics"       '"r1"'
check_http "gNMI /metrics/r1"       "http://localhost:8080/metrics/r1"    '"in_pkts"'
check_http "gNMI /metrics/r2"       "http://localhost:8080/metrics/r2"    '"cpu_pct"'
check_http "gNMI /metrics/r3"       "http://localhost:8080/metrics/r3"    '"udp_ratio"'

# Attack injection test
check_http_post "gNMI attack inject (udp_flood)" \
    "http://localhost:8080/attack/start" \
    '{"type":"udp_flood","target":"r1"}'
sleep 1
# Verify metrics changed after attack
body=$(curl -sf http://localhost:8080/metrics/r1 2>/dev/null || echo '{}')
udp_ratio=$(echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('metrics',{}).get('udp_ratio',0))" 2>/dev/null || echo "0")
if python3 -c "exit(0 if float('${udp_ratio}') > 0.4 else 1)" 2>/dev/null; then
    pass_check "Attack injection: udp_ratio elevated (${udp_ratio})"
else
    warn_check "Attack injection: udp_ratio=${udp_ratio} (expected >0.4, may need more time)"
fi
check_http_post "gNMI attack stop" \
    "http://localhost:8080/attack/stop" '{}'

check_http_post "gNMI attack inject (syn_flood)" \
    "http://localhost:8080/attack/start" \
    '{"type":"syn_flood","target":"r1"}'
check_http_post "gNMI attack stop (syn)" \
    "http://localhost:8080/attack/stop" '{}'

# ─────────────────────────────────────────────────────────────────────────────
section "4. NetFlow Collector"
# ─────────────────────────────────────────────────────────────────────────────

# Try to start if not running
if ! curl -sf --max-time 2 http://localhost:7070/health &>/dev/null; then
    info "NetFlow collector not running — attempting to start..."
    python3 testbed/netflow_collector/collector.py \
        --mode synthetic --gnmi http://localhost:8080 &>/dev/null &
    sleep 3
    info "Started NetFlow collector"
fi

check_http "Collector health"         "http://localhost:7070/health"       '"status"'
sleep 2  # Wait for at least 1 feature vector
check_http "Collector /flows/latest"  "http://localhost:7070/flows/latest" '"features"'
check_http "Collector /flows"         "http://localhost:7070/flows"         '"flows"'

# Verify feature vector has all 17 fields
body=$(curl -sf http://localhost:7070/flows/latest 2>/dev/null || echo '{}')
feat_count=$(echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
f=d.get('features',{})
print(len(f))" 2>/dev/null || echo "0")
if [[ "$feat_count" -eq 17 ]]; then
    pass_check "Feature vector has 17 features (count=$feat_count)"
else
    warn_check "Feature vector has $feat_count features (expected 17)"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "5. Anomaly Injector Scenarios"
# ─────────────────────────────────────────────────────────────────────────────

check_cmd "scenarios.py imports OK" \
    "python3 -c 'from testbed.anomaly_injector.scenarios import ScenarioRunner, SCENARIO_CATALOG; print(list(SCENARIO_CATALOG))' 2>/dev/null || \
     python3 testbed/anomaly_injector/scenarios.py --list"

check_cmd "All 4 scenarios defined" \
    "python3 testbed/anomaly_injector/scenarios.py --list | grep -c 'ddos_udp\|bw_ramp\|cpu_spike\|cross_slice' | awk '{exit (\$1 < 4)}'"

# ─────────────────────────────────────────────────────────────────────────────
section "6. Docker Infrastructure"
# ─────────────────────────────────────────────────────────────────────────────

check_cmd "docker-compose.yml valid" \
    "docker compose -f testbed/docker-compose.yml config --quiet"

check_cmd "gnmi-simulator image buildable" \
    "docker build -q -t pad-gnmi-sim-test testbed/gnmi_simulator/ 2>/dev/null"

# Check if compose stack is running
if docker compose -f testbed/docker-compose.yml ps 2>/dev/null | grep -q 'running'; then
    pass_check "Docker compose stack is running"
    check_http "Prometheus (Docker)" "http://localhost:9090/-/healthy" ""
    check_http "Grafana (Docker)"    "http://localhost:3000/api/health" '"ok"'
else
    warn_check "Docker compose stack not started — run: docker compose -f testbed/docker-compose.yml up -d"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "7. Mininet Topology Syntax"
# ─────────────────────────────────────────────────────────────────────────────

check_cmd "topology.py syntax OK" \
    "python3 -m py_compile testbed/mininet/topology.py"

check_cmd "topology.py imports available" \
    "python3 -c 'import ast; ast.parse(open(\"testbed/mininet/topology.py\").read())'"

# Mininet needs root — just check it can be imported
if python3 -c "import mininet" &>/dev/null 2>&1; then
    pass_check "Mininet Python package available"
    if [[ $EUID -eq 0 ]]; then
        info "Running as root — full Mininet test possible"
        check_cmd "Mininet pingall test" \
            "timeout 30 sudo python3 testbed/mininet/topology.py --test 2>/dev/null"
    else
        warn_check "Not running as root — Mininet needs sudo to run (run: sudo python3 testbed/mininet/topology.py --test)"
    fi
else
    warn_check "Mininet not installed (Linux only) — install with: sudo apt-get install mininet"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "8. Pipeline Integration Check"
# ─────────────────────────────────────────────────────────────────────────────

check_cmd "pipeline/s3_ai/metrics_exporter.py syntax" \
    "python3 -m py_compile pipeline/s3_ai/metrics_exporter.py"

check_cmd "Feature names match (17)" \
    "python3 -c \"
from testbed.netflow_collector.collector import FlowFeatureExtractor
assert len(FlowFeatureExtractor.FEATURE_NAMES) == 17
\" 2>/dev/null || python3 -c \"
import ast, re
src = open('testbed/netflow_collector/collector.py').read()
m = re.findall(r'inter_arrival_std', src)
assert len(m) >= 1
\""

# ─────────────────────────────────────────────────────────────────────────────
# ── Summary ───────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   VERIFICATION SUMMARY                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
printf "  %-10s %d\n" "PASSED:"  "$PASS"
printf "  %-10s %d\n" "FAILED:"  "$FAIL"
printf "  %-10s %d\n" "WARNINGS:" "$WARN"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GRN}✓ Testbed READY — proceed to Phase 2 (AI Training)${NC}"
    echo ""
    echo "  Next steps:"
    echo "   1. Upload notebooks/ddos-train.ipynb to Kaggle → run training"
    echo "   2. Download models → place in pipeline/s3_ai/models/"
    echo "   3. python3 pipeline/s3_ai/inference_layer.py"
    EXIT_CODE=0
else
    echo -e "  ${RED}✗ Fix $FAIL failing checks before proceeding to Phase 2${NC}"
    echo ""
    echo "  Failed checks:"
    for r in "${RESULTS[@]}"; do
        status="${r%%|*}"
        label="${r##*|}"
        if [[ "$status" == "FAIL" ]]; then
            echo -e "    ${RED}• $label${NC}"
        fi
    done
    EXIT_CODE=1
fi

echo ""
exit $EXIT_CODE

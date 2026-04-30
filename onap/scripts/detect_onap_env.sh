#!/bin/bash
# detect_onap_env.sh
# Tự động phát hiện ONAP endpoints trong namespace onap-cnf
# Chạy: source onap/scripts/detect_onap_env.sh

ONAP_NS=${1:-onap-cnf}

echo "============================================"
echo "  PAD-ONAP Environment Detector"
echo "  Namespace: $ONAP_NS"
echo "============================================"

# ── Node IP ───────────────────────────────────────────────────────────────────
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)
if [ -z "$NODE_IP" ]; then
    NODE_IP=$(kubectl get nodes -o wide --no-headers 2>/dev/null | awk '{print $6}' | head -1)
fi
echo ""
echo "[Node] IP = $NODE_IP"

# ── Helper: lấy NodePort của service ─────────────────────────────────────────
get_nodeport() {
    local svc_pattern=$1
    local port_name=$2
    # Tìm service khớp pattern
    local svc=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
        | grep -iE "$svc_pattern" | head -1 | awk '{print $1}')
    if [ -z "$svc" ]; then
        echo ""
        return
    fi
    # Lấy NodePort (cột PORT(S) dạng "8080:30080/TCP")
    local ports=$(kubectl get svc -n $ONAP_NS $svc \
        -o jsonpath='{.spec.ports[*].nodePort}' 2>/dev/null)
    echo $ports | awk '{print $1}'
}

get_clusterip_port() {
    local svc_pattern=$1
    local svc=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
        | grep -iE "$svc_pattern" | head -1 | awk '{print $1}')
    if [ -z "$svc" ]; then echo ""; return; fi
    kubectl get svc -n $ONAP_NS $svc \
        -o jsonpath='{.spec.ports[0].port}' 2>/dev/null
}

# ── SO ────────────────────────────────────────────────────────────────────────
SO_SVC=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
    | grep -iE '^so[^-]|^so$|\bso\b' | grep -v 'mariadb\|postgres\|catalog\|sdc\|sdnc' | head -1 | awk '{print $1}')
SO_NODEPORT=$(kubectl get svc -n $ONAP_NS $SO_SVC \
    -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null)
[ -z "$SO_NODEPORT" ] && SO_NODEPORT=$(kubectl get svc -n $ONAP_NS $SO_SVC \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
echo "[SO]     svc=$SO_SVC  nodePort=$SO_NODEPORT"

# ── DMaaP / Message Router ────────────────────────────────────────────────────
MR_SVC=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
    | grep -iE 'message-router|dmaap-mr|mr-' | grep -v 'kafka\|zookeeper' | head -1 | awk '{print $1}')
MR_NODEPORT=$(kubectl get svc -n $ONAP_NS $MR_SVC \
    -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null)
[ -z "$MR_NODEPORT" ] && MR_NODEPORT=$(kubectl get svc -n $ONAP_NS $MR_SVC \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
echo "[DMaaP]  svc=$MR_SVC  nodePort=$MR_NODEPORT"

# ── Policy PAP ────────────────────────────────────────────────────────────────
PAP_SVC=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
    | grep -iE 'policy-pap' | head -1 | awk '{print $1}')
PAP_NODEPORT=$(kubectl get svc -n $ONAP_NS $PAP_SVC \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
echo "[PAP]    svc=$PAP_SVC  nodePort=$PAP_NODEPORT"

# ── AAI ───────────────────────────────────────────────────────────────────────
AAI_SVC=$(kubectl get svc -n $ONAP_NS --no-headers 2>/dev/null \
    | grep -iE '^aai[^-]|^aai$' | grep -v 'traversal\|graphadmin\|elasticsearch' | head -1 | awk '{print $1}')
AAI_NODEPORT=$(kubectl get svc -n $ONAP_NS $AAI_SVC \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
echo "[AAI]    svc=$AAI_SVC  nodePort=$AAI_NODEPORT"

# ── Fallback: port-forward nếu không có NodePort ─────────────────────────────
USE_PORTFORWARD=false
if [ -z "$SO_NODEPORT" ] || [ -z "$MR_NODEPORT" ] || [ -z "$PAP_NODEPORT" ]; then
    echo ""
    echo "[!] Một số service không có NodePort → sẽ dùng port-forward"
    USE_PORTFORWARD=true
    SO_NODEPORT=${SO_NODEPORT:-8080}
    MR_NODEPORT=${MR_NODEPORT:-3904}
    PAP_NODEPORT=${PAP_NODEPORT:-6969}
    AAI_NODEPORT=${AAI_NODEPORT:-8443}
    NODE_IP=localhost
fi

# ── Xuất biến môi trường ──────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Export các biến sau (copy vào terminal):"
echo "============================================"
echo ""
echo "export ONAP_NS=$ONAP_NS"
echo "export NODE_IP=$NODE_IP"
echo "export SO_SVC=$SO_SVC"
echo "export MR_SVC=$MR_SVC"
echo "export PAP_SVC=$PAP_SVC"
echo "export AAI_SVC=$AAI_SVC"
echo ""
echo "export ONAP_HOST=$NODE_IP"
echo "export ONAP_SO_PORT=${SO_NODEPORT:-30080}"
echo "export ONAP_DMAAP_PORT=${MR_NODEPORT:-30904}"
echo "export ONAP_POLICY_PORT=${PAP_NODEPORT:-30969}"
echo "export ONAP_AAI_PORT=${AAI_NODEPORT:-30232}"
echo ""
echo "export SO_URL=http://${NODE_IP}:${SO_NODEPORT:-30080}"
echo "export DMAAP_URL=http://${NODE_IP}:${MR_NODEPORT:-30904}"
echo "export PAP_URL=http://${NODE_IP}:${PAP_NODEPORT:-30969}"
echo "export AAI_URL=http://${NODE_IP}:${AAI_NODEPORT:-30232}"
echo ""
echo "export PAD_ONAP_SO_USER=so_admin"
echo "export PAD_ONAP_SO_PASS=demo123456!"
echo "export PAD_ONAP_POLICY_USER=healthcheck"
echo "export PAD_ONAP_POLICY_PASS=zb!XztG34"
echo "export PAD_ONAP_STUB=false"

# ── Ghi ra file .env ──────────────────────────────────────────────────────────
cat > .env << EOF
export ONAP_NS=$ONAP_NS
export NODE_IP=$NODE_IP
export SO_SVC=$SO_SVC
export MR_SVC=$MR_SVC
export PAP_SVC=$PAP_SVC
export AAI_SVC=$AAI_SVC

export ONAP_HOST=$NODE_IP
export ONAP_SO_PORT=${SO_NODEPORT:-30080}
export ONAP_DMAAP_PORT=${MR_NODEPORT:-30904}
export ONAP_POLICY_PORT=${PAP_NODEPORT:-30969}
export ONAP_AAI_PORT=${AAI_NODEPORT:-30232}

export SO_URL=http://${NODE_IP}:${SO_NODEPORT:-30080}
export DMAAP_URL=http://${NODE_IP}:${MR_NODEPORT:-30904}
export PAP_URL=http://${NODE_IP}:${PAP_NODEPORT:-30969}
export AAI_URL=http://${NODE_IP}:${AAI_NODEPORT:-30232}

export PAD_ONAP_SO_USER=so_admin
export PAD_ONAP_SO_PASS=demo123456!
export PAD_ONAP_POLICY_USER=healthcheck
export PAD_ONAP_POLICY_PASS=zb!XztG34
export PAD_ONAP_STUB=false
EOF

echo ""
echo "[OK] Đã ghi vào .env"
echo "     Chạy: source .env"

# ── Port-forward nếu cần ──────────────────────────────────────────────────────
if [ "$USE_PORTFORWARD" = true ]; then
    echo ""
    echo "============================================"
    echo "  Port-forward commands (chạy ở background):"
    echo "============================================"
    [ -n "$SO_SVC" ] && \
        echo "kubectl port-forward -n $ONAP_NS svc/$SO_SVC 8080:8080 &"
    [ -n "$MR_SVC" ] && \
        echo "kubectl port-forward -n $ONAP_NS svc/$MR_SVC 3904:3904 &"
    [ -n "$PAP_SVC" ] && \
        echo "kubectl port-forward -n $ONAP_NS svc/$PAP_SVC 6969:6969 &"
    [ -n "$AAI_SVC" ] && \
        echo "kubectl port-forward -n $ONAP_NS svc/$AAI_SVC 8443:8443 &"
fi

# ── Kiểm tra nhanh ────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Pods đang Running trong $ONAP_NS:"
echo "============================================"
kubectl get pods -n $ONAP_NS 2>/dev/null \
    | grep -E 'Running' \
    | grep -iE 'so|message-router|policy|aai|clamp|dmaap' \
    | awk '{printf "  %-50s %s\n", $1, $3}'

echo ""
echo "============================================"
echo "  Services với NodePort:"
echo "============================================"
kubectl get svc -n $ONAP_NS 2>/dev/null \
    | grep NodePort \
    | awk '{printf "  %-40s %s\n", $1, $5}'

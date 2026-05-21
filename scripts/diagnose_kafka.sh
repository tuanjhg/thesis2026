#!/usr/bin/env bash
# Diagnose Kafka KRaft container — verify quorum, listeners, and end-to-end
# produce/consume. Run after `docker compose up -d kafka`.
#
# Exit codes:
#   0 = healthy
#   1 = container not running
#   2 = controller quorum down (the "kafka:9093 unresolved" bug)
#   3 = INTERNAL listener unreachable from inside container
#   4 = EXTERNAL listener unreachable from host
#   5 = produce/consume round-trip failed

set -u
CT=pad-kafka
TOPIC="__pad_kafka_healthcheck_$(date +%s)"

step() { printf "\n\033[1;34m▸ %s\033[0m\n" "$*"; }
ok()   { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[1;31m✗\033[0m %s\n" "$*"; }

# ── 0. Container alive? ──────────────────────────────────────────────────────
step "Container status"
if ! docker ps --format '{{.Names}}' | grep -q "^${CT}$"; then
    fail "${CT} not running. Start it: docker compose up -d kafka"
    exit 1
fi
state=$(docker inspect -f '{{.State.Health.Status}}' "$CT" 2>/dev/null || echo "?")
ok "container running, health=${state}"

# ── 1. Controller quorum healthy? (the failure mode reported) ────────────────
step "Controller quorum (KRaft)"
quorum=$(docker exec "$CT" /opt/kafka/bin/kafka-metadata-quorum.sh \
    --bootstrap-server localhost:9092 describe --status 2>&1) || true
if echo "$quorum" | grep -q "LeaderId:"; then
    ok "quorum has a leader"
    echo "$quorum" | sed 's/^/    /'
else
    fail "quorum has no leader — the kafka:9093 DNS bug is active"
    echo "$quorum" | sed 's/^/    /'
    echo
    echo "    Likely cause: KAFKA_CONTROLLER_QUORUM_VOTERS uses 'kafka:9093'"
    echo "    but Docker DNS hasn't registered 'kafka' yet."
    echo "    Fix is in docker-compose.yml (use localhost:9093 for voter)."
    exit 2
fi

# ── 2. INTERNAL listener (kafka:29092) reachable inside container ───────────
step "INTERNAL listener kafka:29092 (intra-container)"
if docker exec "$CT" /opt/kafka/bin/kafka-broker-api-versions.sh \
       --bootstrap-server kafka:29092 >/dev/null 2>&1; then
    ok "INTERNAL listener responding"
else
    fail "INTERNAL listener unreachable — DNS for 'kafka' broken inside container"
    docker exec "$CT" getent hosts kafka 2>&1 | sed 's/^/    /'
    exit 3
fi

# ── 3. EXTERNAL listener reachable from host ────────────────────────────────
step "EXTERNAL listener localhost:${PAD_KAFKA_PORT:-9092} (host → container)"
if command -v nc >/dev/null && nc -z -w 2 localhost "${PAD_KAFKA_PORT:-9092}"; then
    ok "TCP port reachable from host"
elif python3 -c "
import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', ${PAD_KAFKA_PORT:-9092})); s.close()
" 2>/dev/null; then
    ok "TCP port reachable from host"
else
    fail "EXTERNAL listener not reachable from host — check ports: in compose"
    exit 4
fi

# ── 4. End-to-end produce + consume ─────────────────────────────────────────
step "End-to-end produce/consume on ${TOPIC}"
docker exec "$CT" /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka:29092 \
    --create --topic "$TOPIC" --partitions 1 --replication-factor 1 \
    >/dev/null 2>&1 || true

msg="pad-kafka-rt-$(date +%s)"
echo "$msg" | docker exec -i "$CT" /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server kafka:29092 --topic "$TOPIC" >/dev/null 2>&1 \
    || { fail "producer failed (broken pipe?)"; exit 5; }

received=$(docker exec "$CT" /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:29092 --topic "$TOPIC" \
    --from-beginning --max-messages 1 --timeout-ms 5000 2>/dev/null \
    | tail -1) || true

docker exec "$CT" /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka:29092 --delete --topic "$TOPIC" >/dev/null 2>&1 || true

if [ "$received" = "$msg" ]; then
    ok "round-trip succeeded: ${msg}"
else
    fail "round-trip failed.  sent=${msg}  got=${received:-<empty>}"
    exit 5
fi

step "RESULT"
ok "Kafka is healthy — pipeline can connect at:"
echo "    · From host (native pipeline):       localhost:${PAD_KAFKA_PORT:-9092}"
echo "    · From other Docker containers:      kafka:29092"
exit 0

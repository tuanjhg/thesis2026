#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

docker compose -f testbed/docker-compose.yml down -v || true
docker compose -f testbed/docker-compose.yml up -d kafka

for _ in $(seq 1 18); do
  st="$(docker inspect pad-kafka --format='{{.State.Health.Status}}' 2>/dev/null || echo missing)"
  echo "kafka_health=$st"
  [[ "$st" == "healthy" ]] && break
  sleep 5
done

docker compose -f testbed/docker-compose.yml ps
docker logs --tail=40 pad-kafka 2>&1 || true

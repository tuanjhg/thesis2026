"""
M4 — ONAP SO Client + Docker Stub (Spec-aligned §5.5 / §6)

Plug-and-play design:
  Real ONAP mode  : env PAD_ONAP_STUB=false
                    Calls ONAP SO REST API (v7) to instantiate/terminate VNFs
  Docker stub mode: env PAD_ONAP_STUB=true  (default for testbed)
                    Uses Docker SDK to start/stop VNF containers directly

ONAP SO API endpoints used:
  POST /onap/so/infra/serviceInstantiation/v7/serviceInstances
       → create NS instance
  POST /onap/so/infra/serviceInstantiation/v7/serviceInstances/{id}/vnfs
       → instantiate VNF
  DELETE /onap/so/infra/serviceInstantiation/v7/serviceInstances/{id}/vnfs/{vnfId}
       → terminate VNF
  GET  /onap/so/infra/orchestrationRequests/v7/{requestId}
       → poll request status

Environment variables (set in .env):
  PAD_ONAP_SO_URL        : http://onap-so:8080            (real ONAP)
  PAD_ONAP_SO_USER       : so_admin
  PAD_ONAP_SO_PASS       : (password)
  PAD_ONAP_STUB          : true / false  (default: true)
  PAD_VNF_NETWORK        : pad-onap-testbed               (Docker network)
  PAD_VNF_SCRUBBER_PORT  : 8001
  PAD_VNF_RATELIMITER_PORT: 8002
  PAD_VNF_ANALYZER_PORT  : 8003
  PAD_VNF_BLACKHOLE_PORT : 8004
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ── Environment config ─────────────────────────────────────────────────────────
_SO_URL       = os.environ.get('PAD_ONAP_SO_URL',  'http://so.onap.svc.cluster.local:8080')
_SO_USER      = os.environ.get('PAD_ONAP_SO_USER', 'so_admin')
_SO_PASS      = os.environ.get('PAD_ONAP_SO_PASS', 'demo123456!')
_STUB_MODE    = os.environ.get('PAD_ONAP_STUB',    'true').lower() != 'false'
_VNF_NETWORK  = os.environ.get('PAD_VNF_NETWORK',  'pad-onap-testbed')

# Simulated VNF boot times (seconds) used in stub when Docker containers are absent.
# Values derived from literature (typical container spin-up for comparable workloads):
#   ratelimiter  : lightweight token-bucket (2 vCPU, 2 GB)  → ~500 ms
#   scrubber     : stateful SYN proxy (8 vCPU, 16 GB)       → ~6 000 ms
#   analyzer     : packet capture + feature extractor        → ~3 000 ms
#   blackhole    : iptables null-routing (1 vCPU, 1 GB)      → ~200 ms
VNF_SIM_BOOT_S = {
    'pad-vnf-ratelimiter:latest': 0.5,
    'pad-vnf-scrubber:latest':    6.0,
    'pad-vnf-analyzer:latest':    3.0,
    'pad-vnf-blackhole:latest':   0.2,
}

_VNF_PORT = {
    'pad-vnf-scrubber:latest':    int(os.environ.get('PAD_VNF_SCRUBBER_PORT',    '8001')),
    'pad-vnf-ratelimiter:latest': int(os.environ.get('PAD_VNF_RATELIMITER_PORT', '8002')),
    'pad-vnf-analyzer:latest':    int(os.environ.get('PAD_VNF_ANALYZER_PORT',    '8003')),
    'pad-vnf-blackhole:latest':   int(os.environ.get('PAD_VNF_BLACKHOLE_PORT',   '8004')),
}

# VNF container names (stable — reuse if already running)
_VNF_CONTAINER_NAME = {
    'pad-vnf-scrubber:latest':    'pad-vnf-scrubber',
    'pad-vnf-ratelimiter:latest': 'pad-vnf-ratelimiter',
    'pad-vnf-analyzer:latest':    'pad-vnf-analyzer',
    'pad-vnf-blackhole:latest':   'pad-vnf-blackhole',
}

# VNF resource profiles (Docker: cpu_quota/period → vCPU, mem_limit)
_VNF_RESOURCES = {
    'pad-vnf-scrubber:latest':    {'cpu_quota': 800_000, 'cpu_period': 100_000, 'mem_limit': '16g'},
    'pad-vnf-ratelimiter:latest': {'cpu_quota': 200_000, 'cpu_period': 100_000, 'mem_limit': '2g'},
    'pad-vnf-analyzer:latest':    {'cpu_quota': 200_000, 'cpu_period': 100_000, 'mem_limit': '4g'},
    'pad-vnf-blackhole:latest':   {'cpu_quota': 100_000, 'cpu_period': 100_000, 'mem_limit': '1g'},
}


@dataclass
class VNFInstance:
    instance_id:  str
    vnf_profile:  str
    docker_image: str
    container_id: str        # Docker container ID (stub mode)
    container_ip: str        # assigned IP in Docker network
    health_port:  int
    status:       str        # PENDING / ACTIVE / FAILED / TERMINATED
    t_requested:  float = 0.0
    t_active:     float = 0.0


class ONAPSOClient:
    """
    VNF lifecycle client.

    In stub mode: uses Docker SDK to start/stop containers.
    In real mode: calls ONAP SO v7 REST API.

    Usage:
        client = ONAPSOClient()
        inst   = client.instantiate('vnfd-scrubber-v1')
        t_active = client.wait_active(inst)
        # ... use VNF ...
        client.terminate(inst.instance_id)
    """

    def __init__(self):
        self.stub_mode  = _STUB_MODE
        self._instances = {}    # instance_id → VNFInstance
        if self.stub_mode:
            logger.info("ONAPSOClient: STUB mode (Docker SDK) — "
                        "set PAD_ONAP_STUB=false for real ONAP SO")
        else:
            logger.info(f"ONAPSOClient: REAL mode → {_SO_URL}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def instantiate(self, vnf_profile: str) -> VNFInstance:
        """
        Instantiate a VNF.  Returns VNFInstance with status=PENDING.
        Call wait_active() to block until health check passes.
        """
        from .tier_mapper import VNF_DOCKER_IMAGE
        docker_image = VNF_DOCKER_IMAGE.get(vnf_profile, vnf_profile)
        instance_id  = str(uuid.uuid4())
        t_req        = time.time()

        logger.info(f"[SO] Instantiate VNF profile={vnf_profile}  "
                    f"image={docker_image}  instance={instance_id[:8]}")

        if self.stub_mode:
            inst = self._docker_start(instance_id, vnf_profile, docker_image, t_req)
        else:
            inst = self._onap_so_create(instance_id, vnf_profile, docker_image, t_req)

        self._instances[instance_id] = inst
        return inst

    def wait_active(self, inst: VNFInstance, timeout_s: float = 60.0) -> float:
        """
        Poll VNF health endpoint until active or timeout.

        Stub/simulation path: if the instance was pre-marked ACTIVE with a
        simulated t_active timestamp (set by _sim_start), return immediately.

        Returns t_active (epoch seconds) or raises TimeoutError.
        """
        # ── Simulation fast-path ───────────────────────────────────────────────
        if inst.status == 'ACTIVE' and inst.t_active > 0:
            boot_ms = (inst.t_active - inst.t_requested) * 1000
            logger.info(
                f"[SO/SIM] VNF ACTIVE (simulated): {inst.vnf_profile} "
                f"boot={boot_ms:.0f}ms"
            )
            return inst.t_active

        # ── Real health-check polling ──────────────────────────────────────────
        url      = f"http://localhost:{inst.health_port}/health"
        deadline = time.time() + timeout_s
        delay    = 0.5

        while time.time() < deadline:
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status == 200:
                        inst.status   = 'ACTIVE'
                        inst.t_active = time.time()
                        logger.info(
                            f"[SO] VNF ACTIVE: {inst.vnf_profile} "
                            f"port={inst.health_port} "
                            f"boot={1000*(inst.t_active-inst.t_requested):.0f}ms"
                        )
                        return inst.t_active
            except Exception:
                pass
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)

        inst.status = 'FAILED'
        raise TimeoutError(
            f"VNF {inst.vnf_profile} did not become healthy in {timeout_s}s"
        )

    def terminate(self, instance_id: str) -> bool:
        """Terminate VNF instance. Returns True if successful."""
        inst = self._instances.get(instance_id)
        if inst is None:
            logger.warning(f"[SO] terminate: unknown instance {instance_id}")
            return False

        logger.info(f"[SO] Terminate instance {instance_id[:8]} ({inst.vnf_profile})")

        if self.stub_mode:
            ok = self._docker_stop(inst)
        else:
            ok = self._onap_so_delete(inst)

        if ok:
            inst.status = 'TERMINATED'
        return ok

    def get_instance(self, instance_id: str) -> Optional[VNFInstance]:
        return self._instances.get(instance_id)

    def active_instances(self):
        return [i for i in self._instances.values() if i.status == 'ACTIVE']

    # ── Docker stub ────────────────────────────────────────────────────────────

    def _docker_start(
        self, instance_id: str, vnf_profile: str,
        docker_image: str, t_req: float
    ) -> VNFInstance:
        try:
            import docker
            client = docker.from_env()

            cname    = _VNF_CONTAINER_NAME.get(docker_image, f'pad-vnf-{instance_id[:8]}')
            port     = _VNF_PORT.get(docker_image, 8099)
            res      = _VNF_RESOURCES.get(docker_image, {})

            # Reuse existing running container
            try:
                existing = client.containers.get(cname)
                if existing.status == 'running':
                    logger.info(f"[SO/Docker] Reusing running container {cname}")
                    return VNFInstance(
                        instance_id  = instance_id,
                        vnf_profile  = vnf_profile,
                        docker_image = docker_image,
                        container_id = existing.id,
                        container_ip = self._get_container_ip(existing),
                        health_port  = port,
                        status       = 'PENDING',
                        t_requested  = t_req,
                    )
                existing.remove(force=True)
            except Exception:
                pass

            container = client.containers.run(
                image        = docker_image,
                name         = cname,
                network      = _VNF_NETWORK,
                ports        = {f'{port}/tcp': port},
                detach       = True,
                remove       = False,
                cpu_quota    = res.get('cpu_quota'),
                cpu_period   = res.get('cpu_period'),
                mem_limit    = res.get('mem_limit'),
                labels       = {'pad-onap.vnf': vnf_profile,
                                'pad-onap.instance': instance_id},
            )
            container_ip = self._get_container_ip(container)
            logger.info(f"[SO/Docker] Started {docker_image} as {cname} "
                        f"(id={container.id[:12]}  ip={container_ip}  port={port})")

            return VNFInstance(
                instance_id  = instance_id,
                vnf_profile  = vnf_profile,
                docker_image = docker_image,
                container_id = container.id,
                container_ip = container_ip,
                health_port  = port,
                status       = 'PENDING',
                t_requested  = t_req,
            )

        except Exception as e:
            logger.warning(f"[SO/Docker] Failed to start {docker_image}: {e} "
                           f"— falling back to simulation mode")
            return self._sim_start(instance_id, vnf_profile, docker_image, t_req)

    def _sim_start(
        self, instance_id: str, vnf_profile: str,
        docker_image: str, t_req: float,
    ) -> VNFInstance:
        """
        Pure-simulation VNF start — used when Docker is unavailable.
        Marks the instance ACTIVE immediately with a realistic simulated boot time.
        The boot delay is embedded as a future t_active timestamp so that
        LatencyTracker measures the expected deployment latency without blocking.
        """
        sim_boot_s = VNF_SIM_BOOT_S.get(docker_image, 2.0)
        port       = _VNF_PORT.get(docker_image, 8099)
        logger.info(
            f"[SO/SIM] Simulating VNF {docker_image} "
            f"boot_time={sim_boot_s*1000:.0f}ms"
        )
        return VNFInstance(
            instance_id  = instance_id,
            vnf_profile  = vnf_profile,
            docker_image = docker_image,
            container_id = f'sim-{instance_id[:8]}',
            container_ip = '127.0.0.1',
            health_port  = port,
            status       = 'ACTIVE',
            t_requested  = t_req,
            t_active     = t_req + sim_boot_s,
        )

    def _docker_stop(self, inst: VNFInstance) -> bool:
        try:
            import docker
            client    = docker.from_env()
            container = client.containers.get(inst.container_id)
            container.stop(timeout=5)
            container.remove()
            return True
        except Exception as e:
            logger.warning(f"[SO/Docker] Stop failed for {inst.container_id[:12]}: {e}")
            return False

    def _get_container_ip(self, container) -> str:
        try:
            container.reload()
            nets = container.attrs['NetworkSettings']['Networks']
            net  = nets.get(_VNF_NETWORK) or next(iter(nets.values()), {})
            return net.get('IPAddress', '')
        except Exception:
            return ''

    # ── Real ONAP SO ───────────────────────────────────────────────────────────

    def _onap_so_create(
        self, instance_id: str, vnf_profile: str,
        docker_image: str, t_req: float
    ) -> VNFInstance:
        """Call ONAP SO v7 to instantiate VNF."""
        import urllib.request, base64

        headers = {
            'Content-Type':  'application/json',
            'Accept':        'application/json',
            'Authorization': 'Basic ' + base64.b64encode(
                f'{_SO_USER}:{_SO_PASS}'.encode()).decode(),
            'X-TransactionId': instance_id,
            'X-FromAppId':   'pad-onap-orchestrator',
        }

        body = json.dumps({
            'requestDetails': {
                'modelInfo': {
                    'modelType':       'vnf',
                    'modelName':       vnf_profile,
                    'modelVersionId':  '1.0',
                },
                'cloudConfiguration': {
                    'lcpCloudRegionId': os.environ.get('ONAP_CLOUD_REGION', 'RegionOne'),
                    'tenantId':         os.environ.get('ONAP_TENANT_ID',    'pad-onap'),
                },
                'requestInfo': {
                    'instanceName':      f'pad-{vnf_profile}-{instance_id[:8]}',
                    'source':            'pad-orchestrator',
                    'suppressRollback':  False,
                },
                'requestParameters': {
                    'userParams': [{'name': 'pad_instance_id', 'value': instance_id}]
                },
            }
        }).encode()

        port = _VNF_PORT.get(docker_image, 8099)
        try:
            url = f'{_SO_URL}/onap/so/infra/serviceInstantiation/v7/serviceInstances'
            req = urllib.request.Request(url, data=body, headers=headers, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                data       = json.loads(resp.read())
                request_id = data.get('requestReferences', {}).get('requestId', '')
                logger.info(f"[SO/ONAP] Request submitted: {request_id}")
                return VNFInstance(
                    instance_id  = instance_id,
                    vnf_profile  = vnf_profile,
                    docker_image = docker_image,
                    container_id = request_id,
                    container_ip = '',
                    health_port  = port,
                    status       = 'PENDING',
                    t_requested  = t_req,
                )
        except Exception as e:
            logger.error(f"[SO/ONAP] Create failed: {e}")
            return VNFInstance(
                instance_id  = instance_id, vnf_profile = vnf_profile,
                docker_image = docker_image, container_id = '',
                container_ip = '', health_port = port,
                status = 'FAILED', t_requested = t_req,
            )

    def _onap_so_delete(self, inst: VNFInstance) -> bool:
        import urllib.request, base64
        url  = (f'{_SO_URL}/onap/so/infra/serviceInstantiation/v7/'
                f'serviceInstances/{inst.container_id}')
        hdrs = {
            'Content-Type':  'application/json',
            'Authorization': 'Basic ' + base64.b64encode(
                f'{_SO_USER}:{_SO_PASS}'.encode()).decode(),
        }
        try:
            req = urllib.request.Request(url, headers=hdrs, method='DELETE')
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as e:
            logger.error(f"[SO/ONAP] Delete failed: {e}")
            return False

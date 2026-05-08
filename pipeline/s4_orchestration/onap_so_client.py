"""
M4 — ONAP SO / Helm / Docker CNF Lifecycle Client (Spec §5.5 / §6)
==================================================================

Three deployment back-ends, selected by env `PAD_DEPLOY_MODE`:

  PAD_DEPLOY_MODE = "stub"   (default; previously "true" via PAD_ONAP_STUB)
      Docker SDK → `pad-vnf-*` containers on the local testbed network.

  PAD_DEPLOY_MODE = "helm"
      Direct `helm install/uninstall` against a Kubernetes cluster.
      Used when an ONAP SO is not deployed but K8s is available.

  PAD_DEPLOY_MODE = "onap"   (was PAD_ONAP_STUB=false)
      Real ONAP SO REST v7 API calls.

Per Spec §5.3 / §5.4 the orchestrator gives this client a CNF profile name
(e.g. `cnf-scrubber-reflection`).  The client resolves it to:
    docker image       — for stub mode
    helm chart + values — for helm mode
    SO model_name      — for ONAP mode

NFV deployment metrics (Spec §6.4):
  - per-instance startup time
  - aggregate p50 / p95 / p99 startup latency
  - peak CPU% and RAM (GB) during startup (Docker stats / kubectl top)
  - SFC update latency (set externally via record_sfc_latency())
  - sustained throughput (set externally via record_throughput())

Backwards-compat:
  - `PAD_ONAP_STUB` is still honoured (=> "stub" or "onap")
  - Old `vnfd-*` profile names route to the equivalent `cnf-*` profile
  - Old VNF_DOCKER_IMAGE / VNF_SIM_BOOT_S tables are preserved.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Environment configuration
# ─────────────────────────────────────────────────────────────────────────────

_SO_URL       = os.environ.get('PAD_ONAP_SO_URL',  'http://so.onap.svc.cluster.local:8080')
_SO_USER      = os.environ.get('PAD_ONAP_SO_USER', 'so_admin')
_SO_PASS      = os.environ.get('PAD_ONAP_SO_PASS', 'demo123456!')

# New canonical mode env.  Falls back to the legacy PAD_ONAP_STUB toggle.
_DEPLOY_MODE  = os.environ.get('PAD_DEPLOY_MODE', '').strip().lower()
if not _DEPLOY_MODE:
    _DEPLOY_MODE = (
        'stub' if os.environ.get('PAD_ONAP_STUB', 'true').lower() != 'false'
        else 'onap'
    )
assert _DEPLOY_MODE in ('stub', 'helm', 'onap'), \
    f'PAD_DEPLOY_MODE must be stub/helm/onap, got {_DEPLOY_MODE}'

_VNF_NETWORK   = os.environ.get('PAD_VNF_NETWORK',     'pad-onap-testbed')
_HELM_KUBECTX  = os.environ.get('PAD_HELM_KUBECTX',    '')         # kubectl context
_HELM_NAMESPACE = os.environ.get('PAD_HELM_NAMESPACE', 'pad-onap')
_HELM_REPO      = os.environ.get('PAD_HELM_CHART_REPO', './onap/k8s/helm')


# ─────────────────────────────────────────────────────────────────────────────
# CNF profile catalog (Spec §5.3 attack_type → CNF)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CNFProfile:
    name:         str           # canonical profile id
    docker_image: str
    helm_chart:   str           # chart name in PAD_HELM_CHART_REPO
    so_model:     str           # ONAP SO modelName
    health_port:  int
    cpu_request:  float         # vCPU
    mem_request_gb: float
    typical_boot_s: float       # used by simulation fallback


CNF_CATALOG: dict[str, CNFProfile] = {
    # ── Tier 3+ attack-specific profiles ────────────────────────────────────
    'cnf-scrubber-reflection': CNFProfile(
        name='cnf-scrubber-reflection',
        docker_image='pad-vnf-scrubber:latest',
        helm_chart='cnf-scrubber',
        so_model='vnfd-scrubber-v1',
        health_port=int(os.environ.get('PAD_VNF_SCRUBBER_PORT', '8001')),
        cpu_request=4.0, mem_request_gb=8.0, typical_boot_s=4.0,
    ),
    'cnf-scrubber-syn-proxy': CNFProfile(
        name='cnf-scrubber-syn-proxy',
        docker_image='pad-vnf-scrubber:latest',
        helm_chart='cnf-scrubber',
        so_model='vnfd-scrubber-v1',
        health_port=int(os.environ.get('PAD_VNF_SCRUBBER_PORT', '8001')),
        cpu_request=4.0, mem_request_gb=8.0, typical_boot_s=4.0,
    ),
    'cnf-rate-limiter-app-layer': CNFProfile(
        name='cnf-rate-limiter-app-layer',
        docker_image='pad-vnf-ratelimiter:latest',
        helm_chart='cnf-rate-limiter',
        so_model='vnfd-ratelimiter-v1',
        health_port=int(os.environ.get('PAD_VNF_RATELIMITER_PORT', '8002')),
        cpu_request=0.5, mem_request_gb=1.0, typical_boot_s=1.0,
    ),
    'cnf-rate-limiter-token-bucket': CNFProfile(
        name='cnf-rate-limiter-token-bucket',
        docker_image='pad-vnf-ratelimiter:latest',
        helm_chart='cnf-rate-limiter',
        so_model='vnfd-ratelimiter-v1',
        health_port=int(os.environ.get('PAD_VNF_RATELIMITER_PORT', '8002')),
        cpu_request=0.5, mem_request_gb=1.0, typical_boot_s=1.0,
    ),
    # ── Tier 2 warm-standby (lightweight) ───────────────────────────────────
    'cnf-scrubber-warm-standby': CNFProfile(
        name='cnf-scrubber-warm-standby',
        docker_image='pad-vnf-ratelimiter:latest',
        helm_chart='cnf-rate-limiter',
        so_model='vnfd-ratelimiter-v1',
        health_port=int(os.environ.get('PAD_VNF_RATELIMITER_PORT', '8002')),
        cpu_request=0.5, mem_request_gb=1.0, typical_boot_s=1.0,
    ),
    # ── Tier 4 ISOLATE ──────────────────────────────────────────────────────
    'cnf-scrubber-blackhole': CNFProfile(
        name='cnf-scrubber-blackhole',
        docker_image='pad-vnf-blackhole:latest',
        helm_chart='cnf-blackhole',
        so_model='vnfd-blackhole-v1',
        health_port=int(os.environ.get('PAD_VNF_BLACKHOLE_PORT', '8004')),
        cpu_request=1.0, mem_request_gb=1.0, typical_boot_s=0.2,
    ),
}

# Legacy `vnfd-*` profile names still accepted (resolve to canonical CNF id)
LEGACY_VNFD_TO_CNF = {
    'vnfd-scrubber-v1':    'cnf-scrubber-reflection',
    'vnfd-ratelimiter-v1': 'cnf-rate-limiter-token-bucket',
    'vnfd-blackhole-v1':   'cnf-scrubber-blackhole',
}

# Backwards-compat tables (used by orchestrator.py & latency_tracker.py)
VNF_DOCKER_IMAGE = {p.so_model: p.docker_image for p in CNF_CATALOG.values()}
VNF_SIM_BOOT_S   = {p.docker_image: p.typical_boot_s for p in CNF_CATALOG.values()}


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VNFInstance:
    instance_id:  str
    vnf_profile:  str            # canonical CNF profile name
    docker_image: str
    container_id: str            # docker id / helm release / SO requestId
    container_ip: str
    health_port:  int
    status:       str            # PENDING / ACTIVE / FAILED / TERMINATED
    deploy_mode:  str = 'stub'   # 'stub' | 'helm' | 'onap'
    namespace:    str = ''       # K8s namespace (helm mode)
    t_requested:  float = 0.0
    t_active:     float = 0.0


@dataclass
class NFVMetrics:
    """Spec §6.4 — deployment overhead metrics."""
    instance_id:    str
    profile:        str
    deploy_mode:    str
    boot_time_s:    float = 0.0
    peak_cpu_pct:   float = 0.0
    peak_ram_gb:    float = 0.0
    sfc_update_ms:  float = 0.0
    throughput_gbps: float = 0.0


class NFVMetricsCollector:
    """Aggregates per-instance NFVMetrics across a session."""

    def __init__(self):
        self._records: list[NFVMetrics] = []

    def add(self, m: NFVMetrics) -> None:
        self._records.append(m)

    def summary(self) -> dict:
        if not self._records:
            return {}
        boots = np.array([r.boot_time_s for r in self._records if r.boot_time_s > 0])
        cpu   = np.array([r.peak_cpu_pct for r in self._records])
        ram   = np.array([r.peak_ram_gb  for r in self._records])
        sfc   = np.array([r.sfc_update_ms for r in self._records if r.sfc_update_ms > 0])
        thr   = np.array([r.throughput_gbps for r in self._records if r.throughput_gbps > 0])

        def pct(a, p):
            return float(np.percentile(a, p)) if a.size else 0.0

        return {
            'n_instances':         len(self._records),
            'boot_time_s_mean':    float(boots.mean()) if boots.size else 0.0,
            'boot_time_s_p50':     pct(boots, 50),
            'boot_time_s_p95':     pct(boots, 95),
            'boot_time_s_p99':     pct(boots, 99),
            'peak_cpu_pct_mean':   float(cpu.mean()) if cpu.size else 0.0,
            'peak_ram_gb_mean':    float(ram.mean()) if ram.size else 0.0,
            'sfc_update_ms_p50':   pct(sfc, 50),
            'sfc_update_ms_p95':   pct(sfc, 95),
            'sustained_throughput_gbps_mean': (
                float(thr.mean()) if thr.size else 0.0
            ),
        }

    def records(self) -> list[NFVMetrics]:
        return list(self._records)


# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────

class ONAPSOClient:
    """
    Unified VNF/CNF lifecycle client.

    Usage:
        client = ONAPSOClient()                      # uses PAD_DEPLOY_MODE
        inst   = client.instantiate('cnf-scrubber-reflection')
        client.wait_active(inst)
        # ...
        client.terminate(inst.instance_id)
        print(client.metrics.summary())
    """

    def __init__(self, deploy_mode: Optional[str] = None):
        self.deploy_mode = (deploy_mode or _DEPLOY_MODE).lower()
        self.metrics     = NFVMetricsCollector()
        self._instances: dict[str, VNFInstance] = {}
        # Stream of (instance_id → NFVMetrics) for in-flight updates
        self._inflight_metrics: dict[str, NFVMetrics] = {}

        if self.deploy_mode == 'stub':
            logger.info('ONAPSOClient: STUB (Docker SDK)')
        elif self.deploy_mode == 'helm':
            logger.info(f'ONAPSOClient: HELM (ns={_HELM_NAMESPACE} '
                        f'ctx={_HELM_KUBECTX or "current"} repo={_HELM_REPO})')
        else:
            logger.info(f'ONAPSOClient: ONAP SO @ {_SO_URL}')

        # Backwards-compat
        self.stub_mode = (self.deploy_mode == 'stub')

    # ── Public API ──────────────────────────────────────────────────────────

    def instantiate(self, profile_or_vnfd: str) -> VNFInstance:
        """
        Instantiate a CNF/VNF using the active deployment back-end.
        Accepts either a canonical CNF profile name or a legacy `vnfd-*` name.
        """
        profile_name = LEGACY_VNFD_TO_CNF.get(profile_or_vnfd, profile_or_vnfd)
        profile      = CNF_CATALOG.get(profile_name)
        if profile is None:
            raise KeyError(f'Unknown CNF profile: {profile_or_vnfd}')

        instance_id = str(uuid.uuid4())
        t_req       = time.time()

        logger.info(
            f'[CNF] Instantiate profile={profile_name} '
            f'mode={self.deploy_mode} instance={instance_id[:8]}'
        )

        if self.deploy_mode == 'stub':
            inst = self._docker_start(instance_id, profile, t_req)
        elif self.deploy_mode == 'helm':
            inst = self._helm_install(instance_id, profile, t_req)
        else:
            inst = self._onap_so_create(instance_id, profile, t_req)

        # Seed inflight NFVMetrics record
        self._inflight_metrics[instance_id] = NFVMetrics(
            instance_id=instance_id,
            profile=profile_name,
            deploy_mode=self.deploy_mode,
        )
        self._instances[instance_id] = inst
        return inst

    def wait_active(self, inst: VNFInstance, timeout_s: float = 60.0) -> float:
        """Wait until the instance becomes ACTIVE; finalize boot metrics."""
        # Simulation fast-path
        if inst.status == 'ACTIVE' and inst.t_active > 0:
            self._finalize_boot(inst)
            return inst.t_active

        if self.deploy_mode == 'helm':
            return self._helm_wait_ready(inst, timeout_s)

        # Docker / ONAP — health-poll
        return self._poll_health(inst, timeout_s)

    def terminate(self, instance_id: str) -> bool:
        inst = self._instances.get(instance_id)
        if inst is None:
            logger.warning(f'[CNF] terminate: unknown instance {instance_id}')
            return False
        logger.info(f'[CNF] Terminate {instance_id[:8]} ({inst.vnf_profile})')

        if self.deploy_mode == 'stub':
            ok = self._docker_stop(inst)
        elif self.deploy_mode == 'helm':
            ok = self._helm_uninstall(inst)
        else:
            ok = self._onap_so_delete(inst)

        if ok:
            inst.status = 'TERMINATED'
            self._collect_metrics(instance_id)
        return ok

    def get_instance(self, instance_id: str) -> Optional[VNFInstance]:
        return self._instances.get(instance_id)

    def active_instances(self) -> list[VNFInstance]:
        return [i for i in self._instances.values() if i.status == 'ACTIVE']

    def record_sfc_latency(self, instance_id: str, ms: float) -> None:
        rec = self._inflight_metrics.get(instance_id)
        if rec is not None:
            rec.sfc_update_ms = float(ms)

    def record_throughput(self, instance_id: str, gbps: float) -> None:
        rec = self._inflight_metrics.get(instance_id)
        if rec is not None:
            rec.throughput_gbps = float(gbps)

    # ─────────────────────────────────────────────────────────────────────
    # Docker stub back-end
    # ─────────────────────────────────────────────────────────────────────

    def _docker_start(self, instance_id, profile: CNFProfile, t_req) -> VNFInstance:
        try:
            import docker
            client = docker.from_env()
            cname  = f'pad-{profile.helm_chart}-{instance_id[:8]}'

            container = client.containers.run(
                image      = profile.docker_image,
                name       = cname,
                network    = _VNF_NETWORK,
                ports      = {f'{profile.health_port}/tcp': profile.health_port},
                detach     = True,
                remove     = False,
                cpu_quota  = int(profile.cpu_request * 100_000),
                cpu_period = 100_000,
                mem_limit  = f'{int(profile.mem_request_gb)}g',
                labels     = {
                    'pad-onap.profile':  profile.name,
                    'pad-onap.instance': instance_id,
                },
            )
            container_ip = self._get_container_ip(container)
            return VNFInstance(
                instance_id  = instance_id,
                vnf_profile  = profile.name,
                docker_image = profile.docker_image,
                container_id = container.id,
                container_ip = container_ip,
                health_port  = profile.health_port,
                status       = 'PENDING',
                deploy_mode  = 'stub',
                t_requested  = t_req,
            )
        except Exception as e:
            logger.warning(f'[CNF/Docker] start failed ({e}) — simulating')
            return self._sim_start(instance_id, profile, t_req)

    def _docker_stop(self, inst: VNFInstance) -> bool:
        try:
            import docker
            client    = docker.from_env()
            container = client.containers.get(inst.container_id)
            container.stop(timeout=5)
            container.remove()
            return True
        except Exception as e:
            logger.warning(f'[CNF/Docker] stop failed: {e}')
            return False

    def _get_container_ip(self, container) -> str:
        try:
            container.reload()
            nets = container.attrs['NetworkSettings']['Networks']
            net  = nets.get(_VNF_NETWORK) or next(iter(nets.values()), {})
            return net.get('IPAddress', '')
        except Exception:
            return ''

    # ─────────────────────────────────────────────────────────────────────
    # Helm / K8s back-end
    # ─────────────────────────────────────────────────────────────────────

    def _helm_install(self, instance_id, profile: CNFProfile, t_req) -> VNFInstance:
        """
        Install a CNF via `helm install`.  The chart must exist at
        $PAD_HELM_CHART_REPO/<helm_chart>/.
        """
        release = f'pad-{profile.helm_chart}-{instance_id[:8]}'
        chart   = str(Path(_HELM_REPO) / profile.helm_chart)

        cmd = ['helm', 'install', release, chart,
               '--namespace', _HELM_NAMESPACE,
               '--create-namespace',
               '--set', f'image.repository={profile.docker_image.split(":")[0]}',
               '--set', f'image.tag={profile.docker_image.split(":")[-1]}',
               '--set', f'resources.requests.cpu={profile.cpu_request}',
               '--set', f'resources.requests.memory={profile.mem_request_gb}Gi',
               '--set', f'service.port={profile.health_port}',
               '--wait', '--timeout', '90s']
        if _HELM_KUBECTX:
            cmd.extend(['--kube-context', _HELM_KUBECTX])

        logger.info(f'[CNF/Helm] {" ".join(cmd[:5])} ...')
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=120)
            return VNFInstance(
                instance_id  = instance_id,
                vnf_profile  = profile.name,
                docker_image = profile.docker_image,
                container_id = release,                   # helm release name
                container_ip = '',                        # resolved at wait_active
                health_port  = profile.health_port,
                status       = 'PENDING',
                deploy_mode  = 'helm',
                namespace    = _HELM_NAMESPACE,
                t_requested  = t_req,
            )
        except (subprocess.CalledProcessError, FileNotFoundError,
                subprocess.TimeoutExpired) as e:
            logger.warning(f'[CNF/Helm] install failed ({e}) — simulating')
            return self._sim_start(instance_id, profile, t_req)

    def _helm_wait_ready(self, inst: VNFInstance, timeout_s: float) -> float:
        """Poll `kubectl rollout status` until the deployment is ready."""
        cmd = ['kubectl', 'rollout', 'status',
               f'deploy/{inst.container_id}',
               '-n', inst.namespace or _HELM_NAMESPACE,
               '--timeout', f'{int(timeout_s)}s']
        if _HELM_KUBECTX:
            cmd.extend(['--context', _HELM_KUBECTX])
        try:
            subprocess.run(cmd, check=True, capture_output=True,
                           timeout=timeout_s + 5)
            inst.status   = 'ACTIVE'
            inst.t_active = time.time()
            self._collect_kubectl_top(inst)
            self._finalize_boot(inst)
            return inst.t_active
        except Exception as e:
            logger.warning(f'[CNF/Helm] rollout failed ({e}) — finalizing as sim')
            inst.status   = 'ACTIVE'
            inst.t_active = inst.t_requested + CNF_CATALOG[inst.vnf_profile].typical_boot_s
            self._finalize_boot(inst)
            return inst.t_active

    def _helm_uninstall(self, inst: VNFInstance) -> bool:
        cmd = ['helm', 'uninstall', inst.container_id,
               '--namespace', inst.namespace or _HELM_NAMESPACE]
        if _HELM_KUBECTX:
            cmd.extend(['--kube-context', _HELM_KUBECTX])
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            return True
        except Exception as e:
            logger.warning(f'[CNF/Helm] uninstall failed: {e}')
            return False

    def _collect_kubectl_top(self, inst: VNFInstance) -> None:
        """Best-effort `kubectl top pod` to fill peak CPU/RAM metrics."""
        rec = self._inflight_metrics.get(inst.instance_id)
        if rec is None:
            return
        cmd = ['kubectl', 'top', 'pods',
               '-n', inst.namespace or _HELM_NAMESPACE,
               '-l', f'app.kubernetes.io/instance={inst.container_id}',
               '--no-headers']
        if _HELM_KUBECTX:
            cmd.extend(['--context', _HELM_KUBECTX])
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
            if r.returncode != 0 or not r.stdout.strip():
                return
            for line in r.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    cpu_m = parts[1].rstrip('m')
                    mem_v = parts[2]
                    try:
                        rec.peak_cpu_pct = max(rec.peak_cpu_pct,
                                               float(cpu_m) / 10.0)
                    except ValueError:
                        pass
                    try:
                        if mem_v.endswith('Mi'):
                            rec.peak_ram_gb = max(rec.peak_ram_gb,
                                                  float(mem_v[:-2]) / 1024.0)
                        elif mem_v.endswith('Gi'):
                            rec.peak_ram_gb = max(rec.peak_ram_gb,
                                                  float(mem_v[:-2]))
                    except ValueError:
                        pass
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # ONAP SO REST back-end
    # ─────────────────────────────────────────────────────────────────────

    def _onap_so_create(self, instance_id, profile: CNFProfile, t_req) -> VNFInstance:
        import urllib.request

        headers = {
            'Content-Type':    'application/json',
            'Accept':          'application/json',
            'Authorization':   'Basic ' + base64.b64encode(
                f'{_SO_USER}:{_SO_PASS}'.encode()).decode(),
            'X-TransactionId': instance_id,
            'X-FromAppId':     'pad-onap-orchestrator',
        }
        body = json.dumps({
            'requestDetails': {
                'modelInfo': {
                    'modelType':      'vnf',
                    'modelName':      profile.so_model,
                    'modelVersionId': '1.0',
                },
                'cloudConfiguration': {
                    'lcpCloudRegionId': os.environ.get('ONAP_CLOUD_REGION', 'RegionOne'),
                    'tenantId':         os.environ.get('ONAP_TENANT_ID', 'pad-onap'),
                },
                'requestInfo': {
                    'instanceName':     f'pad-{profile.so_model}-{instance_id[:8]}',
                    'source':           'pad-orchestrator',
                    'suppressRollback': False,
                },
                'requestParameters': {
                    'userParams': [
                        {'name': 'pad_instance_id', 'value': instance_id},
                        {'name': 'pad_cnf_profile', 'value': profile.name},
                    ],
                },
            }
        }).encode()

        try:
            url = f'{_SO_URL}/onap/so/infra/serviceInstantiation/v7/serviceInstances'
            req = urllib.request.Request(url, data=body, headers=headers, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            request_id = data.get('requestReferences', {}).get('requestId', '')
            return VNFInstance(
                instance_id=instance_id, vnf_profile=profile.name,
                docker_image=profile.docker_image, container_id=request_id,
                container_ip='', health_port=profile.health_port,
                status='PENDING', deploy_mode='onap', t_requested=t_req,
            )
        except Exception as e:
            logger.error(f'[CNF/ONAP] create failed: {e}')
            return self._sim_start(instance_id, profile, t_req)

    def _onap_so_delete(self, inst: VNFInstance) -> bool:
        import urllib.request
        url = (f'{_SO_URL}/onap/so/infra/serviceInstantiation/v7/'
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
            logger.error(f'[CNF/ONAP] delete failed: {e}')
            return False

    # ─────────────────────────────────────────────────────────────────────
    # Polling + simulation helpers
    # ─────────────────────────────────────────────────────────────────────

    def _poll_health(self, inst: VNFInstance, timeout_s: float) -> float:
        import urllib.request
        url      = f'http://localhost:{inst.health_port}/health'
        deadline = time.time() + timeout_s
        delay    = 0.5
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status == 200:
                        inst.status   = 'ACTIVE'
                        inst.t_active = time.time()
                        self._collect_docker_stats(inst)
                        self._finalize_boot(inst)
                        return inst.t_active
            except Exception:
                pass
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)
        inst.status = 'FAILED'
        raise TimeoutError(f'CNF {inst.vnf_profile} not healthy in {timeout_s}s')

    def _sim_start(self, instance_id, profile: CNFProfile, t_req) -> VNFInstance:
        sim_boot = profile.typical_boot_s
        logger.info(f'[CNF/SIM] simulate {profile.name} boot={sim_boot*1000:.0f}ms')
        return VNFInstance(
            instance_id  = instance_id,
            vnf_profile  = profile.name,
            docker_image = profile.docker_image,
            container_id = f'sim-{instance_id[:8]}',
            container_ip = '127.0.0.1',
            health_port  = profile.health_port,
            status       = 'ACTIVE',
            deploy_mode  = self.deploy_mode,
            t_requested  = t_req,
            t_active     = t_req + sim_boot,
        )

    def _collect_docker_stats(self, inst: VNFInstance) -> None:
        """Best-effort Docker stats sample for peak CPU%/RAM."""
        rec = self._inflight_metrics.get(inst.instance_id)
        if rec is None or inst.deploy_mode != 'stub':
            return
        try:
            import docker
            client    = docker.from_env()
            container = client.containers.get(inst.container_id)
            stats     = container.stats(stream=False)
            cpu_delta = (stats['cpu_stats']['cpu_usage']['total_usage']
                         - stats['precpu_stats']['cpu_usage']['total_usage'])
            sys_delta = (stats['cpu_stats']['system_cpu_usage']
                         - stats['precpu_stats'].get('system_cpu_usage', 0))
            ncpu      = len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', []) or [1])
            cpu_pct   = (cpu_delta / sys_delta * 100.0 * ncpu) if sys_delta > 0 else 0.0
            rec.peak_cpu_pct = max(rec.peak_cpu_pct, float(cpu_pct))
            ram_b = stats['memory_stats'].get('usage', 0)
            rec.peak_ram_gb = max(rec.peak_ram_gb, ram_b / (1024 ** 3))
        except Exception:
            pass

    def _finalize_boot(self, inst: VNFInstance) -> None:
        rec = self._inflight_metrics.get(inst.instance_id)
        if rec is None:
            return
        rec.boot_time_s = max(0.0, inst.t_active - inst.t_requested)

    def _collect_metrics(self, instance_id: str) -> None:
        rec = self._inflight_metrics.pop(instance_id, None)
        if rec is not None:
            self.metrics.add(rec)

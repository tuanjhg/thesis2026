"""
ProDDoS-NFV — VNF Manager
===========================
Manages VNF lifecycle: create, start, stop, scale-out, scale-in.

In the Mininet testbed, VNFs are simulated as:
  - Lightweight processes on Mininet hosts
  - iptables rules for firewall/rate-limiting
  - Simple Python scripts for scrubbing/proxy logic

In production, this would interface with an NFV MANO (e.g., OSM, ONAP).
"""
import json
import time
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("proddos.vnf_manager")


class VNFState(Enum):
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class VNFInstance:
    """Represents a running VNF instance."""
    vnf_id: str
    vnf_type: str
    host: str  # Mininet host name (e.g., "h1", "vnf_dns_1")
    state: VNFState = VNFState.CREATING
    created_at: float = field(default_factory=time.time)
    config: dict = field(default_factory=dict)
    pid: Optional[int] = None


# ── VNF Templates ─────────────────────────────────────────────────

VNF_TEMPLATES = {
    "rate_limiter": {
        "description": "Token-bucket rate limiter using tc/iptables",
        "start_cmd": (
            "tc qdisc add dev {iface} root tbf "
            "rate {limit_mbps}mbit burst 32kbit latency 50ms"
        ),
        "stop_cmd": "tc qdisc del dev {iface} root",
        "default_config": {"iface": "eth0", "limit_mbps": 100},
    },
    "dns_scrubber": {
        "description": "DNS amplification scrubber — drops oversized DNS responses",
        "start_cmd": (
            "iptables -A FORWARD -p udp --sport 53 "
            "-m length --length 512:65535 -j DROP"
        ),
        "stop_cmd": (
            "iptables -D FORWARD -p udp --sport 53 "
            "-m length --length 512:65535 -j DROP"
        ),
        "default_config": {},
    },
    "syn_proxy": {
        "description": "SYN proxy — validates TCP handshakes before forwarding",
        "start_cmd": (
            "iptables -t raw -A PREROUTING -p tcp --syn "
            "-j CT --notrack && "
            "iptables -A FORWARD -p tcp -m state --state INVALID,UNTRACKED "
            "-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
        ),
        "stop_cmd": (
            "iptables -t raw -D PREROUTING -p tcp --syn "
            "-j CT --notrack; "
            "iptables -D FORWARD -p tcp -m state --state INVALID,UNTRACKED "
            "-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
        ),
        "default_config": {},
    },
    "ntp_scrubber": {
        "description": "NTP amplification filter — blocks monlist responses",
        "start_cmd": (
            "iptables -A FORWARD -p udp --sport 123 "
            "-m length --length 468:65535 -j DROP"
        ),
        "stop_cmd": (
            "iptables -D FORWARD -p udp --sport 123 "
            "-m length --length 468:65535 -j DROP"
        ),
        "default_config": {},
    },
    "ldap_filter": {
        "description": "LDAP amplification filter",
        "start_cmd": (
            "iptables -A FORWARD -p udp --sport 389 "
            "-m length --length 1024:65535 -j DROP"
        ),
        "stop_cmd": (
            "iptables -D FORWARD -p udp --sport 389 "
            "-m length --length 1024:65535 -j DROP"
        ),
        "default_config": {},
    },
    "ssdp_filter": {
        "description": "SSDP amplification filter",
        "start_cmd": (
            "iptables -A FORWARD -p udp --sport 1900 "
            "-m length --length 512:65535 -j DROP"
        ),
        "stop_cmd": (
            "iptables -D FORWARD -p udp --sport 1900 "
            "-m length --length 512:65535 -j DROP"
        ),
        "default_config": {},
    },
    "generic_scrubber": {
        "description": "Generic traffic scrubber — rate limits by source IP",
        "start_cmd": (
            "iptables -A FORWARD -m hashlimit "
            "--hashlimit-above {limit_pps}/sec --hashlimit-mode srcip "
            "--hashlimit-name scrub -j DROP"
        ),
        "stop_cmd": (
            "iptables -D FORWARD -m hashlimit "
            "--hashlimit-above {limit_pps}/sec --hashlimit-mode srcip "
            "--hashlimit-name scrub -j DROP"
        ),
        "default_config": {"limit_pps": 10000},
    },
}


class VNFManager:
    """
    Manages VNF instances in the testbed.

    In simulation mode (default), commands are logged but not executed.
    Set simulate=False for real execution on Mininet hosts.
    """

    def __init__(self, simulate: bool = True):
        self.simulate = simulate
        self.instances: dict[str, VNFInstance] = {}
        self._next_id = 1

        # Metrics
        self.total_created = 0
        self.total_destroyed = 0
        self.scale_out_events = 0
        self.scale_in_events = 0

    def _generate_id(self, vnf_type: str) -> str:
        vid = f"{vnf_type}_{self._next_id}"
        self._next_id += 1
        return vid

    def _execute_cmd(self, host: str, cmd: str) -> bool:
        """Execute a command on a Mininet host (or simulate it)."""
        if self.simulate:
            logger.info(f"[SIMULATE] {host}: {cmd}")
            return True

        try:
            # In real Mininet, use: net.get(host).cmd(cmd)
            # For standalone testing, use subprocess
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(f"Command failed on {host}: {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out on {host}: {cmd}")
            return False

    def create_vnf(
        self,
        vnf_type: str,
        host: str = "vnf_default",
        config: Optional[dict] = None,
    ) -> Optional[VNFInstance]:
        """Create and start a new VNF instance."""
        template = VNF_TEMPLATES.get(vnf_type)
        if not template:
            logger.error(f"Unknown VNF type: {vnf_type}")
            return None

        vnf_id = self._generate_id(vnf_type)
        merged_config = {**template["default_config"], **(config or {})}

        instance = VNFInstance(
            vnf_id=vnf_id,
            vnf_type=vnf_type,
            host=host,
            config=merged_config,
        )

        # Execute start command
        cmd = template["start_cmd"].format(**merged_config)
        if self._execute_cmd(host, cmd):
            instance.state = VNFState.RUNNING
            self.instances[vnf_id] = instance
            self.total_created += 1
            logger.info(f"Created VNF: {vnf_id} ({vnf_type}) on {host}")
            return instance
        else:
            instance.state = VNFState.ERROR
            return instance

    def destroy_vnf(self, vnf_id: str) -> bool:
        """Stop and remove a VNF instance."""
        instance = self.instances.get(vnf_id)
        if not instance:
            logger.warning(f"VNF not found: {vnf_id}")
            return False

        template = VNF_TEMPLATES.get(instance.vnf_type)
        if template:
            cmd = template["stop_cmd"].format(**instance.config)
            self._execute_cmd(instance.host, cmd)

        instance.state = VNFState.STOPPED
        del self.instances[vnf_id]
        self.total_destroyed += 1
        logger.info(f"Destroyed VNF: {vnf_id}")
        return True

    def scale_out(self, vnf_type: str, replicas: int = 1, host_prefix: str = "vnf") -> list[VNFInstance]:
        """Scale out by creating additional VNF instances."""
        new_instances = []
        for i in range(replicas):
            host = f"{host_prefix}_{vnf_type}_{len(self.instances) + i}"
            instance = self.create_vnf(vnf_type, host=host)
            if instance:
                new_instances.append(instance)

        self.scale_out_events += 1
        logger.info(f"Scaled out {vnf_type}: +{len(new_instances)} instances")
        return new_instances

    def scale_in(self, vnf_type: str, count: int = 1) -> int:
        """Scale in by removing VNF instances of the given type."""
        removed = 0
        # Remove newest instances first (LIFO)
        instances_of_type = [
            (vid, inst) for vid, inst in self.instances.items()
            if inst.vnf_type == vnf_type and inst.state == VNFState.RUNNING
        ]
        instances_of_type.sort(key=lambda x: x[1].created_at, reverse=True)

        for vnf_id, _ in instances_of_type[:count]:
            if self.destroy_vnf(vnf_id):
                removed += 1

        self.scale_in_events += 1
        logger.info(f"Scaled in {vnf_type}: -{removed} instances")
        return removed

    def get_instances_by_type(self, vnf_type: str) -> list[VNFInstance]:
        """Get all running instances of a given VNF type."""
        return [
            inst for inst in self.instances.values()
            if inst.vnf_type == vnf_type and inst.state == VNFState.RUNNING
        ]

    def get_stats(self) -> dict:
        """Return VNF manager statistics."""
        type_counts = {}
        for inst in self.instances.values():
            if inst.state == VNFState.RUNNING:
                type_counts[inst.vnf_type] = type_counts.get(inst.vnf_type, 0) + 1

        return {
            "active_instances": len(self.instances),
            "total_created": self.total_created,
            "total_destroyed": self.total_destroyed,
            "scale_out_events": self.scale_out_events,
            "scale_in_events": self.scale_in_events,
            "instances_by_type": type_counts,
        }

    def get_all_instances(self) -> list[dict]:
        """Return all instances as dicts (for API serialization)."""
        return [
            {
                "vnf_id": inst.vnf_id,
                "vnf_type": inst.vnf_type,
                "host": inst.host,
                "state": inst.state.value,
                "created_at": inst.created_at,
                "uptime": round(time.time() - inst.created_at, 1),
            }
            for inst in self.instances.values()
        ]


# ── CLI / Testing ─────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = VNFManager(simulate=True)

    # Create some VNFs
    print("=== Creating VNFs ===")
    manager.create_vnf("dns_scrubber", host="vnf_host_1")
    manager.create_vnf("syn_proxy", host="vnf_host_2")
    manager.create_vnf("rate_limiter", host="vnf_host_3",
                       config={"iface": "eth0", "limit_mbps": 200})

    # Scale out
    print("\n=== Scale Out ===")
    manager.scale_out("rate_limiter", replicas=2)

    print(f"\n=== Stats ===")
    print(json.dumps(manager.get_stats(), indent=2))

    print(f"\n=== All Instances ===")
    for inst in manager.get_all_instances():
        print(f"  {inst['vnf_id']:25s} state={inst['state']:10s} host={inst['host']}")

    # Scale in
    print("\n=== Scale In ===")
    manager.scale_in("rate_limiter", count=1)

    print(f"\n=== Stats After Scale-In ===")
    print(json.dumps(manager.get_stats(), indent=2))

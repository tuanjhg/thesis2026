"""
ProDDoS-NFV — Ryu SDN Controller Application
===============================================
Ryu app that:
  1. Collects periodic flow statistics from OpenFlow switches
  2. Extracts CICFlowMeter-compatible features
  3. Queries the ML prediction API for attack type + confidence
  4. Executes orchestration actions (install flow rules, redirect to VNFs)

Requires: ryu-manager (pip install ryu)
Run: ryu-manager ryu_app.py
"""
import time
import json
import logging
from collections import defaultdict

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
    from ryu.lib import hub
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    logging.warning("Ryu not installed. Running in simulation mode.")

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("proddos.ryu_app")


# ── Feature Extractor ─────────────────────────────────────────────

class FlowFeatureExtractor:
    """
    Extracts CICFlowMeter-compatible features from OpenFlow flow stats.

    Maps OpenFlow statistics to the features used by the ML model.
    """

    def __init__(self):
        # Track flow state for feature computation
        self._flow_cache: dict[str, dict] = {}

    def _flow_key(self, match: dict) -> str:
        """Generate a unique key for a flow."""
        src = match.get("ipv4_src", match.get("eth_src", "?"))
        dst = match.get("ipv4_dst", match.get("eth_dst", "?"))
        proto = match.get("ip_proto", 0)
        sport = match.get("tcp_src", match.get("udp_src", 0))
        dport = match.get("tcp_dst", match.get("udp_dst", 0))
        return f"{src}-{dst}-{proto}-{sport}-{dport}"

    def extract_features(self, flow_stat: dict) -> dict:
        """
        Extract ML features from an OpenFlow flow stat entry.

        Args:
            flow_stat: dict with keys like packet_count, byte_count, duration_sec, etc.

        Returns:
            dict of feature_name → value (CICFlowMeter-compatible names)
        """
        duration = max(flow_stat.get("duration_sec", 0)
                       + flow_stat.get("duration_nsec", 0) / 1e9, 0.001)
        packet_count = flow_stat.get("packet_count", 0)
        byte_count = flow_stat.get("byte_count", 0)

        flow_key = self._flow_key(flow_stat.get("match", {}))
        prev = self._flow_cache.get(flow_key, {})

        # Compute deltas from previous reading
        delta_packets = packet_count - prev.get("packet_count", 0)
        delta_bytes = byte_count - prev.get("byte_count", 0)
        delta_time = duration - prev.get("duration", 0)
        delta_time = max(delta_time, 0.001)

        # Update cache
        self._flow_cache[flow_key] = {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration": duration,
            "timestamp": time.time(),
        }

        # Compute features matching CICFlowMeter naming
        avg_pkt_size = byte_count / max(packet_count, 1)

        features = {
            "Flow Duration": duration * 1e6,  # CICFlowMeter uses microseconds
            "Tot Fwd Pkts": packet_count,
            "Tot Bwd Pkts": 0,  # OpenFlow doesn't distinguish fwd/bwd easily
            "TotLen Fwd Pkts": byte_count,
            "TotLen Bwd Pkts": 0,
            "Fwd Pkt Len Max": avg_pkt_size,  # approximation
            "Fwd Pkt Len Min": avg_pkt_size,
            "Fwd Pkt Len Mean": avg_pkt_size,
            "Fwd Pkt Len Std": 0,
            "Bwd Pkt Len Max": 0,
            "Bwd Pkt Len Min": 0,
            "Bwd Pkt Len Mean": 0,
            "Bwd Pkt Len Std": 0,
            "Flow Byts/s": byte_count / duration,
            "Flow Pkts/s": packet_count / duration,
            "Flow IAT Mean": delta_time * 1e6 / max(delta_packets, 1),
            "Flow IAT Std": 0,
            "Flow IAT Max": delta_time * 1e6,
            "Flow IAT Min": 0,
            "Fwd IAT Tot": delta_time * 1e6,
            "Fwd IAT Mean": delta_time * 1e6 / max(delta_packets, 1),
            "Fwd IAT Std": 0,
            "Fwd IAT Max": delta_time * 1e6,
            "Fwd IAT Min": 0,
            "Bwd IAT Tot": 0,
            "Bwd IAT Mean": 0,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "Fwd Header Len": 20 * packet_count,  # IP header estimate
            "Bwd Header Len": 0,
            "Fwd Pkts/s": delta_packets / delta_time,
            "Bwd Pkts/s": 0,
            "Pkt Len Min": avg_pkt_size,
            "Pkt Len Max": avg_pkt_size,
            "Pkt Len Mean": avg_pkt_size,
            "Pkt Len Std": 0,
            "Pkt Len Var": 0,
            "FIN Flag Cnt": 0,
            "SYN Flag Cnt": 0,
            "RST Flag Cnt": 0,
            "PSH Flag Cnt": 0,
            "ACK Flag Cnt": 0,
            "URG Flag Cnt": 0,
            "CWE Flag Count": 0,
            "ECE Flag Cnt": 0,
            "Pkt Size Avg": avg_pkt_size,
            "Fwd Seg Size Avg": avg_pkt_size,
            "Bwd Seg Size Avg": 0,
            "Init Fwd Win Byts": 65535,  # default
            "Init Bwd Win Byts": 0,
            "Fwd Act Data Pkts": packet_count,
            "Fwd Seg Size Min": 20,
            "Active Mean": duration * 1e6,
            "Active Std": 0,
            "Active Max": duration * 1e6,
            "Active Min": duration * 1e6,
            "Idle Mean": 0,
            "Idle Std": 0,
            "Idle Max": 0,
            "Idle Min": 0,
            "Protocol": flow_stat.get("match", {}).get("ip_proto", 6),
        }

        return features

    def cleanup_old_flows(self, max_age: float = 300.0):
        """Remove flows from cache that haven't been updated recently."""
        now = time.time()
        expired = [
            k for k, v in self._flow_cache.items()
            if now - v["timestamp"] > max_age
        ]
        for k in expired:
            del self._flow_cache[k]


# ── Orchestration Action Executor ─────────────────────────────────

class ActionExecutor:
    """Translates orchestration actions into OpenFlow rules."""

    def __init__(self, datapath=None):
        self.datapath = datapath

    def execute_rate_limit(self, action: dict, datapath=None):
        """Install meter-based rate limiting via OpenFlow."""
        dp = datapath or self.datapath
        if dp is None:
            logger.info(f"[SIMULATE] Rate limit: {action}")
            return

        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        params = action.get("parameters", {})
        rate_kbps = params.get("limit_mbps", 100) * 1000

        # Install a meter for rate limiting
        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=10)]
        mod = parser.OFPMeterMod(
            datapath=dp,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=1,
            bands=bands,
        )
        dp.send_msg(mod)
        logger.info(f"Installed rate limit meter: {rate_kbps} kbps")

    def execute_redirect_to_vnf(self, action: dict, vnf_port: int, datapath=None):
        """Redirect matching traffic to a VNF port."""
        dp = datapath or self.datapath
        if dp is None:
            logger.info(f"[SIMULATE] Redirect to VNF port {vnf_port}: {action}")
            return

        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # Match all traffic (can be refined per attack type)
        match = parser.OFPMatch()
        actions_of = [parser.OFPActionOutput(vnf_port)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions_of
        )]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=match,
            instructions=inst,
            idle_timeout=60,
        )
        dp.send_msg(mod)
        logger.info(f"Installed redirect rule to VNF port {vnf_port}")

    def execute_drop(self, match_params: dict, datapath=None):
        """Install a drop rule (blackhole)."""
        dp = datapath or self.datapath
        if dp is None:
            logger.info(f"[SIMULATE] Drop rule: {match_params}")
            return

        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(**match_params)
        inst = []  # empty instruction = drop

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=200,
            match=match,
            instructions=inst,
            idle_timeout=120,
        )
        dp.send_msg(mod)
        logger.info(f"Installed drop rule: {match_params}")


# ── Main Ryu Application ─────────────────────────────────────────

if RYU_AVAILABLE:
    class ProDDoSController(app_manager.RyuApp):
        """
        Ryu SDN controller app for ProDDoS-NFV.

        Periodically polls flow stats → extracts features → queries ML API
        → executes orchestration actions via OpenFlow.
        """
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.datapaths = {}
            self.feature_extractor = FlowFeatureExtractor()
            self.action_executor = ActionExecutor()
            self.api_url = "http://127.0.0.1:5000"
            self.poll_interval = 5  # seconds
            self.monitor_thread = hub.spawn(self._monitor_loop)

            # Statistics
            self.total_flows_analyzed = 0
            self.attacks_detected = 0
            self.actions_taken = 0

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            """Handle new switch connection — install default flow rule."""
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            self.datapaths[datapath.id] = datapath
            self.action_executor.datapath = datapath

            # Install table-miss flow entry (send to controller)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                match=match,
                instructions=inst,
            )
            datapath.send_msg(mod)
            self.logger.info(f"Switch {datapath.id} connected")

        def _monitor_loop(self):
            """Periodically request flow stats from all switches."""
            while True:
                for dp_id, dp in self.datapaths.items():
                    self._request_flow_stats(dp)
                hub.sleep(self.poll_interval)

        def _request_flow_stats(self, datapath):
            """Send flow stats request to a switch."""
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            """Handle flow stats reply — extract features and predict."""
            datapath = ev.msg.datapath

            for stat in ev.msg.body:
                self.total_flows_analyzed += 1

                # Convert OFPMatch to dict
                match_dict = {}
                for field_name in ["ipv4_src", "ipv4_dst", "ip_proto",
                                   "tcp_src", "tcp_dst", "udp_src", "udp_dst"]:
                    try:
                        val = stat.match.get(field_name)
                        if val is not None:
                            match_dict[field_name] = val
                    except KeyError:
                        pass

                flow_stat = {
                    "packet_count": stat.packet_count,
                    "byte_count": stat.byte_count,
                    "duration_sec": stat.duration_sec,
                    "duration_nsec": stat.duration_nsec,
                    "match": match_dict,
                }

                # Extract features
                features = self.feature_extractor.extract_features(flow_stat)

                # Query ML API
                prediction = self._query_api(features)
                if prediction and prediction.get("attack_type") != "BENIGN":
                    self.attacks_detected += 1
                    self.logger.warning(
                        f"Attack detected: {prediction['attack_type']} "
                        f"(confidence={prediction['confidence']:.2f})"
                    )

                    # Execute actions
                    for action in prediction.get("actions", []):
                        self._execute_action(action, datapath)
                        self.actions_taken += 1

            # Periodic cleanup
            self.feature_extractor.cleanup_old_flows()

        def _query_api(self, features: dict) -> dict:
            """Query the ML prediction API."""
            if requests is None:
                return {}
            try:
                resp = requests.post(
                    f"{self.api_url}/predict",
                    json=features,
                    timeout=2,
                )
                if resp.status_code == 200:
                    return resp.json()
            except requests.RequestException as e:
                self.logger.debug(f"API query failed: {e}")
            return {}

        def _execute_action(self, action: dict, datapath):
            """Execute an orchestration action."""
            action_type = action.get("action_type", "")

            if action_type == "rate_limit":
                self.action_executor.execute_rate_limit(action, datapath)
            elif action_type == "blackhole":
                self.action_executor.execute_drop({}, datapath)
            elif action_type == "sfc_insert":
                # In a real setup, redirect to VNF port
                self.action_executor.execute_redirect_to_vnf(
                    action, vnf_port=99, datapath=datapath
                )
            else:
                self.logger.info(f"Action type '{action_type}' handled by VNF manager")


# ── Simulation Mode (no Ryu) ─────────────────────────────────────

class ProDDoSControllerSimulation:
    """
    Simulated controller for testing without Ryu/Mininet.
    Reads flow data from CSV and processes through the full pipeline.
    """

    def __init__(self, api_url: str = "http://127.0.0.1:5000"):
        self.api_url = api_url
        self.feature_extractor = FlowFeatureExtractor()
        self.action_executor = ActionExecutor()

        self.total_flows = 0
        self.attacks_detected = 0
        self.actions_taken = 0
        self.results: list[dict] = []

    def process_flow(self, flow_features: dict) -> dict:
        """Process a single flow through the detection pipeline."""
        self.total_flows += 1

        # Query API if available, otherwise return empty
        prediction = {}
        if requests is not None:
            try:
                resp = requests.post(
                    f"{self.api_url}/predict",
                    json=flow_features,
                    timeout=2,
                )
                if resp.status_code == 200:
                    prediction = resp.json()
            except requests.RequestException:
                pass

        if prediction.get("attack_type") and prediction["attack_type"] != "BENIGN":
            self.attacks_detected += 1
            for action in prediction.get("actions", []):
                self.actions_taken += 1

        result = {
            "flow_id": self.total_flows,
            "prediction": prediction,
            "timestamp": time.time(),
        }
        self.results.append(result)
        return result

    def get_stats(self) -> dict:
        return {
            "total_flows": self.total_flows,
            "attacks_detected": self.attacks_detected,
            "actions_taken": self.actions_taken,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if RYU_AVAILABLE:
        print("Ryu is available. Run with: ryu-manager ryu_app.py")
    else:
        print("Ryu not installed. Testing simulation mode...")
        sim = ProDDoSControllerSimulation()

        # Simulate some flows
        test_features = {
            "Flow Duration": 1000000,
            "Tot Fwd Pkts": 50000,
            "TotLen Fwd Pkts": 75000000,
            "Flow Byts/s": 75000000,
            "Flow Pkts/s": 50000,
            "Protocol": 17,  # UDP
        }

        result = sim.process_flow(test_features)
        print(f"Result: {json.dumps(result, indent=2, default=str)}")
        print(f"Stats: {sim.get_stats()}")

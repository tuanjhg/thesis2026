"""
ProDDoS-NFV — End-to-End Orchestration Runner
================================================
Ties together all components for end-to-end testing:
  1. Load ML model
  2. Start API server
  3. Process traffic (from CSV or live)
  4. Execute orchestration actions
  5. Collect metrics

Usage:
    python orchestration/run_orchestration.py --csv path/to/attacks.csv
    python orchestration/run_orchestration.py --simulate
"""
import sys
import json
import time
import logging
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from orchestration.policy_engine import PolicyEngine, Prediction, ActionType
from orchestration.vnf_manager import VNFManager

logger = logging.getLogger("proddos.runner")

MODEL_DIR = Path(__file__).parent.parent / "models"


class OrchestrationRunner:
    """
    End-to-end orchestration pipeline.

    Flow: Traffic → Feature Extraction → ML Prediction → Policy Decision → VNF Action
    """

    def __init__(self, simulate: bool = True):
        self.policy_engine = PolicyEngine()
        self.vnf_manager = VNFManager(simulate=simulate)

        # Try to load ML model
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.features = None
        self._load_model()

        # Metrics
        self.total_processed = 0
        self.total_attacks = 0
        self.total_actions = 0
        self.processing_times: list[float] = []
        self.start_time = time.time()

    def _load_model(self):
        """Load ML model artifacts."""
        try:
            import lightgbm as lgb
            import joblib

            for name in ["multiclass_lgb_full.txt", "multiclass_lgb.txt"]:
                model_path = MODEL_DIR / name
                if model_path.exists():
                    self.model = lgb.Booster(model_file=str(model_path))
                    logger.info(f"Loaded model: {name}")
                    break

            scaler_path = MODEL_DIR / "multiclass_scaler.pkl"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)

            le_path = MODEL_DIR / "label_encoder.pkl"
            if le_path.exists():
                self.label_encoder = joblib.load(le_path)

            features_path = MODEL_DIR / "selected_features.pkl"
            if features_path.exists():
                self.features = joblib.load(features_path)

        except ImportError:
            logger.warning("LightGBM/joblib not available. Using simulation mode.")

    def predict(self, flow_features: dict) -> Prediction:
        """Run ML prediction on a flow."""
        if self.model is None:
            return self._simulate_prediction(flow_features)

        feature_names = self.features or []
        values = [float(flow_features.get(f, 0.0)) for f in feature_names]
        X = np.array([values], dtype="float32")

        if self.scaler is not None:
            X = self.scaler.transform(X)

        probs = self.model.predict(X)[0]
        pred_class = int(np.argmax(probs))
        confidence = float(probs[pred_class])

        if self.label_encoder is not None:
            attack_type = self.label_encoder.inverse_transform([pred_class])[0]
        else:
            attack_type = str(pred_class)

        class_probs = {}
        if self.label_encoder is not None:
            for name, p in zip(self.label_encoder.classes_, probs):
                class_probs[name] = round(float(p), 4)

        return Prediction(
            attack_type=attack_type,
            confidence=confidence,
            class_probabilities=class_probs,
        )

    def _simulate_prediction(self, flow_features: dict) -> Prediction:
        """Simulate prediction when model is not available."""
        pps = flow_features.get("Flow Pkts/s", 0)
        bps = flow_features.get("Flow Byts/s", 0)

        if pps > 10000 or bps > 100_000_000:
            attack_types = ["DrDoS_DNS", "DrDoS_UDP", "Syn", "DrDoS_NTP"]
            attack_type = np.random.choice(attack_types)
            confidence = np.random.uniform(0.7, 0.95)
        else:
            attack_type = "BENIGN"
            confidence = np.random.uniform(0.85, 0.99)

        return Prediction(attack_type=attack_type, confidence=confidence)

    def process_flow(self, flow_features: dict) -> dict:
        """Process a single flow through the full pipeline."""
        t_start = time.perf_counter()

        # Step 1: Predict
        prediction = self.predict(flow_features)

        # Step 2: Policy decision
        actions = self.policy_engine.decide(prediction)

        # Step 3: Execute VNF actions
        executed_actions = []
        for action in actions:
            if action.action_type == ActionType.SCALE_OUT:
                replicas = action.parameters.get("replicas", 1)
                instances = self.vnf_manager.scale_out(
                    action.vnf_type, replicas=replicas
                )
                executed_actions.append({
                    "type": "scale_out",
                    "vnf_type": action.vnf_type,
                    "instances_created": len(instances),
                })
            elif action.action_type == ActionType.SCALE_IN:
                removed = self.vnf_manager.scale_in(action.vnf_type)
                executed_actions.append({
                    "type": "scale_in",
                    "vnf_type": action.vnf_type,
                    "instances_removed": removed,
                })
            elif action.action_type == ActionType.SFC_INSERT:
                inst = self.vnf_manager.create_vnf(action.vnf_type)
                executed_actions.append({
                    "type": "sfc_insert",
                    "vnf_type": action.vnf_type,
                    "vnf_id": inst.vnf_id if inst else None,
                })
            elif action.action_type in (ActionType.RATE_LIMIT, ActionType.BLACKHOLE):
                executed_actions.append({
                    "type": action.action_type.value,
                    "vnf_type": action.vnf_type,
                    "params": action.parameters,
                })
            elif action.action_type == ActionType.ALERT:
                executed_actions.append({
                    "type": "alert",
                    "message": action.parameters.get("message", ""),
                })

        t_end = time.perf_counter()
        processing_time = t_end - t_start

        # Update metrics
        self.total_processed += 1
        self.processing_times.append(processing_time)
        if prediction.attack_type != "BENIGN":
            self.total_attacks += 1
        self.total_actions += len(executed_actions)

        return {
            "prediction": {
                "attack_type": prediction.attack_type,
                "confidence": round(prediction.confidence, 4),
            },
            "actions": executed_actions,
            "processing_time_ms": round(processing_time * 1000, 2),
        }

    def process_csv(self, csv_path: str, label_col: str = "Label", max_rows: int = None):
        """Process flows from a CSV file."""
        logger.info(f"Processing CSV: {csv_path}")

        results = []
        reader = pd.read_csv(
            csv_path, chunksize=10000,
            low_memory=False, on_bad_lines="skip",
        )

        rows_processed = 0
        for chunk in reader:
            chunk.columns = chunk.columns.str.strip()
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            chunk.fillna(0, inplace=True)

            for _, row in chunk.iterrows():
                flow_features = row.to_dict()
                result = self.process_flow(flow_features)
                results.append(result)

                rows_processed += 1
                if rows_processed % 1000 == 0:
                    logger.info(
                        f"Processed {rows_processed} flows, "
                        f"{self.total_attacks} attacks detected"
                    )
                if max_rows and rows_processed >= max_rows:
                    break

            if max_rows and rows_processed >= max_rows:
                break

        return results

    def run_simulation(self, n_flows: int = 1000):
        """Run a simulated traffic mix."""
        logger.info(f"Running simulation with {n_flows} flows...")
        rng = np.random.default_rng(42)
        results = []

        for i in range(n_flows):
            # 70% benign, 30% attack
            is_attack = rng.random() < 0.3
            if is_attack:
                flow = {
                    "Flow Duration": rng.uniform(1e3, 1e5),
                    "Tot Fwd Pkts": rng.integers(1000, 100000),
                    "TotLen Fwd Pkts": rng.uniform(1e6, 1e8),
                    "Flow Byts/s": rng.uniform(1e7, 1e9),
                    "Flow Pkts/s": rng.uniform(10000, 500000),
                    "Protocol": rng.choice([6, 17]),
                    "SYN Flag Cnt": rng.integers(0, 1000),
                    "Fwd Pkt Len Mean": rng.uniform(40, 200),
                }
            else:
                flow = {
                    "Flow Duration": rng.uniform(1e5, 1e7),
                    "Tot Fwd Pkts": rng.integers(1, 100),
                    "TotLen Fwd Pkts": rng.uniform(100, 50000),
                    "Flow Byts/s": rng.uniform(1000, 100000),
                    "Flow Pkts/s": rng.uniform(1, 100),
                    "Protocol": rng.choice([6, 17]),
                    "SYN Flag Cnt": rng.integers(0, 3),
                    "Fwd Pkt Len Mean": rng.uniform(100, 1500),
                }

            result = self.process_flow(flow)
            results.append(result)

        return results

    def get_stats(self) -> dict:
        """Return runtime statistics."""
        uptime = time.time() - self.start_time
        avg_time = np.mean(self.processing_times) if self.processing_times else 0

        return {
            "total_processed": self.total_processed,
            "total_attacks": self.total_attacks,
            "total_actions": self.total_actions,
            "avg_processing_time_ms": round(avg_time * 1000, 2),
            "p99_processing_time_ms": round(
                np.percentile(self.processing_times, 99) * 1000, 2
            ) if self.processing_times else 0,
            "uptime_seconds": round(uptime, 1),
            "flows_per_second": round(
                self.total_processed / max(uptime, 1), 1
            ),
            "vnf_stats": self.vnf_manager.get_stats(),
            "policy_stats": self.policy_engine.get_stats(),
        }

    def print_summary(self):
        """Print a summary of the run."""
        stats = self.get_stats()
        print(f"\n{'='*60}")
        print("  ProDDoS-NFV Orchestration Summary")
        print(f"{'='*60}")
        print(f"  Flows processed:    {stats['total_processed']:,}")
        print(f"  Attacks detected:   {stats['total_attacks']:,}")
        print(f"  Actions executed:   {stats['total_actions']:,}")
        print(f"  Avg processing:     {stats['avg_processing_time_ms']:.2f} ms")
        print(f"  P99 processing:     {stats['p99_processing_time_ms']:.2f} ms")
        print(f"  Throughput:         {stats['flows_per_second']:.1f} flows/s")
        print(f"  Active VNFs:        {stats['vnf_stats']['active_instances']}")
        print(f"  Scale-out events:   {stats['vnf_stats']['scale_out_events']}")
        print(f"  Scale-in events:    {stats['vnf_stats']['scale_in_events']}")
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ProDDoS-NFV Orchestration Runner")
    parser.add_argument("--csv", type=str, help="Path to CSV file for replay")
    parser.add_argument("--simulate", action="store_true", help="Run simulation")
    parser.add_argument("--n-flows", type=int, default=1000, help="Number of simulated flows")
    parser.add_argument("--max-rows", type=int, default=None, help="Max rows from CSV")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    runner = OrchestrationRunner(simulate=True)

    if args.csv:
        runner.process_csv(args.csv, max_rows=args.max_rows)
    else:
        runner.run_simulation(n_flows=args.n_flows)

    runner.print_summary()

    # Save stats
    stats_path = MODEL_DIR / "orchestration_stats.json"
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stats_path, "w") as f:
        json.dump(runner.get_stats(), f, indent=2)
    print(f"\nStats saved to {stats_path.name}")


if __name__ == "__main__":
    main()

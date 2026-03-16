"""
ProDDoS-NFV — API Server
==========================
Flask REST API serving the multi-class DDoS detection model.

Endpoints:
    POST /predict       — Single flow prediction
    POST /predict_batch — Batch prediction
    GET  /health        — Health check
    GET  /model/info    — Model metadata
    GET  /stats         — Prediction statistics

The orchestration layer (Ryu controller) calls this API to get
attack type predictions + confidence scores for each flow.
"""
import json
import time
import logging
import os
from pathlib import Path

import numpy as np
import joblib

try:
    from flask import Flask, request, jsonify
except ImportError:
    raise ImportError("Flask is required: pip install flask")

try:
    import lightgbm as lgb
except ImportError:
    raise ImportError("LightGBM is required: pip install lightgbm")

from policy_engine import PolicyEngine, Prediction

logger = logging.getLogger("proddos.api")

# ── Configuration ─────────────────────────────────────────────────

MODEL_DIR = Path(os.environ.get(
    "PRODDOS_MODEL_DIR",
    str(Path(__file__).parent.parent / "models"),
))

app = Flask(__name__)


class DetectionService:
    """Loads model artifacts and provides prediction interface."""

    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.features = None
        self.metadata = None
        self.policy_engine = PolicyEngine()

        # Statistics
        self.total_predictions = 0
        self.attack_counts: dict[str, int] = {}
        self.start_time = time.time()

        self._load_artifacts()

    def _load_artifacts(self):
        """Load all model artifacts from disk."""
        metadata_path = self.model_dir / "model_metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                self.metadata = json.load(f)
            logger.info(f"Loaded metadata: {self.metadata['n_classes']} classes")

        # Try full model first, fall back to sample model
        for model_name in ["multiclass_lgb_full.txt", "multiclass_lgb.txt"]:
            model_path = self.model_dir / model_name
            if model_path.exists():
                self.model = lgb.Booster(model_file=str(model_path))
                logger.info(f"Loaded model: {model_name}")
                break

        scaler_path = self.model_dir / "multiclass_scaler.pkl"
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
            logger.info("Loaded scaler")

        le_path = self.model_dir / "label_encoder.pkl"
        if le_path.exists():
            self.label_encoder = joblib.load(le_path)
            logger.info(f"Loaded label encoder: {list(self.label_encoder.classes_)}")

        features_path = self.model_dir / "selected_features.pkl"
        if features_path.exists():
            self.features = joblib.load(features_path)
            logger.info(f"Loaded {len(self.features)} features")

    def predict(self, flow_features: dict) -> dict:
        """
        Predict attack type for a single flow.

        Args:
            flow_features: dict of feature_name → value

        Returns:
            dict with attack_type, confidence, class_probabilities, actions
        """
        if self.model is None:
            return {"error": "Model not loaded"}

        # Extract features in correct order
        feature_names = self.features or (
            self.metadata["selected_features"] if self.metadata else []
        )
        values = []
        for feat in feature_names:
            values.append(float(flow_features.get(feat, 0.0)))

        X = np.array([values], dtype="float32")

        # Scale if scaler is available
        if self.scaler is not None:
            X = self.scaler.transform(X)

        # Predict
        probabilities = self.model.predict(X)[0]  # shape: (n_classes,)
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])

        # Get class name
        if self.label_encoder is not None:
            attack_type = self.label_encoder.inverse_transform([predicted_class])[0]
        elif self.metadata:
            attack_type = self.metadata["class_names"][predicted_class]
        else:
            attack_type = str(predicted_class)

        # Build class probabilities dict
        class_probs = {}
        class_names = (
            list(self.label_encoder.classes_) if self.label_encoder is not None
            else self.metadata.get("class_names", []) if self.metadata
            else [str(i) for i in range(len(probabilities))]
        )
        for name, prob in zip(class_names, probabilities):
            class_probs[name] = round(float(prob), 4)

        # Update statistics
        self.total_predictions += 1
        self.attack_counts[attack_type] = self.attack_counts.get(attack_type, 0) + 1

        # Get orchestration actions from policy engine
        prediction = Prediction(
            attack_type=attack_type,
            confidence=confidence,
            class_probabilities=class_probs,
        )
        actions = self.policy_engine.decide(prediction)
        action_dicts = [
            {
                "action_type": a.action_type.value,
                "vnf_type": a.vnf_type,
                "parameters": a.parameters,
                "priority": a.priority,
                "reason": a.reason,
            }
            for a in actions
        ]

        return {
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "class_probabilities": class_probs,
            "predicted_class_id": predicted_class,
            "actions": action_dicts,
            "timestamp": time.time(),
        }

    def predict_batch(self, flows: list[dict]) -> list[dict]:
        """Predict for multiple flows."""
        return [self.predict(flow) for flow in flows]

    def get_stats(self) -> dict:
        """Return prediction statistics."""
        uptime = time.time() - self.start_time
        return {
            "total_predictions": self.total_predictions,
            "uptime_seconds": round(uptime, 1),
            "predictions_per_second": round(self.total_predictions / max(uptime, 1), 2),
            "attack_counts": self.attack_counts,
            "policy_stats": self.policy_engine.get_stats(),
        }


# ── Initialize Service ────────────────────────────────────────────

service = DetectionService(MODEL_DIR)


# ── API Endpoints ─────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    model_loaded = service.model is not None
    return jsonify({
        "status": "healthy" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "uptime": round(time.time() - service.start_time, 1),
    })


@app.route("/model/info", methods=["GET"])
def model_info():
    """Return model metadata."""
    if service.metadata:
        return jsonify(service.metadata)
    return jsonify({"error": "No metadata available"}), 404


@app.route("/predict", methods=["POST"])
def predict():
    """
    Predict attack type for a single flow.

    Request body: JSON dict of feature_name → value
    Response: {attack_type, confidence, class_probabilities, actions}
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    result = service.predict(data)
    if "error" in result:
        return jsonify(result), 503

    return jsonify(result)


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    """
    Predict for multiple flows.

    Request body: JSON array of flow feature dicts
    Response: JSON array of predictions
    """
    data = request.get_json(force=True)
    if not isinstance(data, list):
        return jsonify({"error": "Expected JSON array"}), 400

    results = service.predict_batch(data)
    return jsonify(results)


@app.route("/stats", methods=["GET"])
def stats():
    """Return prediction statistics."""
    return jsonify(service.get_stats())


# ── Main ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logger.info(f"Model directory: {MODEL_DIR}")
    logger.info(f"Model loaded: {service.model is not None}")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

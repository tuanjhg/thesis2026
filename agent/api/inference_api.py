"""
REST API wrapper for XGBoost + Transformer+LSTM inference engine.
Exposes ML models as HTTP endpoints for the LLM SOC Agent tool-calling layer.

Endpoints:
  POST /classify_flow     — XGBoost 4-class detection + SHAP
  POST /predict_horizon   — Transformer+LSTM 4-horizon forecast
  POST /infer             — Combined single-window inference
  GET  /health            — Liveness check
  GET  /model_info        — Model metadata
"""

import sys
import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# Allow importing pipeline modules from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from pipeline.s3_ai.inference_layer import InferenceEngine
from pipeline.s3_ai.ai_output import payload_to_dict, CLASS_NAMES

logger = logging.getLogger(__name__)

# ── Pydantic schemas ──────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "pkt_rate", "byte_rate", "avg_pkt_size", "pkt_size_std",
    "proto_dist_tcp", "proto_dist_udp", "proto_dist_icmp", "proto_dist_other",
    "syn_ratio", "fin_ratio", "rst_ratio", "psh_ratio",
    "src_ip_entropy", "dst_ip_entropy", "src_port_entropy", "dst_port_entropy",
    "new_flows_rate",
]

class FlowFeatures(BaseModel):
    """17 raw (unscaled) flow-level features for a 5-second window."""
    features: list[float] = Field(
        ...,
        min_length=17,
        max_length=17,
        description="17 flow features in order: " + ", ".join(FEATURE_NAMES),
        examples=[[0.1] * 17],
    )

    @field_validator("features")
    @classmethod
    def check_finite(cls, v):
        if any(not np.isfinite(x) for x in v):
            raise ValueError("features must be finite (no NaN or Inf)")
        return v


class ClassifyResponse(BaseModel):
    attack_class: int
    attack_type: str
    confidence: float
    class_probs: dict[str, float]
    top_features: dict[str, float]
    latency_ms: float


class HorizonResponse(BaseModel):
    p_attack_30s: float
    p_attack_60s: float
    p_attack_90s: float
    p_attack_120s: float
    proactive_trigger: bool
    recommended_action: str
    latency_ms: float


class InferResponse(BaseModel):
    """Full combined inference output (wraps AIOutputPayload as dict)."""
    payload: dict
    xgboost_latency_ms: float
    transformer_latency_ms: float


# ── App lifecycle ─────────────────────────────────────────────────────────────

engine: Optional[InferenceEngine] = None

MODEL_DIR = os.environ.get("MODEL_DIR", "./pad_onap_v3/models")
DATA_DIR  = os.environ.get("DATA_DIR",  "./pad_onap_v3/processed")
DEVICE    = os.environ.get("DEVICE", "auto")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    logger.info(f"Loading InferenceEngine from {MODEL_DIR} ...")
    engine = InferenceEngine.load(
        model_dir=MODEL_DIR,
        data_dir=DATA_DIR,
        device=DEVICE,
        shap_enabled=True,
    )
    logger.info("InferenceEngine ready.")
    yield
    logger.info("Shutting down InferenceEngine.")


app = FastAPI(
    title="PAD-ONAP Inference API",
    version="1.0.0",
    description="REST wrapper for XGBoost + Transformer+LSTM DDoS detection models",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "engine_loaded": engine is not None}


@app.get("/model_info")
def model_info():
    if engine is None:
        raise HTTPException(503, "Engine not loaded")
    return {
        "xgboost_classes": CLASS_NAMES,
        "forecast_horizons_s": [30, 60, 90, 120],
        "feature_names": FEATURE_NAMES,
        "n_features": 17,
        "model_dir": MODEL_DIR,
        "shap_enabled": engine.shap_enabled,
        "device": str(engine.device),
    }


@app.post("/classify_flow", response_model=ClassifyResponse)
def classify_flow(body: FlowFeatures):
    """
    XGBoost 4-class detection on a single 5-second flow window.
    Returns attack class, confidence, per-class probabilities, and SHAP top-5.
    """
    if engine is None:
        raise HTTPException(503, "Engine not loaded")

    x = np.array(body.features, dtype=np.float64)
    x_scaled = engine.scaler.transform(x.reshape(1, -1))[0]

    class_probs, shap_top5, latency_ms = engine._run_xgboost(x_scaled)
    best_class = int(np.argmax(class_probs))

    # Map 4-class probs to 7-class schema (pad zeros for missing classes)
    full_probs = np.zeros(7)
    for i, p in enumerate(class_probs):
        full_probs[i] = float(p)

    return ClassifyResponse(
        attack_class=best_class,
        attack_type=CLASS_NAMES.get(best_class, "Unknown"),
        confidence=float(class_probs[best_class]),
        class_probs={CLASS_NAMES[i]: float(full_probs[i]) for i in range(7)},
        top_features=shap_top5 or {},
        latency_ms=latency_ms,
    )


@app.post("/predict_horizon", response_model=HorizonResponse)
def predict_horizon(body: FlowFeatures):
    """
    Transformer+LSTM 4-horizon forecast using the last 12 windows in the rolling buffer.
    Appends current window to buffer and returns P(attack) at t+30/60/90/120s.
    Returns [0,0,0,0] until buffer has 12 windows.
    """
    if engine is None:
        raise HTTPException(503, "Engine not loaded")

    x = np.array(body.features, dtype=np.float64)
    x_scaled = engine.scaler.transform(x.reshape(1, -1))[0]

    # Push to rolling buffer then forecast
    engine._seq_buffer.append(x_scaled)
    forecast, latency_ms = engine._run_transformer()

    p30, p60, p90, p120 = [float(p) for p in forecast]
    proactive = bool(p30 > 0.50)

    return HorizonResponse(
        p_attack_30s=p30,
        p_attack_60s=p60,
        p_attack_90s=p90,
        p_attack_120s=p120,
        proactive_trigger=proactive,
        recommended_action="PREPOSITION_TIER2_MITIGATION" if proactive else "NONE",
        latency_ms=latency_ms,
    )


@app.post("/infer", response_model=InferResponse)
def infer(body: FlowFeatures):
    """
    Combined single-window inference: XGBoost + Transformer+LSTM.
    Returns full AIOutputPayload as dict.
    """
    if engine is None:
        raise HTTPException(503, "Engine not loaded")

    x = np.array(body.features, dtype=np.float64)
    payload = engine.infer(x)
    summary = engine.latency_summary()

    return InferResponse(
        payload=payload_to_dict(payload),
        xgboost_latency_ms=summary.get("xgboost_ms", 0.0),
        transformer_latency_ms=summary.get("transformer_ms", 0.0),
    )


@app.post("/reset_buffer")
def reset_buffer():
    """Reset the Transformer rolling window buffer (e.g. between test scenarios)."""
    if engine is None:
        raise HTTPException(503, "Engine not loaded")
    engine.reset_buffer()
    return {"status": "buffer_reset"}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run("inference_api:app", host="0.0.0.0", port=8000, reload=False)

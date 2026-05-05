"""
ai_runtime.py — Live trained AI driver for real-ONAP scenarios
==============================================================

Wraps the trained `InferenceEngine` (XGBoost + Transformer+LSTM in
`pad_onap_v3/models/`) and the NetFlow feature collector
(`testbed/netflow_collector/collector.py`) into a background runner that
emits one `TierEvent` per 5-second window.

The S2 / S8 ONAP runners use this in place of `_simulate_ai_detect()`
so all triggers come from the **real** model output, not hard-coded
payloads. The model is loaded once and stays warm for the run.

Usage:
    from onap.scripts.ai_runtime import LiveInferenceRunner

    runner = LiveInferenceRunner(
        collector_url="http://localhost:7070",
        model_dir="pad_onap_v3/models",
    )
    runner.start()
    ...
    ev = runner.wait_for_tier(min_tier=3, timeout_s=60)
    # ev.payload is a dict ready to publish to DMaaP
    # ev.confidence, ev.attack_type, ev.proactive_trigger come from the live model
    ...
    runner.stop()
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.s3_ai.inference_layer import InferenceEngine
from pipeline.s3_ai.live_pipeline import (
    TIER_LABEL, fetch_latest, features_dict_to_array, get_tier,
)
from pipeline.s3_ai.ai_output import payload_to_dict

logger = logging.getLogger("ai_runtime")


@dataclass
class TierEvent:
    """One window of real-model output with its derived tier."""
    t:                 float
    window_id:         int
    tier:              int
    confidence:        float
    p_attack_30s:      float
    attack_type:       str
    attack_class:      int
    proactive_trigger: bool
    payload:           dict   = field(default_factory=dict)
    raw_features:      dict   = field(default_factory=dict)


class LiveInferenceRunner:
    """
    Polls the NetFlow collector HTTP endpoint at `interval_s`, runs the
    trained InferenceEngine on every fresh feature window, and publishes
    a TierEvent. The latest event is exposed thread-safely; consumers can
    block on `wait_for_tier()` / `wait_for_proactive()`.
    """

    def __init__(
        self,
        collector_url: str   = "http://localhost:7070",
        model_dir:     str   = "pad_onap_v3/models",
        data_dir:      str   = "pad_onap_v3/processed",
        device:        str   = "cpu",
        interval_s:    float = 5.0,
        shap_enabled:  bool  = False,
        on_event:      Optional[Callable[[TierEvent], None]] = None,
    ):
        self.collector_url = collector_url.rstrip("/")
        self.interval_s    = interval_s
        self.on_event      = on_event

        logger.info(f"Loading trained AI from {model_dir} (device={device})")
        self._engine = InferenceEngine.load(
            model_dir    = model_dir,
            data_dir     = data_dir,
            device       = device,
            shap_enabled = shap_enabled,
        )
        logger.info("Trained AI loaded — engine warm")

        self._stop    = threading.Event()
        self._lock    = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._latest: Optional[TierEvent]        = None
        self._history: List[TierEvent]           = []

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ai-runtime")
        self._thread.start()
        logger.info(f"AI runtime started — polling {self.collector_url} "
                    f"every {self.interval_s}s")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("AI runtime stopped")

    # ── State accessors ───────────────────────────────────────────────────────
    @property
    def latest(self) -> Optional[TierEvent]:
        with self._lock:
            return self._latest

    @property
    def history(self) -> List[TierEvent]:
        with self._lock:
            return list(self._history)

    # ── Blocking helpers ──────────────────────────────────────────────────────
    def wait_for_tier(self, min_tier: int, timeout_s: float = 60.0,
                      after: Optional[float] = None) -> Optional[TierEvent]:
        """Block until a TierEvent with tier >= min_tier arrives. The optional
        `after` filter ignores events recorded before that wall-clock time —
        useful when consuming a second trigger after the first has fired."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            ev = self.latest
            if ev is not None and ev.tier >= min_tier and (after is None or ev.t > after):
                return ev
            time.sleep(0.2)
        return None

    def wait_for_proactive(self, timeout_s: float = 60.0,
                           after: Optional[float] = None) -> Optional[TierEvent]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            ev = self.latest
            if ev is not None and ev.proactive_trigger and (after is None or ev.t > after):
                return ev
            time.sleep(0.2)
        return None

    # ── Inference loop ────────────────────────────────────────────────────────
    def _loop(self) -> None:
        last_ts = None
        consecutive_misses = 0
        while not self._stop.is_set():
            t0 = time.time()
            try:
                raw = fetch_latest(self.collector_url)
            except Exception as e:
                logger.warning(f"collector fetch error: {e}")
                raw = None

            if raw is None:
                consecutive_misses += 1
                if consecutive_misses == 5:
                    logger.warning(
                        f"collector at {self.collector_url} not responding — "
                        f"start it with: python testbed/netflow_collector/collector.py "
                        f"--mode synthetic"
                    )
            else:
                consecutive_misses = 0
                ts = raw.get("timestamp")
                if ts != last_ts:
                    last_ts = ts
                    feats = raw.get("features", {})
                    if feats:
                        try:
                            self._handle_window(feats)
                        except Exception as e:
                            logger.exception(f"inference error: {e}")

            elapsed = time.time() - t0
            time.sleep(max(0.0, self.interval_s - elapsed))

    def _handle_window(self, feats: dict) -> None:
        x_raw   = features_dict_to_array(feats)
        payload = self._engine.infer(x_raw)
        pd      = payload_to_dict(payload)

        tier = get_tier(
            confidence   = payload.detection.confidence,
            p30          = payload.forecast.p_attack_30s,
            attack_class = payload.detection.attack_class,
        )

        ev = TierEvent(
            t                 = time.time(),
            window_id         = pd.get("window_id", 0),
            tier              = tier,
            confidence        = float(payload.detection.confidence),
            p_attack_30s      = float(payload.forecast.p_attack_30s),
            attack_type       = payload.detection.attack_type,
            attack_class      = int(payload.detection.attack_class),
            proactive_trigger = bool(payload.proactive_trigger.triggered),
            payload           = pd,
            raw_features      = feats,
        )

        with self._lock:
            self._latest = ev
            self._history.append(ev)

        marker = "[PROACTIVE]" if ev.proactive_trigger else ""
        logger.info(
            f"[W{ev.window_id:04d}] T{ev.tier} {TIER_LABEL[ev.tier].split('—')[0].strip()} "
            f"| {ev.attack_type} conf={ev.confidence:.3f} P30={ev.p_attack_30s:.3f} {marker}"
        )

        if self.on_event:
            try:
                self.on_event(ev)
            except Exception as e:
                logger.warning(f"on_event callback error: {e}")

"""
M2 Track B — Transformer + LSTM 4-Horizon Forecaster (Spec-aligned)
Spec:
  Input:  (batch, 12, 17)  — 12 timesteps × 17 features (60s rolling window @ 5s interval)
  Output: (batch, 4)       — P(attack) at t+30s, t+60s, t+90s, t+120s
  Architecture:
    Transformer Encoder (4 heads, d_model=64, 2 layers, sinusoidal PE)
    → LSTM (hidden=128, 2 layers, dropout=0.2)
    → FC: 128 → 64 → 4 (sigmoid)
  Training: BCE per horizon, class_weight attack:normal = 10:1
  Proactive trigger: P(t+30s) > 0.70 → Tier 2 pre-position signal
"""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torch.amp import GradScaler, autocast
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import logging, json, time
from pathlib import Path
from sklearn.metrics import roc_auc_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

N_TIMESTEPS = 12       # 12 × 5s = 60s rolling window
N_FEATURES  = 17
N_HORIZONS  = 4        # t+30s, t+60s, t+90s, t+120s
HORIZON_LABELS = ["t+30s", "t+60s", "t+90s", "t+120s"]
PROACTIVE_THRESHOLD = 0.70  # spec §4.3

TARGETS = {'auc_h0': 0.90, 'accuracy_h0': 0.88}

HP_CONFIGS = [
    dict(hidden_dim=64,  num_heads=4, num_layers=2,
         lstm_hidden=128, lstm_layers=2, dropout=0.2,
         lr=1e-3, batch_size=128, epochs=80,  patience=15),
    dict(hidden_dim=64,  num_heads=4, num_layers=3,
         lstm_hidden=128, lstm_layers=2, dropout=0.2,
         lr=5e-4, batch_size=64,  epochs=100, patience=20),
    dict(hidden_dim=128, num_heads=4, num_heads_=4, num_layers=2,
         lstm_hidden=256, lstm_layers=2, dropout=0.3,
         lr=3e-4, batch_size=64,  epochs=120, patience=20),
]


# ── Sinusoidal Positional Encoding ────────────────────────────────────────
class SinusoidalPE(nn.Module):
    def __init__(self, d_model, max_len=100):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        pos = torch.arange(max_len).unsqueeze(1).float()
        div = torch.exp(torch.arange(0, d_model, 2).float() * (-np.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(pos * div)
        pe[:, 1::2] = torch.cos(pos * div)
        self.register_buffer('pe', pe.unsqueeze(0))  # (1, max_len, d_model)

    def forward(self, x):
        return x + self.pe[:, :x.size(1)]


# ── Model ─────────────────────────────────────────────────────────────────
class TransformerLSTMForecaster(nn.Module):
    """
    Spec-aligned Transformer + LSTM 4-horizon forecaster.
    """
    def __init__(self, input_dim=N_FEATURES, hidden_dim=64,
                 num_heads=4, num_layers=2,
                 lstm_hidden=128, lstm_layers=2, dropout=0.2):
        super().__init__()

        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)

        # Sinusoidal positional encoding
        self.pos_enc = SinusoidalPE(hidden_dim)

        # Transformer Encoder
        enc_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=num_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout, batch_first=True, activation='gelu',
        )
        self.transformer = nn.TransformerEncoder(
            enc_layer, num_layers=num_layers,
            norm=nn.LayerNorm(hidden_dim),
        )

        # LSTM Forecaster
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=lstm_hidden,
            num_layers=lstm_layers,
            dropout=dropout if lstm_layers > 1 else 0,
            batch_first=True,
        )

        # FC head: 128 → 64 → 4 (raw logits; sigmoid applied at inference)
        self.fc = nn.Sequential(
            nn.Linear(lstm_hidden, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, N_HORIZONS),
            # No Sigmoid here — use BCEWithLogitsLoss for FP16 safety
        )

    def forward(self, x):
        """
        Args:
            x: (batch, seq_len=12, features=17)
        Returns:
            out: (batch, 4)  — P(attack) at t+30s/60s/90s/120s
        """
        # Project + positional encoding
        h = self.pos_enc(self.input_proj(x))   # (B, 12, hidden_dim)

        # Transformer encoding
        h = self.transformer(h)                 # (B, 12, hidden_dim)

        # LSTM forecasting
        h, _ = self.lstm(h)                     # (B, 12, lstm_hidden)
        h_last = h[:, -1, :]                    # (B, lstm_hidden)

        # Output: 4 probabilities
        return self.fc(h_last)                  # (B, 4)


# ── Dataset ───────────────────────────────────────────────────────────────
class ForecastDataset(Dataset):
    """
    Sliding window dataset for 4-horizon forecasting.

    For each position i:
      Input:  X[i : i+N_TIMESTEPS]  (12 timesteps)
      Labels: binary attack label at horizon steps ahead
              [i+6, i+12, i+18, i+24] if step=6 (approx. t+30s/60s/90s/120s)
    """

    def __init__(self, X, y_class, n_timesteps=N_TIMESTEPS):
        """
        y_class: 0 = Normal, >0 = attack (7-class from M2 TrackA)

        Label strategy: TRUE future labels from temporal data.
        Data must be in temporal order (not shuffled).
        For each position i:
          Input:  X[i : i+n_timesteps]        (current window)
          Labels: majority-vote binary label at future windows
                  horizon_steps = [6, 12, 18, 24] ≈ t+30s, t+60s, t+90s, t+120s
        Each horizon label = majority of a small look-ahead window (3 steps)
        to reduce noise from single-step labels.
        """
        self.windows = []
        self.labels  = []

        y_binary = (y_class > 0).astype(np.float32)

        # Horizon steps (in window units, each ~5s)
        horizon_steps = [6, 12, 18, 24]   # t+30s, t+60s, t+90s, t+120s
        lookahead     = 3                   # smooth over 3 steps per horizon
        max_offset    = max(horizon_steps) + lookahead

        for i in range(0, len(X) - n_timesteps - max_offset, 1):
            window = X[i:i+n_timesteps]

            # Future labels: majority of look-ahead window at each horizon
            future_labels = np.zeros(N_HORIZONS, dtype=np.float32)
            for h_idx, h in enumerate(horizon_steps):
                future_start = i + n_timesteps + h
                future_end   = min(future_start + lookahead, len(y_binary))
                future_labels[h_idx] = float(
                    y_binary[future_start:future_end].mean() > 0.5
                )

            self.windows.append(window)
            self.labels.append(future_labels)

        logger.info(f"    ForecastDataset: {len(self.windows):,} windows")
        if len(self.windows) > 0:
            pos = np.array([l[0] for l in self.labels]).mean()
            logger.info(f"    Attack ratio (t+30s): {pos*100:.1f}%")

    def __len__(self):
        return len(self.windows)

    def __getitem__(self, idx):
        return (
            torch.FloatTensor(self.windows[idx]),  # (12, 17)
            torch.FloatTensor(self.labels[idx]),    # (4,)
        )


# ── Training ──────────────────────────────────────────────────────────────
def train_one_config(X_train, y_train, X_test, y_test, hp, device):
    # Cap dataset for memory
    MAX_ROWS = 100000
    if len(X_train) > MAX_ROWS:
        idx = np.random.default_rng(42).choice(len(X_train), MAX_ROWS, replace=False)
        idx.sort()
        X_train, y_train = X_train[idx], y_train[idx]

    MAX_TEST = 30000
    if len(X_test) > MAX_TEST:
        idx = np.random.default_rng(99).choice(len(X_test), MAX_TEST, replace=False)
        idx.sort()
        X_test, y_test = X_test[idx], y_test[idx]

    train_ds = ForecastDataset(X_train, y_train)
    test_ds  = ForecastDataset(X_test,  y_test)

    if len(train_ds) == 0 or len(test_ds) == 0:
        logger.warning("  Empty dataset — skipping")
        return None, {}, 0

    train_dl = DataLoader(train_ds, batch_size=hp['batch_size'],
                          shuffle=True,  num_workers=0, pin_memory=True)
    test_dl  = DataLoader(test_ds,  batch_size=hp['batch_size'] * 2,
                          shuffle=False, num_workers=0, pin_memory=True)

    model = TransformerLSTMForecaster(
        input_dim=N_FEATURES,
        hidden_dim=hp['hidden_dim'],
        num_heads=hp['num_heads'],
        num_layers=hp['num_layers'],
        lstm_hidden=hp['lstm_hidden'],
        lstm_layers=hp['lstm_layers'],
        dropout=hp['dropout'],
    ).to(device)
    logger.info(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")

    optimizer = optim.AdamW(model.parameters(), lr=hp['lr'], weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=hp['epochs'])

    # Class weight: attack:normal = 10:1 (spec §4.3)
    pos_weight = torch.tensor([10.0] * N_HORIZONS).to(device)
    criterion  = nn.BCELoss()   # Sigmoid already applied in model

    use_amp = device.type == 'cuda'
    scaler  = GradScaler('cuda', enabled=use_amp)

    best_auc   = 0.0
    best_state = None
    patience_ct = 0
    train_losses, val_aucs = [], []

    t0 = time.time()
    for epoch in range(hp['epochs']):
        # Train
        model.train()
        total_loss = 0
        for Xb, yb in train_dl:
            Xb, yb = Xb.to(device), yb.to(device)
            with autocast('cuda', enabled=use_amp):
                logits = model(Xb)         # (B, 4) raw logits
                # BCEWithLogitsLoss is autocast-safe; pos_weight upweights attacks
                loss = 0
                for h in range(N_HORIZONS):
                    loss += nn.functional.binary_cross_entropy_with_logits(
                        logits[:, h], yb[:, h],
                        pos_weight=pos_weight[h].unsqueeze(0),
                    )
                loss = loss / N_HORIZONS

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            optimizer.zero_grad(set_to_none=True)
            total_loss += loss.item()
        scheduler.step()
        train_losses.append(total_loss / len(train_dl))

        # Validate
        model.eval()
        all_proba = [[] for _ in range(N_HORIZONS)]
        all_labels = [[] for _ in range(N_HORIZONS)]
        with torch.no_grad():
            for Xb, yb in test_dl:
                Xb = Xb.to(device)
                with autocast('cuda', enabled=use_amp):
                    logits_val = model(Xb)
                proba_val = torch.sigmoid(logits_val.float())
                for h in range(N_HORIZONS):
                    all_proba[h].extend(proba_val[:, h].cpu().numpy())
                    all_labels[h].extend(yb[:, h].numpy())

        aucs = []
        for h in range(N_HORIZONS):
            lbl = np.array(all_labels[h])
            prb = np.array(all_proba[h])
            try:
                a = roc_auc_score(lbl, prb) if len(np.unique(lbl)) > 1 else 0.5
            except Exception:
                a = 0.5
            aucs.append(a)
        val_auc_mean = float(np.mean(aucs))
        val_aucs.append(val_auc_mean)

        if (epoch + 1) % 10 == 0 or epoch == 0:
            auc_str = "  ".join([f"{HORIZON_LABELS[h]}:{aucs[h]:.3f}" for h in range(N_HORIZONS)])
            logger.info(f"  Epoch {epoch+1:3d}/{hp['epochs']} | "
                        f"loss={train_losses[-1]:.4f} | AUC [{auc_str}]")

        if val_auc_mean > best_auc:
            best_auc   = val_auc_mean
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_ct = 0
        else:
            patience_ct += 1
            if patience_ct >= hp['patience']:
                logger.info(f"  Early stopping at epoch {epoch+1}")
                break

    elapsed = time.time() - t0
    if best_state:
        model.load_state_dict({k: v.to(device) for k, v in best_state.items()})

    # Final eval
    model.eval()
    all_proba = [[] for _ in range(N_HORIZONS)]
    all_labels = [[] for _ in range(N_HORIZONS)]
    with torch.no_grad():
        for Xb, yb in test_dl:
            Xb = Xb.to(device)
            with autocast('cuda', enabled=use_amp):
                logits_final = model(Xb)
            proba_final = torch.sigmoid(logits_final.float())
            for h in range(N_HORIZONS):
                all_proba[h].extend(proba_final[:, h].cpu().numpy())
                all_labels[h].extend(yb[:, h].numpy())

    final_aucs = []
    final_accs = []
    for h in range(N_HORIZONS):
        lbl = np.array(all_labels[h])
        prb = np.array(all_proba[h])
        pred = (prb > 0.5).astype(int)
        try:
            a = roc_auc_score(lbl, prb) if len(np.unique(lbl)) > 1 else 0.5
        except Exception:
            a = 0.5
        final_aucs.append(a)
        final_accs.append(float((pred == lbl).mean()))

    metrics = {
        'auc_h0':      float(final_aucs[0]),   # t+30s (most important)
        'accuracy_h0': float(final_accs[0]),
        'auc_all':     [float(a) for a in final_aucs],
        'acc_all':     [float(a) for a in final_accs],
        'auc_mean':    float(np.mean(final_aucs)),
    }

    logger.info(f"  Training time: {elapsed:.1f}s | Best AUC mean: {best_auc:.4f}")
    return model, metrics, elapsed, train_losses, val_aucs


def run_training(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("="*60)
    logger.info("M2 TRACK B — Transformer+LSTM 4-Horizon Forecast (GPU)")
    logger.info("="*60)

    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train = np.load(data_dir / 'y_train.npy').astype(int)
    y_test  = np.load(data_dir / 'y_test.npy').astype(int)

    logger.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    logger.info(f"Proactive trigger threshold: P(t+30s) > {PROACTIVE_THRESHOLD}")

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Device: {device}")
    if device.type == 'cuda':
        logger.info(f"  GPU: {torch.cuda.get_device_name(0)}")
        logger.info(f"  Mixed precision (FP16): ENABLED")

    best_model, best_metrics, best_losses, best_aucs, best_hp_idx = None, {}, [], [], 0

    for attempt, hp in enumerate(HP_CONFIGS):
        logger.info(f"\n{'─'*60}")
        logger.info(f"Attempt {attempt+1}/{len(HP_CONFIGS)} | "
                    f"hidden={hp['hidden_dim']} lstm={hp['lstm_hidden']} "
                    f"batch={hp['batch_size']} lr={hp['lr']}")
        logger.info('─'*60)

        result = train_one_config(X_train, y_train, X_test, y_test, hp, device)
        if result[0] is None:
            continue
        model, metrics, elapsed, losses, aucs = result

        logger.info(f"\n📊 Results (attempt {attempt+1}):")
        for h in range(N_HORIZONS):
            logger.info(f"  {HORIZON_LABELS[h]:8s}: AUC={metrics['auc_all'][h]:.4f}  ACC={metrics['acc_all'][h]:.4f}")
        logger.info(f"  AUC mean: {metrics['auc_mean']:.4f}")

        if not best_metrics or metrics['auc_h0'] > best_metrics.get('auc_h0', 0):
            best_model, best_metrics = model, metrics
            best_losses, best_aucs   = losses, aucs
            best_hp_idx              = attempt

        if all(metrics.get(k, 0) >= v for k, v in TARGETS.items()):
            logger.info("🎉 All targets met!")
            break

    # ── Final report ───────────────────────────────────────────────────────
    logger.info(f"\n{'='*60}")
    logger.info("BEST TRANSFORMER+LSTM RESULTS")
    logger.info('='*60)
    for h in range(N_HORIZONS):
        logger.info(f"  {HORIZON_LABELS[h]:8s}: AUC={best_metrics['auc_all'][h]:.4f}  ACC={best_metrics['acc_all'][h]:.4f}")
    logger.info(f"  AUC mean: {best_metrics['auc_mean']:.4f}")
    logger.info(f"\n  Proactive trigger: P(t+30s) > {PROACTIVE_THRESHOLD} → Tier 2 pre-position")

    # ── Inference speed ────────────────────────────────────────────────────
    best_model.eval()
    # Build a (64, N_TIMESTEPS, N_FEATURES) bench batch
    if len(X_test) >= N_TIMESTEPS:
        _seq = X_test[:N_TIMESTEPS][np.newaxis, :, :]   # (1, 12, 17)
        _bench_np = np.repeat(_seq, 64, axis=0).astype(np.float32)  # (64, 12, 17)
    else:
        _bench_np = np.random.randn(64, N_TIMESTEPS, N_FEATURES).astype(np.float32)
    sample = torch.FloatTensor(_bench_np).to(device)
    times = []
    with torch.no_grad():
        for _ in range(200):
            t0 = time.time()
            best_model(sample)
            if device.type == 'cuda':
                torch.cuda.synchronize()
            times.append((time.time() - t0) * 1000)
    latency = {
        'p50_ms': float(np.percentile(times, 50)),
        'p95_ms': float(np.percentile(times, 95)),
        'p99_ms': float(np.percentile(times, 99)),
    }
    logger.info(f"\n⏱️  Inference: P50={latency['p50_ms']:.2f}ms  P99={latency['p99_ms']:.2f}ms")

    # ── Training curves ────────────────────────────────────────────────────
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    ax1.plot(best_losses, 'b-', lw=1.5)
    ax1.set_xlabel('Epoch'); ax1.set_ylabel('Loss')
    ax1.set_title('Training Loss'); ax1.grid(alpha=0.3)
    ax2.plot(best_aucs, 'g-', lw=1.5, label='Val AUC mean')
    ax2.axhline(TARGETS['auc_h0'], color='r', ls='--', label=f"Target={TARGETS['auc_h0']}")
    ax2.set_xlabel('Epoch'); ax2.set_ylabel('AUC')
    ax2.set_title('4-Horizon AUC (mean)'); ax2.grid(alpha=0.3); ax2.legend()
    plt.tight_layout()
    plt.savefig(output_dir / 'transformer_lstm_curves.png', dpi=150)
    plt.close()
    logger.info(f"📊 Saved: {output_dir}/transformer_lstm_curves.png")

    # ── Save ───────────────────────────────────────────────────────────────
    model_path = output_dir / 'transformer_lstm_v2.pth'
    torch.save(best_model.state_dict(), model_path)
    logger.info(f"\n💾 Model saved: {model_path}")

    metadata = {
        'model_type':      'TransformerLSTM_4horizon',
        'version':         '2.0',
        'spec_module':     'M2_TrackB',
        'device':          device.type,
        'amp_fp16':        device.type == 'cuda',
        'n_features':      N_FEATURES,
        'n_timesteps':     N_TIMESTEPS,
        'n_horizons':      N_HORIZONS,
        'horizons':        HORIZON_LABELS,
        'proactive_threshold': PROACTIVE_THRESHOLD,
        'best_hp':         HP_CONFIGS[best_hp_idx],
        'metrics':         best_metrics,
        'latency_ms':      latency,
        'targets_met':     all(best_metrics.get(k, 0) >= v for k, v in TARGETS.items()),
    }
    with open(output_dir / 'transformer_lstm_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info("\n✅ Transformer+LSTM 4-horizon training complete!")
    return best_model, best_metrics


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run_training(args.data_dir, args.output_dir)

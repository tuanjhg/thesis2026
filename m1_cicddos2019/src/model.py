from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class Chomp1d(nn.Module):
    def __init__(self, chomp_size: int) -> None:
        super().__init__()
        self.chomp_size = chomp_size

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.chomp_size == 0:
            return x
        return x[:, :, :-self.chomp_size].contiguous()


class TemporalBlock(nn.Module):
    def __init__(
        self,
        n_inputs: int,
        n_outputs: int,
        kernel_size: int,
        dilation: int,
        dropout: float,
    ) -> None:
        super().__init__()
        padding = (kernel_size - 1) * dilation

        self.conv1 = nn.utils.weight_norm(
            nn.Conv1d(n_inputs, n_outputs, kernel_size, padding=padding, dilation=dilation)
        )
        self.chomp1 = Chomp1d(padding)
        self.relu1 = nn.ReLU()
        self.drop1 = nn.Dropout(dropout)

        self.conv2 = nn.utils.weight_norm(
            nn.Conv1d(n_outputs, n_outputs, kernel_size, padding=padding, dilation=dilation)
        )
        self.chomp2 = Chomp1d(padding)
        self.relu2 = nn.ReLU()
        self.drop2 = nn.Dropout(dropout)

        self.net = nn.Sequential(
            self.conv1,
            self.chomp1,
            self.relu1,
            self.drop1,
            self.conv2,
            self.chomp2,
            self.relu2,
            self.drop2,
        )
        self.downsample = nn.Conv1d(n_inputs, n_outputs, 1) if n_inputs != n_outputs else None
        self.relu = nn.ReLU()
        self.init_weights()

    def init_weights(self) -> None:
        self.conv1.weight.data.normal_(0, 0.01)
        self.conv2.weight.data.normal_(0, 0.01)
        if self.downsample is not None:
            self.downsample.weight.data.normal_(0, 0.01)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        res = x if self.downsample is None else self.downsample(x)
        return self.relu(out + res)


class TCNBinaryPredictor(nn.Module):
    def __init__(
        self,
        in_features: int,
        channels: list[int],
        kernel_size: int = 3,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        layers = []
        in_ch = in_features
        for i, out_ch in enumerate(channels):
            dilation = 2**i
            layers.append(
                TemporalBlock(
                    n_inputs=in_ch,
                    n_outputs=out_ch,
                    kernel_size=kernel_size,
                    dilation=dilation,
                    dropout=dropout,
                )
            )
            in_ch = out_ch

        self.tcn = nn.Sequential(*layers)
        self.head = nn.Linear(channels[-1], 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Input shape: [batch, window, features]
        x = x.transpose(1, 2)  # [batch, features, window]
        z = self.tcn(x)
        z_last = z[:, :, -1]
        logits = self.head(z_last).squeeze(-1)
        probs = torch.sigmoid(logits)
        return probs


class LSTMBinaryPredictor(nn.Module):
    def __init__(
        self,
        in_features: int,
        hidden_size: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
        bidirectional: bool = False,
    ) -> None:
        super().__init__()
        effective_dropout = dropout if num_layers > 1 else 0.0
        self.bidirectional = bidirectional
        self.lstm = nn.LSTM(
            input_size=in_features,
            hidden_size=hidden_size,
            num_layers=num_layers,
            dropout=effective_dropout,
            bidirectional=bidirectional,
            batch_first=True,
        )
        out_dim = hidden_size * (2 if bidirectional else 1)
        self.head = nn.Linear(out_dim, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Input shape: [batch, window, features]
        z, _ = self.lstm(x)
        z_last = z[:, -1, :]
        logits = self.head(z_last).squeeze(-1)
        probs = torch.sigmoid(logits)
        return probs


def build_binary_predictor(
    model_type: str,
    in_features: int,
    model_params: dict,
) -> nn.Module:
    model_type = model_type.lower().strip()
    if model_type == "tcn":
        return TCNBinaryPredictor(
            in_features=in_features,
            channels=model_params["tcn_channels"],
            kernel_size=model_params["tcn_kernel_size"],
            dropout=model_params["tcn_dropout"],
        )
    if model_type == "lstm":
        return LSTMBinaryPredictor(
            in_features=in_features,
            hidden_size=model_params["lstm_hidden_size"],
            num_layers=model_params["lstm_num_layers"],
            dropout=model_params["lstm_dropout"],
            bidirectional=model_params["lstm_bidirectional"],
        )
    raise ValueError(f"Unsupported model_type: {model_type}")


def build_model_from_checkpoint(ckpt: dict) -> nn.Module:
    model_type = ckpt.get("model_type", "tcn")
    params = {
        "tcn_channels": ckpt.get("tcn_channels", [64, 64, 32]),
        "tcn_kernel_size": ckpt.get("tcn_kernel_size", 3),
        "tcn_dropout": ckpt.get("tcn_dropout", 0.2),
        "lstm_hidden_size": ckpt.get("lstm_hidden_size", 128),
        "lstm_num_layers": ckpt.get("lstm_num_layers", 2),
        "lstm_dropout": ckpt.get("lstm_dropout", 0.2),
        "lstm_bidirectional": ckpt.get("lstm_bidirectional", False),
    }
    return build_binary_predictor(
        model_type=model_type,
        in_features=len(ckpt["feature_columns"]),
        model_params=params,
    )


class BinaryFocalLoss(nn.Module):
    def __init__(self, alpha: float = 0.25, gamma: float = 2.0, eps: float = 1e-7) -> None:
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.eps = eps

    def forward(self, probs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        probs = torch.clamp(probs, self.eps, 1 - self.eps)
        targets = targets.float()

        bce = F.binary_cross_entropy(probs, targets, reduction="none")
        p_t = probs * targets + (1 - probs) * (1 - targets)
        alpha_t = self.alpha * targets + (1 - self.alpha) * (1 - targets)
        focal = alpha_t * torch.pow((1 - p_t), self.gamma) * bce
        return focal.mean()

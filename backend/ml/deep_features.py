"""Deep learning feature extraction for anomaly detection.

Phase 3: Uses autoencoders and temporal models to learn feature representations
from raw event sequences, complementing hand-crafted features.

The deep learning module:
1. Autoencoder for anomaly detection (reconstruction error as anomaly score)
2. Temporal CNN for sequence pattern recognition
3. Feature fusion combining deep features with hand-crafted features
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict

import numpy as np

logger = logging.getLogger("baraq.ml.deep_features")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class EventAutoencoder(nn.Module):
    """Autoencoder for learning compact event representations.

    The encoder compresses input features into a latent space;
    reconstruction error serves as an anomaly score.
    """

    def __init__(self, input_dim: int, latent_dim: int = 16, hidden_dim: int = 64):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed, latent

    def reconstruction_error(self, x):
        """Per-sample reconstruction error (higher = more anomalous)."""
        with torch.no_grad():
            recon, _ = self(x)
            error = torch.mean((x - recon) ** 2, dim=1)
        return error


class TemporalCNN(nn.Module):
    """1D CNN for capturing local temporal patterns in event sequences.

    Processes sliding windows of event features to detect burst patterns,
    timing anomalies, and sequential attack indicators.
    """

    def __init__(self, input_dim: int, seq_len: int = 10, n_filters: int = 32):
        super().__init__()
        self.conv1 = nn.Conv1d(input_dim, n_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(n_filters, n_filters, kernel_size=3, padding=1)
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Linear(n_filters, 16)

    def forward(self, x):
        # x: (batch, seq_len, features) -> (batch, features, seq_len)
        x = x.permute(0, 2, 1)
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        x = self.pool(x).squeeze(-1)
        return self.fc(x)


class DeepFeatureExtractor:
    """Extracts deep learning features and fuses with hand-crafted features.

    Usage:
        extractor = DeepFeatureExtractor(input_dim=38)
        extractor.train_autoencoder(normal_features, epochs=50)
        features = extractor.extract(event_features)
    """

    def __init__(self, input_dim: int, latent_dim: int = 16, device: str = "cpu"):
        if not HAS_TORCH:
            raise ImportError("PyTorch required for deep feature extraction")

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.device = torch.device(device)

        self.autoencoder = EventAutoencoder(input_dim, latent_dim).to(self.device)
        self.is_trained = False
        self._recon_threshold = 0.1

    def train_autoencoder(
        self,
        X_normal: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32,
        lr: float = 1e-3,
    ) -> dict:
        """Train autoencoder on normal (benign) events.

        Args:
            X_normal: Feature matrix of normal events (n_samples, input_dim)
            epochs: Training epochs
            batch_size: Batch size
            lr: Learning rate

        Returns:
            Training metrics dict
        """
        if not HAS_TORCH:
            return {"status": "pytorch-not-installed"}

        X_tensor = torch.FloatTensor(X_normal).to(self.device)
        dataset = TensorDataset(X_tensor, X_tensor)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = optim.Adam(self.autoencoder.parameters(), lr=lr)
        criterion = nn.MSELoss()

        self.autoencoder.train()
        losses = []
        for epoch in range(epochs):
            epoch_loss = 0.0
            for batch_x, _ in loader:
                optimizer.zero_grad()
                recon, _ = self.autoencoder(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            avg_loss = epoch_loss / len(loader)
            losses.append(avg_loss)

        # Set reconstruction threshold (mean + 2*std of training errors)
        self.autoencoder.eval()
        with torch.no_grad():
            recon_errors = self.autoencoder.reconstruction_error(X_tensor)
            self._recon_threshold = float(
                recon_errors.mean() + 2 * recon_errors.std()
            )

        self.is_trained = True
        return {
            "status": "ok",
            "final_loss": losses[-1] if losses else 0.0,
            "epochs": epochs,
            "recon_threshold": self._recon_threshold,
        }

    def extract(self, X: np.ndarray) -> np.ndarray:
        """Extract latent features from autoencoder.

        Returns concatenated [original_features, latent_features, recon_error].
        """
        if not self.is_trained:
            return X

        X_tensor = torch.FloatTensor(X).to(self.device)
        self.autoencoder.eval()
        with torch.no_grad():
            recon, latent = self.autoencoder(X_tensor)
            recon_errors = self.autoencoder.reconstruction_error(X_tensor)

        latent_np = latent.cpu().numpy()
        errors_np = recon_errors.cpu().numpy().reshape(-1, 1)

        # Scale reconstruction error to [0, 1]
        errors_scaled = np.clip(errors_np / max(self._recon_threshold, 1e-6), 0, 1)

        return np.hstack([X, latent_np, errors_scaled])

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly scores based on reconstruction error."""
        if not self.is_trained:
            return np.zeros(len(X))

        X_tensor = torch.FloatTensor(X).to(self.device)
        self.autoencoder.eval()
        with torch.no_grad():
            errors = self.autoencoder.reconstruction_error(X_tensor)

        scores = errors.cpu().numpy()
        return np.clip(scores / max(self._recon_threshold, 1e-6), 0, 1)


class SequencePatternDetector:
    """Detects temporal attack patterns using sliding window analysis.

    Extracts statistical features from event sequences:
    - Inter-event timing distribution
    - Burst detection (sudden spikes in event rate)
    - Periodicity detection (beaconing patterns)
    """

    def __init__(self, window_size: int = 10):
        self.window_size = window_size

    def extract_sequence_features(
        self,
        events: list[dict],
        feature_key: str = "event_id",
    ) -> np.ndarray:
        """Extract temporal features from a sequence of events.

        Args:
            events: List of event dicts with 'ts' (timestamp) and feature_key
            window_size: Number of events in sliding window

        Returns:
            Feature matrix (n_windows, n_features)
        """
        if len(events) < self.window_size:
            return np.zeros((0, 12))

        features_list = []
        timestamps = [e.get("ts") for e in events]

        for i in range(len(events) - self.window_size + 1):
            window = events[i: i + self.window_size]
            window_ts = timestamps[i: i + self.window_size]

            # Compute inter-event intervals
            intervals = []
            for j in range(1, len(window_ts)):
                if window_ts[j] and window_ts[j - 1]:
                    dt = (window_ts[j] - window_ts[j - 1]).total_seconds()
                    intervals.append(dt)

            if not intervals:
                features_list.append([0.0] * 12)
                continue

            intervals = np.array(intervals)

            # Timing features
            mean_interval = float(np.mean(intervals))
            std_interval = float(np.std(intervals))
            min_interval = float(np.min(intervals))
            max_interval = float(np.max(intervals))
            cv = std_interval / max(mean_interval, 1e-6)

            # Burst detection (coefficient of variation of intervals)
            burst_score = min(1.0, cv / 2.0)

            # Periodicity detection (autocorrelation at lag 1)
            if len(intervals) > 1:
                autocorr = float(np.corrcoef(intervals[:-1], intervals[1:])[0, 1])
            else:
                autocorr = 0.0

            # Event type diversity in window
            event_types = [e.get(feature_key, 0) for e in window]
            unique_types = len(set(event_types))
            type_diversity = unique_types / max(len(event_types), 1)

            features_list.append([
                mean_interval,
                std_interval / max(mean_interval, 1e-6),
                min_interval,
                max_interval,
                cv,
                burst_score,
                abs(autocorr),
                type_diversity,
                1.0 if burst_score > 0.7 else 0.0,
                1.0 if autocorr > 0.8 else 0.0,
                mean_interval / 3600.0,
                len(intervals),
            ])

        return np.array(features_list, dtype=float)


def create_deep_feature_extractor(input_dim: int) -> DeepFeatureExtractor | None:
    """Factory function to create deep feature extractor if PyTorch available."""
    if not HAS_TORCH:
        logger.warning("PyTorch not installed; deep feature extraction unavailable")
        return None
    return DeepFeatureExtractor(input_dim=input_dim)

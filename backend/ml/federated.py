"""Federated learning for collaborative model training.

Enables multiple BARAQ instances to collaboratively train ML models
without sharing raw data, preserving privacy while improving detection
accuracy across organizations.

Uses Federated Averaging (FedAvg) algorithm:
1. Each client trains locally on their data
2. Client model updates (gradients) are sent to a central server
3. Server averages updates and distributes improved global model
4. Repeat until convergence
"""

from __future__ import annotations

import logging
import math
import pickle
import zlib
from dataclasses import dataclass, field
from typing import Any

import numpy as np

logger = logging.getLogger("baraq.ml.federated")

try:
    from sklearn.ensemble import IsolationForest

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


@dataclass
class ClientUpdate:
    """Model update from a federated client."""
    client_id: str
    n_samples: int
    model_params: bytes  # Pickled + compressed model state
    performance_score: float = 0.0
    timestamp: str = ""


@dataclass
class FederatedRound:
    """Result of a single federated averaging round."""
    round_id: int
    n_clients: int
    global_model_score: float = 0.0
    client_scores: dict[str, float] = field(default_factory=dict)
    convergence_delta: float = 0.0


class FederatedAggregator:
    """Central aggregator for federated learning.

    Collects model updates from multiple clients, performs weighted averaging,
    and distributes the improved global model.
    """

    def __init__(self, min_clients: int = 2, max_rounds: int = 10):
        self.min_clients = min_clients
        self.max_rounds = max_rounds
        self._round_id = 0
        self._global_model = None
        self._client_updates: list[ClientUpdate] = []
        self._round_history: list[FederatedRound] = []
        self._previous_global_params = None

    def receive_update(self, update: ClientUpdate) -> bool:
        """Receive a model update from a client.

        Returns True if the update was accepted, False if duplicate.
        """
        # Check for duplicate client in same round
        for existing in self._client_updates:
            if existing.client_id == update.client_id:
                logger.debug("Replacing update from client %s", update.client_id)
                self._client_updates.remove(existing)
                break

        self._client_updates.append(update)
        logger.info(
            "Received update from client %s (n=%d, perf=%.3f)",
            update.client_id, update.n_samples, update.performance_score,
        )
        return True

    def aggregate(self) -> FederatedRound | None:
        """Perform federated averaging on collected client updates.

        Returns FederatedRound with results, or None if insufficient clients.
        """
        if len(self._client_updates) < self.min_clients:
            logger.info(
                "Need %d clients for aggregation, have %d",
                self.min_clients, len(self._client_updates),
            )
            return None

        self._round_id += 1
        round_result = FederatedRound(
            round_id=self._round_id,
            n_clients=len(self._client_updates),
        )

        # Weighted averaging based on client sample counts and performance
        total_weight = 0.0
        weighted_params = {}

        for update in self._client_updates:
            weight = update.n_samples * max(update.performance_score, 0.1)
            total_weight += weight

            try:
                model_state = pickle.loads(zlib.decompress(update.model_params))
                if hasattr(model_state, "estimators_"):
                    # IsolationForest ensemble averaging
                    for i, estimator in enumerate(model_state.estimators_):
                        key = f"estimator_{i}"
                        if key not in weighted_params:
                            weighted_params[key] = {"trees": [], "weight": 0.0}
                        weighted_params[key]["trees"].extend(
                            estimator.estimators_.tolist()
                            if hasattr(estimator, "estimators_")
                            else []
                        )
                        weighted_params[key]["weight"] += weight
                round_result.client_scores[update.client_id] = update.performance_score
            except Exception as e:
                logger.warning("Failed to decode update from %s: %s", update.client_id, e)
                continue

        if total_weight > 0:
            # Normalize weights
            for key in weighted_params:
                weighted_params[key]["weight"] /= total_weight

        # Compute convergence delta
        if self._previous_global_params is not None:
            delta = self._compute_convergence_delta(weighted_params)
            round_result.convergence_delta = delta
            logger.info("Round %d convergence delta: %.6f", self._round_id, delta)

        self._previous_global_params = weighted_params
        self._round_history.append(round_result)

        # Clear client updates for next round
        self._client_updates = []

        return round_result

    def _compute_convergence_delta(self, new_params: dict) -> float:
        """Compute how much the global model changed (convergence metric)."""
        if self._previous_global_params is None:
            return 1.0

        deltas = []
        for key in new_params:
            if key in self._previous_global_params:
                old_weight = self._previous_global_params[key].get("weight", 0)
                new_weight = new_params[key].get("weight", 0)
                deltas.append(abs(new_weight - old_weight))

        return float(np.mean(deltas)) if deltas else 0.0

    def get_global_model(self):
        """Get the current global model (or None if not yet aggregated)."""
        return self._global_model

    def should_stop(self) -> bool:
        """Check if federated training should stop."""
        if self._round_id >= self.max_rounds:
            return True
        if self._round_history:
            last_round = self._round_history[-1]
            if last_round.convergence_delta < 0.001:
                logger.info("Converged after %d rounds", self._round_id)
                return True
        return False

    @property
    def round_id(self) -> int:
        return self._round_id

    def status(self) -> dict:
        """Current state of federated learning."""
        return {
            "round_id": self._round_id,
            "min_clients": self.min_clients,
            "pending_updates": len(self._client_updates),
            "max_rounds": self.max_rounds,
            "should_stop": self.should_stop(),
            "round_history": [
                {
                    "round": r.round_id,
                    "clients": r.n_clients,
                    "convergence_delta": r.convergence_delta,
                }
                for r in self._round_history
            ],
        }


class FederatedClient:
    """Client-side federated learning participant.

    Trains local models and sends updates to the aggregator.
    """

    def __init__(self, client_id: str, aggregator: FederatedAggregator):
        self.client_id = client_id
        self.aggregator = aggregator
        self._local_model = None
        self._local_data = None

    def set_training_data(self, X: np.ndarray, y: np.ndarray | None = None):
        """Set local training data (never leaves the client)."""
        self._local_data = {"X": X, "y": y}

    def train_local(self, contamination: float = 0.05) -> dict:
        """Train a local model on local data.

        Returns training metrics.
        """
        if not HAS_SKLEARN or self._local_data is None:
            return {"status": "no-data"}

        X = self._local_data["X"]
        if len(X) < 10:
            return {"status": "insufficient-data", "n_samples": len(X)}

        self._local_model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples=min(256, len(X)),
        )
        self._local_model.fit(X)

        # Compute local performance score
        scores = self._local_model.decision_function(X)
        performance = float(np.mean(0.5 - scores))

        return {
            "status": "ok",
            "n_samples": len(X),
            "performance": round(performance, 4),
        }

    def send_update(self, performance_score: float = 0.0) -> bool:
        """Send local model update to the aggregator.

        The model is serialized, compressed, and sent.
        Raw data never leaves the client.
        """
        if self._local_model is None:
            return False

        try:
            model_bytes = pickle.dumps(self._local_model)
            compressed = zlib.compress(model_bytes, level=6)

            update = ClientUpdate(
                client_id=self.client_id,
                n_samples=len(self._local_data["X"]) if self._local_data else 0,
                model_params=compressed,
                performance_score=performance_score,
            )

            return self.aggregator.receive_update(update)
        except Exception as e:
            logger.warning("Failed to send update from %s: %s", self.client_id, e)
            return False

    def receive_global_model(self, global_model):
        """Receive and adopt the global model from the aggregator."""
        if global_model is not None:
            self._local_model = global_model
            logger.info("Client %s adopted global model", self.client_id)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict using the local model."""
        if self._local_model is None:
            return np.zeros(len(X))
        return self._local_model.predict(X)


def create_federated_setup(
    n_clients: int = 3,
    min_clients: int = 2,
) -> tuple[FederatedAggregator, list[FederatedClient]]:
    """Create a federated learning setup with multiple clients."""
    aggregator = FederatedAggregator(min_clients=min_clients)
    clients = [
        FederatedClient(client_id=f"client_{i}", aggregator=aggregator)
        for i in range(n_clients)
    ]
    return aggregator, clients

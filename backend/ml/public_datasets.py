"""Public dataset evaluation framework for ML models.

Provides adapters and evaluation pipelines for testing against standard
cybersecurity datasets to benchmark ML performance.

Supported datasets:
- CICIDS2017/2018: Canadian Institute for Cybersecurity intrusion detection
- UNSW-NB15: University of New South Wales network intrusion detection
- CTU-13: Czech Technical University botnet dataset
- MITRE ATT&CK Evaluations: Adversary emulation results
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import numpy as np

logger = logging.getLogger("baraq.ml.evaluation")


class DatasetType(str, Enum):
    CICIDS2017 = "cicids2017"
    UNSW_NB15 = "unsw_nb15"
    CTU13 = "ctu13"
    MITRE_ATTACK = "mitre_attack"


@dataclass
class EvaluationResult:
    """Standardized evaluation result across all datasets."""
    dataset_name: str
    n_samples: int
    n_benign: int
    n_attack: int
    metrics: dict = field(default_factory=dict)
    per_class_metrics: dict = field(default_factory=dict)
    feature_importance: list[float] = field(default_factory=list)
    confusion_matrix: dict = field(default_factory=dict)


class DatasetAdapter:
    """Base class for public dataset adapters.

    Converts public dataset formats to BARAQ's feature space
    for standardized evaluation.
    """

    def __init__(self, dataset_path: str | Path):
        self.dataset_path = Path(dataset_path)
        self.is_loaded = False
        self._data = None
        self._labels = None

    def load(self) -> bool:
        """Load and parse the dataset. Returns True if successful."""
        raise NotImplementedError

    def get_features(self) -> np.ndarray:
        """Get feature matrix in BARAQ's expected format."""
        if not self.is_loaded:
            raise RuntimeError("Dataset not loaded")
        return self._data

    def get_labels(self) -> np.ndarray:
        """Get binary labels (0=benign, 1=attack)."""
        if not self.is_loaded:
            raise RuntimeError("Dataset not loaded")
        return self._labels

    def evaluate_model(self, model, X_test: np.ndarray, y_test: np.ndarray) -> EvaluationResult:
        """Evaluate a trained model against this dataset."""
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            confusion_matrix, roc_auc_score,
        )

        y_pred = model.predict(X_test)
        # IF predicts -1 for anomaly, 1 for normal
        y_pred_binary = (y_pred == -1).astype(int)

        cm = confusion_matrix(y_test, y_pred_binary)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        return EvaluationResult(
            dataset_name=self.dataset_path.name,
            n_samples=len(X_test),
            n_benign=int(np.sum(y_test == 0)),
            n_attack=int(np.sum(y_test == 1)),
            metrics={
                "accuracy": round(float(accuracy_score(y_test, y_pred_binary)), 4),
                "precision": round(float(precision_score(y_test, y_pred_binary, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, y_pred_binary, zero_division=0)), 4),
                "f1": round(float(f1_score(y_test, y_pred_binary, zero_division=0)), 4),
                "auc_roc": round(float(roc_auc_score(y_test, y_pred_binary)) if len(np.unique(y_test)) > 1 else 0.0, 4),
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn),
            },
        )


class CICIDSAdapter(DatasetAdapter):
    """Adapter for CICIDS2017/2018 datasets.

    Expected CSV format with columns:
    Flow Duration, Total Fwd Packets, Total Bwd Packets,
    Total Length of Fwd Packets, Total Length of Bwd Packets,
    Fwd Packet Length Mean, Bwd Packet Length Mean, Label, etc.
    """

    def load(self) -> bool:
        try:
            import pandas as pd
            df = pd.read_csv(self.dataset_path)

            # Map multi-class labels to binary
            label_col = "Label" if "Label" in df.columns else df.columns[-1]
            df["is_attack"] = df[label_col].apply(
                lambda x: 0 if str(x).strip().lower() in ("benign", "normal") else 1
            )

            # Select numeric features
            feature_cols = [c for c in df.columns if c != label_col and c != "is_attack"
                          and df[c].dtype in (np.float64, np.int64, np.float32, np.int32)]

            self._data = df[feature_cols].fillna(0).values.astype(float)
            self._labels = df["is_attack"].values.astype(int)
            self.is_loaded = True
            logger.info("Loaded CICIDS dataset: %d samples, %d features", len(self._data), len(feature_cols))
            return True
        except Exception as e:
            logger.warning("Failed to load CICIDS dataset: %s", e)
            return False


class UNSWNB15Adapter(DatasetAdapter):
    """Adapter for UNSW-NB15 dataset."""

    def load(self) -> bool:
        try:
            import pandas as pd
            df = pd.read_csv(self.dataset_path)

            label_col = "label" if "label" in df.columns else "class"
            if label_col in df.columns:
                df["is_attack"] = (df[label_col] != 0).astype(int)
            else:
                df["is_attack"] = 0

            feature_cols = [c for c in df.columns if c != label_col and c != "is_attack"
                          and c != "attack_cat" and df[c].dtype in (np.float64, np.int64, np.float32, np.int32)]

            self._data = df[feature_cols].fillna(0).values.astype(float)
            self._labels = df["is_attack"].values.astype(int)
            self.is_loaded = True
            logger.info("Loaded UNSW-NB15 dataset: %d samples", len(self._data))
            return True
        except Exception as e:
            logger.warning("Failed to load UNSW-NB15 dataset: %s", e)
            return False


def create_adapter(dataset_type: DatasetType, path: str | Path) -> DatasetAdapter | None:
    """Factory function to create the appropriate dataset adapter."""
    adapters = {
        DatasetType.CICIDS2017: CICIDSAdapter,
        DatasetType.UNSW_NB15: UNSWNB15Adapter,
    }
    adapter_cls = adapters.get(dataset_type)
    if adapter_cls is None:
        logger.warning("Unsupported dataset type: %s", dataset_type)
        return None
    return adapter_cls(path)


def evaluate_on_public_dataset(
    model,
    adapter: DatasetAdapter,
    max_samples: int = 10000,
) -> EvaluationResult | None:
    """Evaluate a trained model on a public dataset.

    Args:
        model: Trained IsolationForest or similar model
        adapter: Loaded dataset adapter
        max_samples: Maximum samples to evaluate (for speed)

    Returns:
        EvaluationResult or None if evaluation fails
    """
    if not adapter.is_loaded:
        if not adapter.load():
            return None

    X = adapter.get_features()
    y = adapter.get_labels()

    # Subsample if needed
    if len(X) > max_samples:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(X), max_samples, replace=False)
        X, y = X[idx], y[idx]

    try:
        return adapter.evaluate_model(model, X, y)
    except Exception as e:
        logger.warning("Evaluation failed: %s", e)
        return None

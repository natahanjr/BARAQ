"""External SOC dataset adapters for BARAQ ML training.

Converts third-party datasets (BOTSv1, BOTES, OTRF Security-Datasets)
into BARAQ-normalized event dicts compatible with the training pipeline.
"""

from backend.ml.dataset_adapters.base import (
    AdapterResult,
    BaseAdapter,
    NormalizedEventDict,
)
from backend.ml.dataset_adapters.botes import BotesAdapter
from backend.ml.dataset_adapters.botsv1 import Botsv1Adapter
from backend.ml.dataset_adapters.security_datasets import SecurityDatasetsAdapter

ADAPTERS = {
    "botsv1": Botsv1Adapter,
    "botes": BotesAdapter,
    "security_datasets": SecurityDatasetsAdapter,
}

__all__ = [
    "ADAPTERS",
    "AdapterResult",
    "BaseAdapter",
    "BotesAdapter",
    "Botsv1Adapter",
    "NormalizedEventDict",
    "SecurityDatasetsAdapter",
]

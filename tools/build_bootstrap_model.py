"""Build (or rebuild) the shipped bootstrap ML model.

Trains a seed detector on the deterministic synthetic corpus inside a
throwaway PostgreSQL database and writes
``backend/ml/assets/bootstrap_model.joblib`` - the bundle fresh
deployments load on day 1 until their first real retrain.

Usage:
    venv\\Scripts\\python tools\\build_bootstrap_model.py [--seed 42]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output",
        default=None,
        help="override bundle output path (default: configured asset path)",
    )
    args = parser.parse_args()

    from backend.ml.bootstrap import build_bootstrap_model

    summary = build_bootstrap_model(output_path=args.output, seed=args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

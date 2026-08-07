"""Automated rule-threshold tuning via grid search (methodology v2).

Addresses the "high configuration sensitivity" limitation (no principled
way to set rule parameters) and the v1 methodology gaps:

1. **Honest precision.** v1 counted FP as "unexpected rules fired on the
   attack corpus" and had no benign baseline, so precision could never
   degrade. v2 maintains a *separate benign-only database* (shared baseline
   + hard benign scenarios) and any finding fired on it is a false positive,
   so tuning genuinely trades recall against precision.
2. **Fixture decoupling.** v1 evaluated one deterministic arrangement of
   attack fixtures, which were calibrated to fire under the current
   defaults (circular). v2 builds ``--variants`` seeded, domain-randomized
   copies of each attack scenario (via
   ``backend.evaluation.holdout._randomize_records``) in *separate*
   databases and sums the metrics, so results are robust to timing/IP
   placement and not tied to one synthetic arrangement.
3. **Independent labeled corpus support.** Pass ``--corpus`` a JSONL file
   (one record per line, same shape as the fixture builders return) to
   tune against a deployment's own labeled dataset instead of the
   synthetic fixtures.

Usage:
    python scripts/tune_parameters.py [--variants 3] [--seed 20260806] [--corpus path.jsonl]

The script is read-only: it never writes config; it only prints the
recommended thresholds so the operator can set them (env or config).
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("SENTINEL_DATABASE_URL", f"sqlite:///{Path(tempfile.gettempdir()) / 'sentinel_tune.db'}")
os.environ.setdefault("SENTINEL_SKIP_SECRET_GEN", "1")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from backend.database.models import Base  # noqa: E402
from backend.detection.rules_engine import build_rules  # noqa: E402
from backend.evaluation.holdout import _randomize_records  # noqa: E402

#: scenario -> rule id expected to fire (the labelled attack corpus).
EXPECTED_RULE = {
    "brute_force": "brute_force",
    "suspicious_powershell": "suspicious_powershell",
    "privilege_escalation": "privilege_escalation",
    "persistence": "persistence",
    "port_scan": "network_recon",
    "lateral_movement": "lateral_movement",
    "data_staging": "data_staging",
    "phishing_email": "email_phishing",
    "dns_exfil": "dns_http_exfil",
    "log_clear": "log_clearing",
    "lolbin_usage": "lolbin_execution",
}

#: benign-only builders; NO rule should fire on any of these.
BENIGN_BUILDERS = (
    "benign_baseline",
    "benign_process",
    "sysmon_lsass_benign",
    "sysmon_benign_registry",
)

GRID = {
    "brute_force": {"threshold": [5, 12, 20]},
    "network_recon": {
        "distinct_ports": [20, 40, 60],
        "window_seconds": [30, 120, 300],
    },
    "email_phishing": {"threshold": [1.5, 3.0, 5.0]},
}


def _new_session():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="sentinel_tune_")
    os.close(fd)
    engine = create_engine("sqlite:///" + path)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _build_attack_sessions(seed: int, variants: int, corpus_path: str | None) -> list[list[dict]]:
    """One independent record list per randomized attack-corpus variant."""
    from tests import fixtures

    if corpus_path:
        with Path(corpus_path).open(encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        base = records
    else:
        base = [rec for name in EXPECTED_RULE if hasattr(fixtures, name) for rec in getattr(fixtures, name)()]

    variants = max(1, variants)
    sessions: list[list[dict]] = []
    for v in range(variants):
        rng = random.Random(seed + v * 100003)
        if variants == 1:
            sessions.append(list(base))
        else:
            sessions.append(_randomize_records(base, rng))
    return sessions


def _build_benign_session():
    """Benign-only session; any finding on it is a false positive."""
    from tests.fixtures import add_normalized
    from tests import fixtures

    session = _new_session()
    for name in BENIGN_BUILDERS:
        add_normalized(session, getattr(fixtures, name)())
    session.commit()
    return session


def _evaluate(session, rules) -> set[str]:
    findings = []
    for rule in rules:
        try:
            findings.extend(rule.evaluate(10))
        except Exception:  # noqa: BLE001
            pass
    return {f.rule for f in findings}


def _score(attack_sessions, benign_session, overrides, window_minutes=10):
    """Return (tp_total, fp, fn_total) across all attack variants + benign.

    tp/fn are summed over the attack variants (each variant is its own DB,
    so no cross-scenario leakage); fp is the set of expected rules that
    fired on the benign-only corpus.
    """
    expected = set(EXPECTED_RULE.values())
    tp_total = fn_total = 0
    for records in attack_sessions:
        session = _new_session()
        from tests.fixtures import add_normalized

        add_normalized(session, records)
        session.commit()
        rules = build_rules(session, overrides=overrides)
        fired = _evaluate(session, rules)
        tp = len({s for s, r in EXPECTED_RULE.items() if r in fired})
        tp_total += tp
        fn_total += len(EXPECTED_RULE) - tp
        session.close()

    benign_rules = build_rules(benign_session, overrides=overrides)
    fired_benign = _evaluate(benign_session, benign_rules)
    fp = len(fired_benign & expected)
    return tp_total, fp, fn_total


def _combo_overrides(keys, combo) -> dict[str, dict]:
    overrides: dict[str, dict] = {}
    for key, value in zip(keys, combo):
        rule, param = key.split("__", 1)
        overrides.setdefault(rule, {})[param] = value
    return overrides


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--variants", type=int, default=3, help="randomized attack-corpus variants (1 = no randomization)")
    parser.add_argument("--seed", type=int, default=20260806, help="RNG seed for attack randomization")
    parser.add_argument("--corpus", type=str, default="", help="external labeled attack corpus (JSONL)")
    args = parser.parse_args()

    benign_session = _build_benign_session()
    attack_sessions = _build_attack_sessions(args.seed, args.variants, args.corpus or None)

    keys = [f"{rule}__{param}" for rule, params in GRID.items() for param in params]
    grids = {f"{rule}__{param}": vals for rule, params in GRID.items() for param, vals in params.items()}
    combos = list(itertools.product(*(grids[k] for k in keys)))

    variants = len(attack_sessions)
    best = None
    best_zero_fp = None
    print(f"attack variants: {variants} (seed {args.seed}); benign FP corpus: {', '.join(BENIGN_BUILDERS)}")
    print(f"{'combination':80s} {'TP':>3} {'FP':>3} {'FN':>3} {'P':>5} {'R':>5} {'F1':>5}")
    for combo in combos:
        overrides = _combo_overrides(keys, combo)
        tp, fp, fn = _score(attack_sessions, benign_session, overrides)
        fn = int(fn)
        precision = tp / (tp + fp * variants) if (tp + fp * variants) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        label = " ".join(f"{k.split('__')[1]}={v}" for k, v in zip(keys, combo))
        print(f"{label:80s} {tp:3d} {fp:3d} {fn:3d} {precision:5.2f} {recall:5.2f} {f1:5.2f}")
        if best is None or f1 > best[0]:
            best = (f1, combo)
        if fp == 0 and (best_zero_fp is None or recall > best_zero_fp[1]):
            best_zero_fp = (combo, recall)

    def _render(combo) -> dict[str, dict]:
        return _combo_overrides(keys, combo)

    if best:
        f1s, combo = best
        print(f"\nBest overall F1 ({f1s:.4f}) — set these in backend/config.py or env:")
        for rule, params in _render(combo).items():
            print(f"  {rule}: {params}")

    if best_zero_fp:
        combo, recall = best_zero_fp
        print(f"\nBest recall at zero false positives (recall {recall:.4f}):")
        for rule, params in _render(combo).items():
            print(f"  {rule}: {params}")
    else:
        print("\nNo combination achieved zero false positives on the benign corpus.")

    benign_session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
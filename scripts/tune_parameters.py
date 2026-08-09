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
4. **Extended coverage (v3).** The joint grid still covers the three
   most config-sensitive rules (brute force / network recon / phishing),
   and ``PER_RULE_GRID`` sweeps each additional rule independently
   (data staging, lateral movement, exfiltration volume, C2 beacon) so
   the parameter space stays tractable without the joint-product
   combinatorial explosion.
5. **Bayesian optimization (v4).** ``--bayesian N`` replaces the exhaustive
   joint sweep with a Gaussian-process expected-improvement search over the
   same lattice (budget ``N`` evaluations; corners + seeded samples
   initialize the surrogate). The surrogate is deterministic per seed, so
   the recommended thresholds are reproducible exactly like the grid sweep.
   The default exhaustive grid remains the baseline when ``--bayesian`` is
   not passed.

Usage:
    python scripts/tune_parameters.py [--variants 3] [--seed 20260806] [--corpus path.jsonl]
    python scripts/tune_parameters.py --bayesian 40 --seed 20260806

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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault(
    "SENTINEL_DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel"
)
os.environ.setdefault("SENTINEL_SKIP_SECRET_GEN", "1")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from backend.config import DATABASE_URL  # noqa: E402
from backend.database.connection import normalize_database_url  # noqa: E402
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
    "http_exfil": "exfiltration_volume",
    "ml_c2_beacon": "c2_beacon",
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

#: per-rule sweeps run independently (other rules at defaults) so the new
#: rules can be tuned without the joint-grid combinatorial explosion.
PER_RULE_GRID = {
    "lateral_movement": {
        "admin_share_threshold": [2, 3, 5],
        "failed_logon_targets": [2, 3, 5],
    },
    "data_staging": {"min_archive_events": [1, 2, 3]},
    "exfiltration_volume": {
        "bytes_threshold": [2_000_000, 5_000_000, 10_000_000],
        "count_threshold": [250, 400, 600],
    },
    "c2_beacon": {
        "bytes_threshold": [2_000_000, 5_000_000, 10_000_000],
        "min_connections": [2, 3, 5],
        "min_duration_seconds": [30.0, 120.0, 300.0],
    },
}


def _anchored_at_now(records: list[dict]) -> list[dict]:
    """Shift timestamps so the newest record is ~2 s before ``now``.

    Keyed fixtures are stamped relative to build time; a long grid sweep
    (many minutes) ages them out of the rule windows, so every combo must
    score a corpus anchored to the moment it runs, not to script start.
    """
    newest: datetime | None = None
    for rec in records:
        ts = rec.get("timestamp")
        if not isinstance(ts, str):
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if newest is None or dt > newest:
            newest = dt
    if newest is None:
        return records
    offset = (datetime.now(timezone.utc) - newest).total_seconds() - 2
    if offset <= 0:
        return records
    shifted = []
    for rec in records:
        rec = dict(rec)
        if isinstance(rec.get("raw"), dict):
            rec["raw"] = dict(rec["raw"])
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                rec["timestamp"] = (dt + timedelta(seconds=offset)).isoformat()
            except ValueError:
                pass
        shifted.append(rec)
    return shifted


_SCRATCH: list[tuple[object, object, str]] = []


def _new_session():
    """Fresh isolated scratch PostgreSQL database; returns a bound session.

    Tuning sweeps isolate every evaluation (per variant, per benign corpus)
    in its own throwaway database so results never leak across combos; all
    scratch databases are dropped again at the end of the run.
    """
    import uuid

    from sqlalchemy import text as sa_text
    from sqlalchemy.engine import make_url

    base_url = make_url(normalize_database_url(DATABASE_URL))
    db_name = f"sentinel_scratch_{uuid.uuid4().hex[:12]}"

    admin = create_engine(base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(sa_text(f'CREATE DATABASE "{db_name}"'))
    finally:
        admin.dispose()

    engine = create_engine(base_url.set(database=db_name))
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    _SCRATCH.append((session, engine, db_name))
    return session


def _drop_scratch() -> None:
    """Close and drop every scratch database created during this run."""
    from sqlalchemy import text as sa_text
    from sqlalchemy.engine import make_url

    base_url = make_url(normalize_database_url(DATABASE_URL))
    admin = create_engine(base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        while _SCRATCH:
            session, engine, db_name = _SCRATCH.pop()
            try:
                session.close()
                engine.dispose()
            except Exception:  # noqa: BLE001
                pass
            try:
                with admin.connect() as conn:
                    conn.execute(sa_text(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)'))
            except Exception:  # noqa: BLE001
                pass
    finally:
        admin.dispose()


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


def _benign_records() -> list[dict]:
    from tests import fixtures

    return [rec for name in BENIGN_BUILDERS for rec in getattr(fixtures, name)()]


def _build_benign_session():
    """Benign-only session; any finding on it is a false positive."""
    from tests.fixtures import add_normalized

    session = _new_session()
    add_normalized(session, _anchored_at_now(_benign_records()))
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

        add_normalized(session, _anchored_at_now(records))
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


def _lattice(keys, grids) -> list[tuple]:
    """All combinations of the joint grid, in deterministic order."""
    return list(itertools.product(*(grids[k] for k in keys)))


def _metrics(tp, fp, fn, variants: int) -> tuple[float, float, float]:
    """(precision, recall, f1) with the precision denominator as the tune
    script defines it: each false positive is weighted per attack variant."""
    fn = int(fn)
    precision = tp / (tp + fp * variants) if (tp + fp * variants) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _track(combo, tp, fp, fn, variants, best, best_zero_fp):
    """Update the running (best f1, best f1 combo) and (best recall at
    zero FP, combo) trackers. Returns the new tuple pair."""
    _, _, f1 = _metrics(tp, fp, fn, variants)
    if best is None or f1 > best[0]:
        best = (f1, combo)
    if fp == 0:
        _, recall, _ = _metrics(tp, fp, fn, variants)
        if best_zero_fp is None or recall > best_zero_fp[1]:
            best_zero_fp = (combo, recall)
    return best, best_zero_fp


def _bayesian_search(keys, grids, attack_sessions, variants, budget, seed):
    """Gaussian-process expected-improvement search over the joint lattice.

    The objective (F1 on the randomized attack corpus minus benign FPs) is
    treated as a noisy-free black box. A GP surrogate is fit on the evaluated
    lattice points; the next point maximizes expected improvement, snapped to
    the nearest grid levels. Initialization covers the grid corners first,
    then seeded pseudo-random points, so the search is reproducible for a
    given ``--seed``.

    Returns ``(best, best_zero_fp, evaluated_count, total_count)`` with the
    same semantics as the exhaustive sweep.
    """
    try:
        from sklearn.gaussian_process import GaussianProcessRegressor
        from sklearn.gaussian_process.kernels import Matern
    except ImportError:  # pragma: no cover - sklearn is a core dependency
        raise SystemExit("--bayesian requires scikit-learn (pip install scikit-learn)")

    from scipy.stats import norm

    combos = _lattice(keys, grids)
    total = len(combos)
    budget = max(1, min(int(budget), total))

    def _coord(combo) -> list[float]:
        x = []
        for key, value in zip(keys, combo):
            levels = grids[key]
            x.append(0.0 if len(levels) < 2 else levels.index(value) / (len(levels) - 1))
        return x

    rng = random.Random(seed)
    corners = [c for c in combos if all(v in (grids[k][0], grids[k][-1]) for k, v in zip(keys, c))]
    rng.shuffle(corners)
    # Initialization covers grid corners only; anything beyond stays for
    # surrogate-guided evaluations, otherwise the GP never gets to pick.
    init_count = min(budget, max(2, len(corners)))
    initial = corners[:init_count]

    evaluated: dict[tuple, float] = {}
    best = None
    best_zero_fp = None
    gp = GaussianProcessRegressor(
        kernel=Matern(length_scale=[0.25] * len(keys), nu=2.5),
        alpha=1e-6,
        normalize_y=True,
        random_state=seed,
    )

    for combo in initial:
        overrides = _combo_overrides(keys, combo)
        benign_session = _build_benign_session()
        tp, fp, fn = _score(attack_sessions, benign_session, overrides)
        benign_session.close()
        _, _, f1 = _metrics(tp, fp, fn, variants)
        evaluated[combo] = f1
        best, best_zero_fp = _track(combo, tp, fp, fn, variants, best, best_zero_fp)
        label = " ".join(f"{k.split('__')[1]}={v}" for k, v in zip(keys, combo))
        print(f"  [BO init] {label:76s} TP {tp:2d} FP {fp} FN {fn:2d} F1 {f1:.2f}")

    while len(evaluated) < budget:
        X = np.array([_coord(c) for c in evaluated])
        y = np.array([-f1 for f1 in evaluated.values()])
        gp.fit(X, y)
        candidates = [c for c in combos if c not in evaluated]
        if not candidates:
            break
        Xc = np.array([_coord(c) for c in candidates])
        mu, sd = gp.predict(Xc, return_std=True)
        sd = np.maximum(sd, 1e-9)
        best_y = float(y.min())
        gamma = (best_y - mu - 0.01) / sd
        ei = sd * (gamma * norm.cdf(gamma) + norm.pdf(gamma))
        combo = candidates[int(np.argmax(ei))]
        overrides = _combo_overrides(keys, combo)
        benign_session = _build_benign_session()
        tp, fp, fn = _score(attack_sessions, benign_session, overrides)
        benign_session.close()
        _, _, f1 = _metrics(tp, fp, fn, variants)
        evaluated[combo] = f1
        best, best_zero_fp = _track(combo, tp, fp, fn, variants, best, best_zero_fp)
        label = " ".join(f"{k.split('__')[1]}={v}" for k, v in zip(keys, combo))
        print(f"  [BO step] {label:76s} TP {tp:2d} FP {fp} FN {fn:2d} F1 {f1:.2f}")

    return best, best_zero_fp, len(evaluated), total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--variants", type=int, default=3, help="randomized attack-corpus variants (1 = no randomization)")
    parser.add_argument("--seed", type=int, default=20260806, help="RNG seed for attack randomization")
    parser.add_argument("--corpus", type=str, default="", help="external labeled attack corpus (JSONL)")
    parser.add_argument("--bayesian", type=int, default=0,
                        help="use GP expected-improvement search over the joint grid with this many evaluations (default: exhaustive grid)")
    args = parser.parse_args()

    try:
        attack_sessions = _build_attack_sessions(args.seed, args.variants, args.corpus or None)
        _sweep(args, attack_sessions)
    finally:
        _drop_scratch()
    return 0


def _sweep(args, attack_sessions: list[list[dict]]) -> None:
    keys = [f"{rule}__{param}" for rule, params in GRID.items() for param in params]
    grids = {f"{rule}__{param}": vals for rule, params in GRID.items() for param, vals in params.items()}
    combos = _lattice(keys, grids)

    variants = len(attack_sessions)
    best = None
    best_zero_fp = None
    print(f"attack variants: {variants} (seed {args.seed}); benign FP corpus: {', '.join(BENIGN_BUILDERS)}")
    if args.bayesian > 0:
        print(f"Bayesian tuning: GP expected-improvement, budget {args.bayesian} of {len(combos)} joint-grid combinations")
        best, best_zero_fp, used, total = _bayesian_search(
            keys, grids, attack_sessions, variants, args.bayesian, args.seed
        )
        print(f"\nEvaluated {used} of {total} joint-grid combinations "
              f"({100.0 * used / max(total, 1):.1f}% of the exhaustive lattice).")
    else:
        print(f"{'combination':80s} {'TP':>3} {'FP':>3} {'FN':>3} {'P':>5} {'R':>5} {'F1':>5}")
        for combo in combos:
            overrides = _combo_overrides(keys, combo)
            # Fresh benign session per combo: anchored timestamps keep the FP
            # corpus inside the rule windows no matter how long the sweep runs.
            benign_session = _build_benign_session()
            tp, fp, fn = _score(attack_sessions, benign_session, overrides)
            benign_session.close()
            precision, recall, f1 = _metrics(tp, fp, fn, variants)
            label = " ".join(f"{k.split('__')[1]}={v}" for k, v in zip(keys, combo))
            print(f"{label:80s} {tp:3d} {fp:3d} {fn:3d} {precision:5.2f} {recall:5.2f} {f1:5.2f}")
            best, best_zero_fp = _track(combo, tp, fp, fn, variants, best, best_zero_fp)

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

    print("\nPer-rule sweeps (each rule tuned independently, others at defaults):")
    recommended: dict[str, dict] = {}
    for rule, params in PER_RULE_GRID.items():
        rkeys = [f"{rule}__{p}" for p in params]
        rgrids = {f"{rule}__{p}": vals for p, vals in params.items()}
        rcombos = list(itertools.product(*(rgrids[k] for k in rkeys)))
        rule_best = None
        rule_best_zero = None
        for combo in rcombos:
            overrides = _combo_overrides(rkeys, combo)
            benign_session = _build_benign_session()
            tp, fp, fn = _score(attack_sessions, benign_session, overrides)
            benign_session.close()
            precision = tp / (tp + fp * variants) if (tp + fp * variants) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            label = " ".join(f"{p}={v}" for p, v in zip(rkeys, combo))
            print(f"  [{rule}] {label:60s} TP {tp:2d} FP {fp} FN {fn:2d} F1 {f1:.2f}")
            if rule_best is None or f1 > rule_best[0]:
                rule_best = (f1, combo)
            if fp == 0 and (rule_best_zero is None or recall > rule_best_zero[1]):
                rule_best_zero = (combo, recall)
        if rule_best:
            f1s, combo = rule_best
            print(f"  -> best {rule} F1 ({f1s:.4f}): {_combo_overrides(rkeys, combo)[rule]}")
        if rule_best_zero:
            combo, recall = rule_best_zero
            print(f"  -> best {rule} recall at zero FP ({recall:.4f}): {_combo_overrides(rkeys, combo)[rule]}")


if __name__ == "__main__":
    raise SystemExit(main())
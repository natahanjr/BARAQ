"""Bootstrap model builder - day-1 cold-start seed for fresh deployments.

A fresh BARAQ deployment used to start with a blind ML detector (default
thresholds, no supervised opinion) until enough real telemetry accrued for
the first local retrain. This module trains a *seed* model offline on a
deterministic synthetic corpus and ships it with the product
(``backend/ml/assets/bootstrap_model.joblib``).

At runtime ``MLAnomalyDetector._load_bootstrap()`` picks the asset up when
no locally-trained bundle exists; the first real retrain supersedes it.

The corpus is generated from the same scenario fixtures the evaluation
framework uses, with seeded domain randomization (timing / address / user
jitter) so the IsolationForest baselines are non-degenerate while every run
of this module produces an equivalent model.
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("baraq.ml.bootstrap")

#: Attack scenarios per behavior stream used in the bootstrap corpus.
#: Login/process scenarios teach the supervised second opinion what local
#: attack patterns look like; network scenarios carry TEST-NET remote IPs
#: which label the per-IP flow buckets as attacks.
CORPUS_ATTACK_SCENARIOS: list[str] = [
    # login stream
    "brute_force",
    "ml_credential_spray",
    "pass_the_hash",
    "kerberoast",
    # process stream
    "suspicious_powershell",
    "ml_obfuscated_powershell",
    "privilege_escalation",
    "persistence",
    "ml_implant_drop",
    "ml_hidden_script",
    "masquerading_process",
    "lsass_dump",
    # network stream (TEST-NET labelled)
    "port_scan",
    "ml_c2_beacon",
    "ml_network_exfil",
    "ml_lateral_c2",
    "dns_tunnel",
    "encrypted_channel",
]

#: How many randomized copies of each attack scenario enter the corpus.
#: Deliberately benign-heavy (~2:1) so the CFAR quantile thresholds stay
#: conservative on day 1 - false positives cost analyst trust.
ATTACK_VARIANTS = 4
BENIGN_RECORDS = 1500


def _jitter_records(records: list[dict], rng: random.Random) -> list[dict]:
    """Seeded domain randomization: timing, addresses, users, hosts.

    Keeps fact semantics intact (event ids, encoded-PowerShell markers,
    TEST-NET prefixes) while varying everything the model should treat as
    noise - so thresholds generalize beyond one deterministic fixture.
    """
    out: list[dict] = []
    shift = timedelta(minutes=rng.randint(-14 * 24 * 60, 14 * 24 * 60))
    users = ["alice", "bob", "carol", "dave", "erin", "svc_backup", "jdoe"]
    hosts = ["WS-01", "WS-02", "SRV-db", "SRV-web", "LAPTOP-7"]
    octets = lambda: rng.randint(2, 254)  # noqa: E731

    def _mutate_ip(ip: str, testnet: bool) -> str:
        if not ip or not isinstance(ip, str):
            return ip
        if testnet and (ip.startswith("203.0.113.") or ip.startswith("198.51.100.")):
            return f"{ip.rsplit('.', 1)[0]}.{octets()}"
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{octets()}.{octets()}"
        return ip

    for rec in records:
        r = dict(rec)
        ts = r.get("timestamp")
        if isinstance(ts, datetime):
            r["timestamp"] = ts + shift
        elif isinstance(ts, str):
            try:
                r["timestamp"] = datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                ) + shift
            except ValueError:
                pass
        r["user"] = rng.choice(users)
        r["host"] = rng.choice(hosts)
        if r.get("source_ip"):
            r["source_ip"] = _mutate_ip(str(r["source_ip"]), testnet=False)
        raw = r.get("raw_json")
        if isinstance(raw, dict):
            raw2 = dict(raw)
            facts = raw2.get("facts")
            if isinstance(facts, dict):
                f2 = dict(facts)
                for key in ("source_ip", "remote_ip"):
                    if f2.get(key):
                        f2[key] = _mutate_ip(str(f2[key]), testnet=True)
                raw2["facts"] = f2
            r["raw_json"] = raw2
        out.append(r)
    return out


def build_corpus(seed: int = 42) -> list[dict]:
    """Deterministic synthetic corpus: benign baseline + varied attacks."""
    from tests import fixtures

    rng = random.Random(seed)
    records: list[dict] = list(fixtures.benign_baseline(BENIGN_RECORDS))
    for scenario in CORPUS_ATTACK_SCENARIOS:
        fn = getattr(fixtures, scenario, None)
        if fn is None:
            logger.warning("bootstrap corpus: unknown scenario %s", scenario)
            continue
        for _ in range(ATTACK_VARIANTS):
            records += _jitter_records(fn(), rng)
    return records


def build_bootstrap_model(
    output_path: str | Path | None = None, seed: int = 42
) -> dict:
    """Train on the synthetic corpus inside a scratch DB and save the bundle.

    Returns a summary dict (samples, streams, thresholds, output path).
    """
    import joblib

    from backend.config import (
        ML_BOOTSTRAP_BUNDLE,
        ML_FEATURE_VERSION,
    )
    from backend.ml.anomaly import MLAnomalyDetector
    from backend.evaluation.holdout import _cleanup, _empty_session, _persist

    output = Path(output_path or ML_BOOTSTRAP_BUNDLE).resolve()
    records = build_corpus(seed=seed)

    session, engine, marker = _empty_session()
    try:
        _persist(session, records)
        session.commit()
        detector = MLAnomalyDetector()
        result = detector.train(
            session, hours=None, validate=False, persist=False, kind="bootstrap"
        )
        if not result.get("trained") or not detector.models:
            raise RuntimeError(f"bootstrap training failed: {result}")

        bundle = {
            "feature_version": ML_FEATURE_VERSION,
            "models": detector.models,
            "encoders": detector.encoders,
            "supervised": detector.supervised,
            "supervised_name": detector.supervised_name,
            "supervised_by_stream": detector.supervised_by_stream,
            "supervised_name_by_stream": detector.supervised_name_by_stream,
            "thresholds": detector.thresholds,
            "baselines": {k: v.tolist() for k, v in detector.baselines.items()},
            "version": 0,
            "feedback_weights": {},
            "bootstrap": True,
            "n_samples": detector.n_samples,
            "trained_at": detector.trained_at,
            "corpus_seed": seed,
            "corpus_records": len(records),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, output, compress=3)
        summary = {
            "output": str(output),
            "records": len(records),
            "samples": detector.n_samples,
            "streams": sorted(detector.models.keys()),
            "supervised": detector.supervised_name,
            "supervised_streams": dict(detector.supervised_name_by_stream),
            "thresholds": {k: round(v, 3) for k, v in detector.thresholds.items()},
            "size_kb": round(output.stat().st_size / 1024, 1),
        }
        logger.info("Bootstrap model written: %s", summary)
        return summary
    finally:
        try:
            _cleanup(session, engine, marker)
        except Exception:  # noqa: BLE001
            logger.warning("scratch db %s left behind", marker)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(build_bootstrap_model())

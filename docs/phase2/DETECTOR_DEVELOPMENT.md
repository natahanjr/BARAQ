# Phase 2: Detector Development Guide

How to add a deterministic, explainable detector to the v2 engine.

## Anatomy

Every detector lives in `backend/detection/detectors/d0NN_<name>.py` and
subclasses `Detector` (`backend/detection/registry.py`):

```python
class MyDetector(Detector):
    id = "D006"                      # unique, registry order
    version = "1.0.0"                # bump on behavior change
    name = "My Detector"
    description = "what it detects, when, and why"
    enabled = True
    supported_event_types = ("authentication",)  # () = any event

    def supports(self, event) -> bool:
        # True -> evaluate() may be called for this event type

    def evaluate(self, event, context=None) -> DETECTION | None:
        # pure decision; None = no detection
```

Register in `backend/detection/detectors/__init__.py`; the registry
asserts unique ids and emits detectors in registration order
(`D001..D005` today).

## Hard rules

1. **Deterministic.** Same events -> same detections. No wall-clock, no
   randomness, no mutable module state. `detection_id` must be a pure
   function of the campaign key.
2. **Explainable.** Every detection carries per-field evidence:
   `Evidence("source_ip", "203.0.113.5", "Source classified as external/public")`.
   Never `Evidence("rule", "...", "Rule matched")`.
3. **No side effects.** `evaluate()` must never write anywhere. Window
   queries use `DetectionContext` (`events_in_window`, `_stored` probe) —
   read-only SELECTs on `v2_events`.
4. **Versioned.** Any change to thresholds, keys, confidence or evidence
   bumps `version`. Old versions remain readable in `detections`.
5. **Never false-positive on noise.** A single benign event must not
   fire. Thresholds aggregate over a documented window (e.g. D002: 10
   failures / 15 min; D005: 20 file modifications / 5 min).
6. **Gated on `event_type`.** Use `supported_event_types` so the
   detector only sees canonical classes it understands. The generic
   normalizer derives `event_type` from `action` when a record lacks it.

## Deterministic thresholds / confidence

* Thresholds are module-level constants (e.g. `FAILURE_THRESHOLD = 10`).
* Crossing rule: fire when `count % threshold == 0` and
  `count >= threshold` — deterministic, replayable, no last-write races.
* Confidence is a documented additive formula, clamped to 1.0, rounded
  to 3 decimals. Each term is a real, named signal (e.g. D001:
  `0.70 + 0.15 logon_type + 0.10 external + 0.02 host + 0.02 user`).
* Severity escalates monotonically with count (D002: medium 10–29,
  high >= 30, or >= 20 with a success in window).

## Tests (required for every detector)

`tests/detection/test_d0NN_<name>.py` must cover:

* positive case(s) — including boundary (exactly the threshold) and
  crossing multiples,
* negative case(s) — including single benign events and off-by-one,
* missing-field robustness (no `path`, no `logon_type`, ...),
* duplicate replay (identical event -> same `detection_id`),
* severity + confidence exact values,
* MITRE mapping,
* evidence contents (field/value/reason),
* determinism (two runs, identical results).

Window-based detectors seed events with `tests/detection/helpers.py`
(`seed_events`, `stored_events`, `row_to_event`) and always evaluate the
**stored, enriched** events — never re-normalized copies.

See `tests/detection/` for the current detector suites, the shared
benchmark (`evaluation_data.py`, SC-001..SC-008) and the metrics runner
(`test_evaluation.py`).

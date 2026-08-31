"""Tests for attack path prediction."""
from backend.ml.attack_path import AttackPathPredictor, AttackStep


def test_predict_next_steps():
    predictor = AttackPathPredictor()
    steps = predictor.predict_next_steps(["execution"])
    assert len(steps) > 0
    assert all(isinstance(s, AttackStep) for s in steps)


def test_predict_follows_matrix():
    predictor = AttackPathPredictor()
    steps = predictor.predict_next_steps(["initial-access"])
    tactics = [s.tactic for s in steps]
    assert "execution" in tactics


def test_build_attack_path():
    predictor = AttackPathPredictor()
    path = predictor.build_attack_path("initial-access", ["initial-access"])
    assert path.entry_point == "initial-access"
    assert len(path.steps) > 0
    assert path.risk_score > 0


def test_blast_radius_empty():
    predictor = AttackPathPredictor()
    result = predictor.analyze_blast_radius("host-01", [])
    assert result["blast_radius"] == 0
    assert result["risk_level"] == "low"


def test_blast_radius_high():
    predictor = AttackPathPredictor()
    entities = [f"entity-{i}" for i in range(25)]
    result = predictor.analyze_blast_radius("host-01", entities)
    assert result["blast_radius"] == 25
    assert result["risk_level"] == "critical"


def test_empty_current_tactics():
    predictor = AttackPathPredictor()
    steps = predictor.predict_next_steps([])
    assert isinstance(steps, list)

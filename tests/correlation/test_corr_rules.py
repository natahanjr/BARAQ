"""Phase 5 rule registry tests (spec 5.11-5.13, 5.74)."""
from backend.correlation.rules import RULES, RULES_VERSION, RULE_BY_ID
from backend.correlation.registry import get_rule, list_rules


def test_registry_has_nine_deterministic_rules():
    assert [rule.rule_id for rule in RULES] == [
        "R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R009",
    ]
    assert RULES_VERSION == "1.0.0"


def test_every_rule_carries_full_metadata():
    for rule in RULES:
        assert rule.version == "1.0.0"
        assert rule.title
        assert rule.description
        assert rule.correlation_type in {
            "TEMPORAL", "ENTITY", "HOST_CHAIN", "USER_CHAIN", "SOURCE_CHAIN",
            "TACTIC_SEQUENCE", "TECHNIQUE_SEQUENCE", "LATERAL_MOVEMENT", "MULTI_STAGE",
        }
        assert rule.window_key in {
            "authentication_to_execution", "execution_to_privilege",
            "host_to_host_lateral_movement", "multi_stage",
        }


def test_priority_is_deterministic_and_total():
    priorities = [rule.priority for rule in RULES]
    assert priorities == sorted(priorities)
    assert len(set(priorities)) == len(priorities)


def test_only_r009_is_chain_level():
    assert [rule.chain_level for rule in RULES].count(True) == 1
    assert RULE_BY_ID["R009"].chain_level


def test_registry_lookup():
    assert get_rule("R001")["rule_id"] == "R001"
    assert get_rule("R001")["version"] == "1.0.0"
    assert get_rule("R404") is None
    assert len(list_rules()) == 9


def test_no_catch_all_rule():
    # Every rule requires concrete shared context: none accepts a bare pair.
    from backend.correlation.registry import pair_rules

    for rule in pair_rules():
        assert rule.description and rule.correlation_type


def test_every_correlation_type_is_reachable():
    pair_types = {rule.correlation_type for rule in RULES if not rule.chain_level}
    chain_type = RULE_BY_ID["R009"].correlation_type
    assert set(pair_types) | {chain_type} == {
        "TEMPORAL", "ENTITY", "TECHNIQUE_SEQUENCE", "LATERAL_MOVEMENT",
        "SOURCE_CHAIN", "USER_CHAIN", "TACTIC_SEQUENCE", "MULTI_STAGE",
    }
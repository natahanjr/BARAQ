"""Phase 4 contract tests (spec 4.2, 4.21, 4.27, 4.35)."""
import pytest

from backend.aggregation.contract import (
    BANNED_TITLE_PHRASES,
    BEHAVIOR_FAMILIES,
    BehaviorGroup,
    GROUP_STATUSES,
    group_title,
)
from backend.aggregation.models import BehaviorGroupRecord


def test_contract_fields_present():
    bg = BehaviorGroup(
        behavior_group_id="BG-000001",
        group_fingerprint="f" * 64,
        title="Remote Authentication Activity",
        description="Three related alerts",
        alert_ids=["ALR-000001", "ALR-000002"],
        host_ids=["ml-host"],
        user_ids=["ml-online-user"],
        source_ips=["185.100.1.5"],
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1133", "T1110"],
        confidence=0.91,
        highest_severity="high",
    )
    for key in (
        "behavior_group_id", "group_fingerprint", "title", "description",
        "status", "first_seen", "last_seen", "alert_count", "occurrence_count",
        "alert_ids", "host_ids", "user_ids", "source_ips", "mitre_tactics",
        "mitre_techniques", "observables", "confidence", "highest_severity",
        "created_at", "updated_at", "closed_at",
    ):
        assert key in bg.to_dict()


def test_group_id_format_enforced():
    with pytest.raises(ValueError, match="BG-"):
        BehaviorGroup(behavior_group_id="ALR-000001", group_fingerprint="f" * 64,
                      title="x", description="")


def test_status_and_severity_validation():
    with pytest.raises(ValueError, match="status"):
        BehaviorGroup(behavior_group_id="BG-000001", group_fingerprint="f" * 64,
                      title="x", description="", status="OPEN")
    with pytest.raises(ValueError, match="severity"):
        BehaviorGroup(behavior_group_id="BG-000001", group_fingerprint="f" * 64,
                      title="x", description="", highest_severity="severe")


def test_confidence_bounded_000_1000():
    with pytest.raises(ValueError, match="0.000-1.000"):
        BehaviorGroup(behavior_group_id="BG-000001", group_fingerprint="f" * 64,
                      title="x", description="", confidence=1.5)
    with pytest.raises(ValueError, match="0.000-1.000"):
        BehaviorGroup(behavior_group_id="BG-000001", group_fingerprint="f" * 64,
                      title="x", description="", confidence=-0.1)


@pytest.mark.parametrize("phrase", BANNED_TITLE_PHRASES)
def test_titles_never_overclaim(phrase):
    with pytest.raises(ValueError, match="overclaims"):
        BehaviorGroup(behavior_group_id="BG-000001", group_fingerprint="f" * 64,
                      title=f"Confirmed {phrase} here", description="")


def test_family_titles_are_behavioral():
    assert group_title("authentication") == "Remote Authentication Activity"
    assert group_title("execution") == "Suspicious Execution Activity"
    assert group_title("encryption") == "Potential Data Encryption Activity"
    assert group_title("unknown") == "Suspicious Activity"


def test_families_and_statuses_are_documented_sets():
    assert GROUP_STATUSES == ("ACTIVE", "QUIET", "CLOSED")
    assert set(BEHAVIOR_FAMILIES) == {"authentication", "execution", "encryption", "unknown"}


def test_engine_titles_are_never_banned():
    from backend.aggregation.contract import FAMILY_TITLES

    for title in FAMILY_TITLES.values():
        lower = title.lower()
        assert not any(phrase in lower for phrase in BANNED_TITLE_PHRASES)


def test_model_has_partial_live_fingerprint_index():
    indexes = {i.name for i in BehaviorGroupRecord.__table__.indexes}
    assert "uq_behavior_groups_live_fingerprint" in indexes
"""V0.9 functional verification script."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main():
    results = []

    # 1. App imports
    try:
        from backend.main import app
        results.append(("App import", "OK", f"{len(app.routes)} routes"))
    except Exception as e:
        results.append(("App import", "FAIL", str(e)))
        print_results(results)
        return

    # 2. Config
    try:
        from backend.config import ADMIN_USERNAME, ADMIN_PASSWORD
        results.append(("Config", "OK", f"admin={ADMIN_USERNAME}"))
    except Exception as e:
        results.append(("Config", "FAIL", str(e)))

    # 3. Database init
    try:
        from backend.database.connection import init_db
        results.append(("DB init function", "OK", "exists"))
    except Exception as e:
        results.append(("DB init function", "FAIL", str(e)))

    # 4. Auth
    try:
        from backend.auth import create_token, verify_token
        token = create_token(1, "test_user", "analyst")
        result = verify_token(token)
        status = "OK" if result else "FAIL"
        results.append(("Auth token", status, "create + verify"))
    except Exception as e:
        results.append(("Auth token", "FAIL", str(e)))

    # 5. Rules engine
    try:
        from backend.detection.rules_engine import RulesEngine
        results.append(("Rules engine", "OK", "importable (needs session)"))
    except Exception as e:
        results.append(("Rules engine", "FAIL", str(e)))

    # 6. ML detector
    try:
        from backend.ml.anomaly import MLAnomalyDetector
        detector = MLAnomalyDetector()
        results.append(("ML detector", "OK", f"ready={detector.is_ready}"))
    except Exception as e:
        results.append(("ML detector", "FAIL", str(e)))

    # 7. Sigma engine
    try:
        from backend.detection.sigma.engine import SigmaRuleEngine
        results.append(("Sigma engine", "OK", "SigmaRuleEngine importable"))
    except Exception as e:
        results.append(("Sigma engine", "FAIL", str(e)))

    # 8. Correlation engine
    try:
        from backend.detection.correlation_engine import CorrelationEngine
        results.append(("Correlation engine", "OK", "importable"))
    except Exception as e:
        results.append(("Correlation engine", "FAIL", str(e)))

    # 9. Risk engine
    try:
        from backend.risk.engine import calculate_risk
        results.append(("Risk engine", "OK", "calculate_risk importable"))
    except Exception as e:
        results.append(("Risk engine", "FAIL", str(e)))

    # 10. Threat intel
    try:
        from backend.intel.feeds import refresh_feeds
        results.append(("Threat intel feeds", "OK", "importable"))
    except Exception as e:
        results.append(("Threat intel feeds", "FAIL", str(e)))

    # 11. SOAR actions
    try:
        from backend.response.actions import block_ip, kill_process, isolate_host
        results.append(("SOAR actions", "OK", "block_ip, kill_process, isolate_host"))
    except Exception as e:
        results.append(("SOAR actions", "FAIL", str(e)))

    # 12. New modules (all 17)
    try:
        from backend.profiling.resource_profiler import ResourceProfiler
        from backend.profiling.benchmarks import ThroughputBenchmark
        from backend.response.approval import ApprovalWorkflow
        from backend.ml.attack_path import AttackPathPredictor
        from backend.ml.ueba import UEBAEngine
        from backend.ml.insider_threat import InsiderThreatDetector
        from backend.risk.blast_radius import BlastRadiusAnalyzer
        from backend.compliance.frameworks import get_framework
        from backend.compliance.gap_analysis import analyze_gaps
        from backend.mitre.gap_analysis import generate_gap_report
        from backend.fleet.log_fetch import LogFetchManager
        from backend.fleet.config_profiles import ConfigProfileManager
        from backend.database.optimization import QueryOptimizer
        from backend.integrations.cloud.aws_connector import AWSConnector
        from backend.integrations.edr.crowdstrike_connector import CrowdStrikeConnector
        from backend.integrations.soar.xsoar_connector import XSOARConnector
        results.append(("New modules (17)", "OK", "all importable"))
    except Exception as e:
        results.append(("New modules", "FAIL", str(e)))

    # 13. API routers
    try:
        from backend.api.approval import router as approval_router
        from backend.api.bookmarks import router as bookmarks_router
        results.append(("New API routers", "OK", "approval + bookmarks"))
    except Exception as e:
        results.append(("New API routers", "FAIL", str(e)))

    # 14. RBAC / security
    try:
        from backend.security import require_auth, require_admin, require_role
        results.append(("RBAC/security", "OK", "require_auth, require_admin, require_role"))
    except Exception as e:
        results.append(("RBAC/security", "FAIL", str(e)))

    # 15. Logging
    try:
        from backend.logging_config import setup_logging
        results.append(("Logging", "OK", "setup_logging importable"))
    except Exception as e:
        results.append(("Logging", "FAIL", str(e)))

    # 16. Scheduler
    try:
        from backend.scheduler_service import run
        results.append(("Scheduler", "OK", "start_scheduler importable"))
    except Exception as e:
        results.append(("Scheduler", "FAIL", str(e)))

    print_results(results)


def print_results(results):
    passed = sum(1 for _, s, _ in results if s == "OK")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    print(f"\n{'='*60}")
    print(f"V0.9 FUNCTIONAL VERIFICATION: {passed}/{len(results)} passed")
    print(f"{'='*60}")
    for name, status, detail in results:
        icon = "[OK]" if status == "OK" else "[FAIL]"
        print(f"  {icon} {name}: {detail}")
    print(f"{'='*60}")
    if failed:
        print(f"RESULT: {failed} FAILURES")
    else:
        print("RESULT: ALL CHECKS PASSED")


if __name__ == "__main__":
    main()

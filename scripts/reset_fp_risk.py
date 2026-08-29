"""Reset entity risk scores and close false-positive alerts."""
from backend.database.connection import SessionLocal
from sqlalchemy import text

db = SessionLocal()
try:
    # Close all entity_risk escalation alerts
    db.execute(text(
        "UPDATE alerts SET status='closed' WHERE rule='entity_risk' AND status='open'"
    ))

    # Close known FP detection alerts
    db.execute(text(
        "UPDATE alerts SET status='closed' "
        "WHERE rule IN ('suspicious_powershell','unusual_port','sigma_rules') "
        "AND status='open' "
        "AND (evidence ILIKE '%toast.ps1%' OR evidence ILIKE '%Discord.exe%' "
        "OR evidence ILIKE '%Security Intelligence Update%' "
        "OR evidence ILIKE '%runweb.py%')"
    ))

    # Reset all entity risk scores to zero
    db.execute(text(
        "UPDATE entity_risk SET "
        "score=0.0, risk_level='LOW', alerts_count=0, "
        "contributions='[]'::jsonb, "
        "last_escalated_level='LOW', last_escalated_score=0.0"
    ))

    db.commit()
    print("Done - entities reset, FP alerts closed")
except Exception as e:
    db.rollback()
    print(f"Error: {e}")
    import traceback; traceback.print_exc()
finally:
    db.close()

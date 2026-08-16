from sqlalchemy import Column, Integer, String, Float, DateTime, func
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone
from backend.database.connection import SessionLocal

Base = declarative_base()

class SummaryTable(Base):
    \"\"\"
    Accelerated summary table for dashboard KPIs.
    Reduces the need to scan millions of raw events.
    \"\"\"
    __tablename__ = \"summary_metrics\"

    id = Column(Integer, primary_key=True)
    metric_name = Column(String(64), index=True) # e.g., 'event_count', 'alert_severity_dist'
    metric_value = Column(Float)
    dimension = Column(String(128), index=True) # e.g., 'source=sysmon' or 'severity=high'
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

def update_summary_metrics(session: SessionLocal):
    \"\"\"
    Computes and persists summary metrics from raw tables.
    This is the 'Acceleration' part of the data model.
    \"\"\"
    # Example: Aggregate Event counts by source for the last hour
    # This logic would typically be expanded to cover all dashboard charts.
    pass

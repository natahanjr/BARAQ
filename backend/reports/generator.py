"""Report generation facade - builds context and exports in any format."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.database.models import ReportRecord
from backend.reports.context import executive_context, technical_context
from backend.reports.exporters import export_report


def generate_report(session: Session, report_type: str, fmt: str = "pdf") -> dict:
    """Generate a report of the given type/format and record its metadata."""
    if report_type == "executive":
        context = executive_context(session)
    elif report_type == "technical":
        context = technical_context(session)
    else:
        raise ValueError("report_type must be 'executive' or 'technical'")

    file_path, ext = export_report(context, fmt)
    record = ReportRecord(
        report_type=report_type,
        format=ext,
        title=context["title"],
        file_path=file_path,
    )
    session.add(record)
    session.commit()
    return {
        "report_type": report_type,
        "format": ext,
        "title": context["title"],
        "file_path": file_path,
        "created_at": record.created_at.isoformat(),
        "security_score": context.get("security_score"),
        "risk_level": context.get("risk_level"),
    }

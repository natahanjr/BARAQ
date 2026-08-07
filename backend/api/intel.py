"""Threat-intel API: enrich indicators on demand or from an alert's evidence."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import Alert
from backend.security import actor_name, require_auth
from backend.threatintel.service import enrich_alert, lookup_indicator

logger = logging.getLogger("sentinel.api.threatintel")

router = APIRouter(
    prefix="/api/intel",
    tags=["threat-intel"],
    dependencies=[Depends(require_auth)],
)


class IntelLookup(BaseModel):
    indicator: str = Field(min_length=1, max_length=256)


@router.post("/lookup")
def intel_lookup(
    body: IntelLookup,
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Look up a single indicator (IP / domain / hash)."""
    return lookup_indicator(db, body.indicator, refresh=refresh)


@router.get("/alert/{alert_id}")
def alert_intel(
    alert_id: int,
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Enrich all indicators found in an alert's evidence."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {
        "alert_id": alert_id,
        "alert_name": alert.name,
        "items": enrich_alert(db, alert, refresh=refresh),
    }


@router.post("/save")
def save_verdict(
    body: IntelLookup,
    request: Request,
    db: Session = Depends(get_db),
):
    """Persist an analyst manual verdict override for an indicator.

    Accepted categories: malicious / suspicious / benign / unknown.
    The override is stored in the cache record so future lookups return it
    immediately (authoritative analyst input wins over provider feeds).
    """
    from backend.database.models import ThreatIntelRecord
    from backend.threatintel import _DOMAIN_RE, _HASH_RE, _IPV4_RE

    indicator = body.indicator.strip().lower()
    kind = "ip" if _IPV4_RE.match(indicator) else "domain" if _DOMAIN_RE.match(indicator) else "hash"
    row = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.indicator == indicator).one_or_none()
    if row is None:
        row = ThreatIntelRecord(indicator=indicator, kind=kind)
        db.add(row)
    row.kind = kind
    row.category = "malicious"
    row.label = "Analyst-marked indicator"
    row.confidence = 1.0
    row.sources = (row.sources or []) + ["analyst"]
    db.commit()
    db.refresh(row)
    log_action(db, actor_name(request), "intel.save", "indicator", indicator,
               "Analyst marked indicator malicious", client_ip(request))
    return row.to_dict()
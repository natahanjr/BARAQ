"""Per-host behavioural baselining - the "deep" FP defence.

Learns each endpoint's normal parent -> child process chains passively from
telemetry. Known chains are *normal for that host*; the alerting gate uses
them to silence generic rule hits, and NOVEL chains annotate alerts as
elevated-signal context (the generic LOLBin answer: "this never happens
here" beats hardcoded lists).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import HostProcessChain, NormalizedEvent

logger = logging.getLogger("baraq.baseline")

#: Minimum observations before a chain is trusted as baseline behaviour.
MIN_OCCURRENCES = 3


def _norm(name: str | None) -> str:
    return (name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()[:128]


def _facts_get(facts: dict, *keys: str):
    """Case-insensitive-ish fact lookup covering the collector's key styles
    (structured XML gives PascalCase, normalizer gives snake_case)."""
    for k in keys:
        if facts.get(k):
            return facts[k]
    lowered = {str(k).lower(): v for k, v in facts.items()}
    for k in keys:
        v = lowered.get(k.lower())
        if v:
            return v
    return None


def _chain_of(facts: dict) -> tuple[str, str]:
    child_src = _facts_get(
        facts, "new_process_name", "newprocessname", "NewProcessName",
        "image_path", "image", "process_name",
    ) or ""
    parent_src = _facts_get(
        facts, "parent_process_name", "parentprocessname", "ParentProcessName",
        "parent_image", "parentimage",
    ) or ""
    return _norm(str(parent_src)), _norm(str(child_src))


def learn_chains(db: Session, hours: int = 24, org: str = "") -> dict:
    """Upsert parent->child chains from recent process-creation telemetry.

    Cheap enough for every scheduler cycle: reads only events newer than the
    previous pass window and merges counts.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.scalars(
        select(NormalizedEvent).where(
            NormalizedEvent.event_id == 4688,
            NormalizedEvent.timestamp >= since,
        )
    ).all()

    seen: dict[tuple[str, str, str], int] = {}
    hosts: set[str] = set()
    for ev in rows:
        facts = (ev.raw_json or {}).get("facts") or {}
        parent, child = _chain_of(facts)
        if not parent or not child or parent == child:
            continue
        host = (ev.host or "-").lower()[:128]
        key = (host, parent, child)
        seen[key] = seen.get(key, 0) + 1
        hosts.add(host)

    created = updated = 0
    for (host, parent, child), n in seen.items():
        chain = db.scalars(
            select(HostProcessChain).where(
                HostProcessChain.host == host,
                HostProcessChain.parent_name == parent,
                HostProcessChain.child_name == child,
                HostProcessChain.org == org,
            )
        ).first()
        if chain is None:
            db.add(
                HostProcessChain(
                    host=host,
                    org=org,
                    parent_name=parent,
                    child_name=child,
                    occurrences=n,
                )
            )
            created += 1
        else:
            chain.occurrences += n
            updated += 1
    if created or updated:
        db.commit()
    return {
        "events_scanned": len(rows),
        "chains_created": created,
        "chains_updated": updated,
        "hosts": sorted(hosts),
    }


def lookup_chain(db: Session, host: str, parent: str, child: str, org: str = "") -> bool:
    """True when this parent->child chain is established baseline for host."""
    chain = db.scalars(
        select(HostProcessChain).where(
            HostProcessChain.host == _norm(host),
            HostProcessChain.parent_name == _norm(parent),
            HostProcessChain.child_name == _norm(child),
            HostProcessChain.org == org,
        )
    ).first()
    return bool(chain and (chain.occurrences or 0) >= MIN_OCCURRENCES)


def list_chains(db: Session, host: str = "", org: str = "", limit: int = 500) -> list[HostProcessChain]:
    stmt = select(HostProcessChain).where(HostProcessChain.org == org)
    if host:
        stmt = stmt.where(HostProcessChain.host == _norm(host))
    return list(
        db.scalars(stmt.order_by(HostProcessChain.occurrences.desc()).limit(limit)).all()
    )


def rebuild(db: Session, days: int = 7, org: str = "") -> dict:
    """Full relearn: wipe + rescan the whole retention window."""
    now = datetime.now(timezone.utc)
    old = db.scalars(select(HostProcessChain).where(HostProcessChain.org == org)).all()
    for item in old:
        db.delete(item)
    db.commit()
    result = {"deleted": len(old)}
    # learn in daily slices to bound memory on large histories
    total_seen = 0
    for offset in range(days):
        end = now - timedelta(days=offset)
        start = end - timedelta(days=1)
        rows = db.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 4688,
                NormalizedEvent.timestamp >= start,
                NormalizedEvent.timestamp < end,
            )
        ).all()
        agg: dict[tuple[str, str, str], int] = {}
        for ev in rows:
            facts = (ev.raw_json or {}).get("facts") or {}
            parent, child = _chain_of(facts)
            if not parent or not child or parent == child:
                continue
            key = ((ev.host or "-").lower()[:128], parent, child)
            agg[key] = agg.get(key, 0) + 1
        for (host, parent, child), n in agg.items():
            db.add(
                HostProcessChain(
                    host=host, org=org, parent_name=parent,
                    child_name=child, occurrences=n,
                )
            )
        total_seen += len(rows)
        db.commit()
    result.update({"events_scanned": total_seen})
    return result

"""Pipe-based search engine over the normalized event / alert store.

Query DSL (pipe-based):

    source=sysmon event_id=4625 "failed logon" user=admin
      | stats count by user, host
      | sort -count
      | top 10 user
      | table user, host, count
      | limit 100

Supported filters: source, category, user, host, event_id, severity, risk,
risk_score, rule, status, name, mitre_id, mitre_tactic, detection_method,
is_anomaly, org. Quoted phrases are matched verbatim against message text.
``index=alerts`` switches the search target from events to alerts.

Time window: ``earliest`` / ``latest`` accept relative offsets (``-24h``,
``-7d``, ``-30m``) or ISO timestamps. Default window is the last 24h.

Pipes (chained left to right):
    stats   count/sum/avg by field(s)          e.g. | stats count, avg(risk_score) by user, host
    timechart  span=<N>[smhdw] [agg] [by field] e.g. | timechart span=1d count by user
    transaction  by field [maxspan=<N>[smhdw]]  e.g. | transaction by host maxspan=5m
    top     N field [by field]                 e.g. | top 10 user
    rare    N field [by field]
    table   field[, field...]
    fields  keep/remove field[, field...]      e.g. | fields -message
    sort    [-+]field[, ...]
    where   field=value | field>N | field>=N | field<N | field<=N
    limit   N

``timechart`` buckets rows by time span (default 1h) and optionally pivots
``by field`` values into one column each (like a timechart). With a
``by`` field the leading ``count`` column is the bucket total.
``transaction`` groups same-key events into sessions whenever consecutive
events are within ``maxspan`` (default 5m); output columns are
``_time`` (session start), ``duration`` (seconds), ``count`` and the key
field. Both emit aggregated rows, so ``sort`` / ``where`` / ``table`` apply.
"""

from __future__ import annotations

import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.models import Alert, NormalizedEvent

log = logging.getLogger("baraq.search")

_EVENT_FIELDS = {
    "id": NormalizedEvent.id,
    "event_id": NormalizedEvent.event_id,
    "category": NormalizedEvent.category,
    "source": NormalizedEvent.source,
    "user": NormalizedEvent.user,
    "host": NormalizedEvent.host,
    "org": NormalizedEvent.org,
    "risk": NormalizedEvent.risk,
    "risk_score": NormalizedEvent.risk_score,
    "severity": NormalizedEvent.severity,
    "message": NormalizedEvent.message,
    "timestamp": NormalizedEvent.timestamp,
    "data_integrity": NormalizedEvent.data_integrity,
    "is_anomaly": NormalizedEvent.is_anomaly,
    "ml_score": NormalizedEvent.ml_score,
    "demo": NormalizedEvent.demo,
}

_ALERT_FIELDS = {
    "id": Alert.id,
    "name": Alert.name,
    "severity": Alert.severity,
    "status": Alert.status,
    "confidence": Alert.confidence,
    "score": Alert.score,
    "rule": Alert.rule,
    "host": Alert.host,
    "org": Alert.org,
    "mitre_id": Alert.mitre_id,
    "mitre_name": Alert.mitre_name,
    "mitre_tactic": Alert.mitre_tactic,
    "risk_score": Alert.risk_score,
    "risk_level": Alert.risk_level,
    "event_count": Alert.event_count,
    "detection_method": Alert.detection_method,
    "created_at": Alert.created_at,
    "demo": Alert.demo,
    "correlation_id": Alert.correlation_id,
}

_FREE_TEXT_FIELDS = {"events": "message", "alerts": "evidence"}


class SearchError(ValueError):
    """Raised for malformed queries; mapped to HTTP 400 by the API layer."""


@dataclass
class SearchResult:
    columns: list[str]
    rows: list[list[Any]]
    total: int
    elapsed_ms: float
    index: str
    query: str


@dataclass
class _Pipe:
    name: str
    args: list[str] = field(default_factory=list)


@dataclass
class _ParsedQuery:
    index: str = "events"
    filters: list[tuple[str, str]] = field(default_factory=list)
    free_text: list[str] = field(default_factory=list)
    pipes: list[_Pipe] = field(default_factory=list)


def _split_pipes(query: str) -> list[str]:
    parts, buf, quote = [], [], None
    for ch in query:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse_query(query: str) -> _ParsedQuery:
    """Parse a search string into filters, free-text tokens and pipes."""
    if not query or not query.strip():
        raise SearchError("empty query")
    q = _ParsedQuery()
    segments = _split_pipes(query)
    for seg_no, segment in enumerate(segments):
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:  # unterminated quote
            raise SearchError(f"unterminated quote: {exc}")
        if not tokens:
            continue
        if seg_no == 0:
            for tok in tokens:
                if "=" in tok:
                    key, _, val = tok.partition("=")
                    key = key.strip().lower()
                    val = val.strip()
                    if not key:
                        raise SearchError(f"malformed filter: {tok!r}")
                    if key == "index":
                        q.index = val
                    else:
                        q.filters.append((key, val))
                else:
                    q.free_text.append(tok)
        else:
            name = tokens[0].lower()
            q.pipes.append(_Pipe(name=name, args=tokens[1:]))
    return q


def _relative_time(value: str, now: datetime) -> datetime:
    m = re.fullmatch(r"([+-]?\d+)([smhdw])", value.strip().lower())
    if not m:
        raise SearchError(f"invalid relative time: {value!r}")
    amount = int(m.group(1))
    unit = m.group(2)
    delta = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
    }[unit]
    return now + delta


def _parse_time(value: str | None, now: datetime, default_offset: timedelta) -> datetime:
    if not value:
        return now - default_offset
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            return _relative_time(value, now)
        except SearchError:
            raise SearchError(f"invalid time value: {value!r}")


def _flatten_args(args: list[str]) -> list[str]:
    """Split pipe args on commas and spaces: 'user, host' -> ['user', 'host']."""
    out: list[str] = []
    for tok in args:
        for part in tok.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _coerce_filter_value(col, val: str):
    """Cast a filter value to the column's Python type."""
    py_type = getattr(col, "type", None)
    py_class = py_type.__class__.__name__ if py_type else ""
    try:
        if py_class in ("Integer", "BigInteger"):
            return int(val)
        if py_class in ("Float", "Numeric"):
            return float(val)
        if py_class == "Boolean":
            return val.strip().lower() in ("true", "1", "yes")
        if py_class == "DateTime":
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except ValueError:
        raise SearchError(f"invalid value {val!r} for filter field")
    return val


def _span_seconds(span: str) -> int:
    m = re.fullmatch(r"(\d+)([smhdw])", span.strip().lower())
    if not m:
        raise SearchError(f"invalid span {span!r} (use e.g. 15m, 1h, 1d)")
    return int(m.group(1)) * {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
    }[m.group(2)]


def _parse_aggs(agg_tokens: list[str], fields: dict) -> list[tuple[str, str, str]]:
    """Parse 'count', 'sum(field)', ... tokens into (alias, fn, field) triples."""
    aggs: list[tuple[str, str, str]] = []
    for tok in agg_tokens:
        tok = tok.strip().rstrip(",").strip()
        if tok in ("count", "count()"):
            aggs.append(("count", "count", None))
            continue
        m = re.fullmatch(r"(count|sum|avg|max|min)\(([\w.]+)\)", tok)
        if not m:
            raise SearchError(f"unsupported aggregation: {tok!r}")
        fn, fld = m.groups()
        if fld not in fields:
            raise SearchError(f"unknown field {fld!r} in aggregation")
        aggs.append((f"{fn}_{fld}", fn, fld))
    return aggs


def _agg_col(sub, fn: str, fld: str | None):
    col = sub.c[fld] if fld else func.count()
    return {
        "count": func.count(),
        "sum": func.sum(col),
        "avg": func.avg(col),
        "max": func.max(col),
        "min": func.min(col),
    }[fn]


def _build_query(
    q: _ParsedQuery,
    db: Session,
    org: str,
    earliest: str | None,
    latest: str | None,
    include_demo: bool = False,
):
    now = datetime.now(timezone.utc)
    start = _parse_time(earliest, now, timedelta(hours=24))
    end = _parse_time(latest, now, timedelta(0))
    if start > end:
        raise SearchError("earliest must be before latest")
    if q.index == "alerts":
        model, fields = Alert, _ALERT_FIELDS
        time_col = Alert.created_at
    elif q.index == "events":
        model, fields = NormalizedEvent, _EVENT_FIELDS
        time_col = NormalizedEvent.timestamp
    else:
        raise SearchError(f"unknown index {q.index!r} (use events or alerts)")
    stmt = select(model).where(time_col >= start, time_col <= end)
    if org:
        stmt = stmt.where(model.org == org)
    explicit_demo = any(key == "demo" for key, _ in q.filters)
    if not include_demo and not explicit_demo:
        # Demo/test separation: production searches never see seeded data
        # unless the console runs in demo mode or the query asks for it.
        stmt = stmt.where(model.demo.is_(False))
    for key, val in q.filters:
        if key not in fields:
            raise SearchError(f"unknown field {key!r} in index {q.index!r}")
        col = fields[key]
        stmt = stmt.where(col == _coerce_filter_value(col, val))
    if q.free_text:
        text_col = fields[_FREE_TEXT_FIELDS[q.index]]
        for phrase in q.free_text:
            stmt = stmt.where(text_col.contains(phrase))
    return stmt, model, fields


def _coerce(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float):
        return round(value, 4)
    return value


def execute_search(
    db: Session,
    query: str,
    org: str = "",
    earliest: str | None = None,
    latest: str | None = None,
    default_limit: int = 500,
    include_demo: bool = False,
) -> SearchResult:
    """Parse and run a search, applying pipes in order."""
    started = time.perf_counter()
    q = parse_query(query)
    stmt, model, fields = _build_query(q, db, org, earliest, latest, include_demo)
    columns = list(fields)
    rows: list[list[Any]] = []
    limit = default_limit
    keep_fields: list[str] | None = None
    aggregated = False
    for pipe in q.pipes:
        name, args = pipe.name, pipe.args
        args = _flatten_args(args) if name in ("fields", "table", "sort") else args
        if name == "limit":
            if not args or not args[0].lstrip("+-").isdigit() or int(args[0]) < 0:
                raise SearchError("limit requires a positive integer")
            limit = int(args[0])
        elif name == "fields":
            keep = [a for a in args if not a.startswith("-")]
            drop = [a[1:] for a in args if a.startswith("-")]
            if keep:
                unknown = [k for k in keep if k not in fields]
                if unknown:
                    raise SearchError(f"unknown field(s): {', '.join(unknown)}")
                keep_fields = keep
            if drop:
                unknown = [k for k in drop if k not in fields]
                if unknown:
                    raise SearchError(f"unknown field(s): {', '.join(unknown)}")
                if keep_fields is None:
                    keep_fields = list(fields)
                keep_fields = [k for k in keep_fields if k not in drop]
        elif name == "table":
            if not args:
                raise SearchError("table requires at least one field")
            unknown = [a for a in args if a not in fields]
            if unknown:
                raise SearchError(f"unknown field(s): {', '.join(unknown)}")
            keep_fields = list(args)
        elif name in ("stats", "top", "rare"):
            rows, columns = _run_stats(db, stmt, model, fields, pipe)
            aggregated = True
            fields = {c: c for c in columns}
            keep_fields = None
        elif name == "timechart":
            rows, columns = _run_timechart(db, stmt, fields, pipe)
            aggregated = True
            fields = {c: c for c in columns}
            keep_fields = None
        elif name == "transaction":
            rows, columns = _run_transaction(db, stmt, fields, pipe)
            aggregated = True
            fields = {c: c for c in columns}
            keep_fields = None
        elif name == "sort":
            if not args:
                raise SearchError("sort requires at least one field")
        elif name == "where":
            if not args:
                raise SearchError("where requires a condition")
        else:
            raise SearchError(f"unknown pipe: {name!r}")

    if not aggregated:
        time_col = fields.get("timestamp") or fields.get("created_at")
        objs = db.execute(
            stmt.order_by(time_col.desc()).limit(limit)
        ).scalars().all()
        rows = [[_coerce(getattr(o, f)) for f in fields] for o in objs]
        if keep_fields is not None:
            idx = [list(fields).index(f) for f in keep_fields]
            rows = [[r[i] for i in idx] for r in rows]
            columns = keep_fields
    elif keep_fields is not None:
        idx = [columns.index(f) for f in keep_fields if f in columns]
        rows = [[r[i] for i in idx] for r in rows]
        columns = [columns[i] for i in idx]

    # sort / where apply in pipe order to the final row set - aggregated
    # rows or raw rows projected by table/fields.
    if rows:
        for pipe in q.pipes:
            if pipe.name == "sort":
                keys = []
                for tok in pipe.args:
                    direction = "desc" if tok.startswith("-") else "asc"
                    fname = tok[1:] if tok.startswith(("+", "-")) else tok
                    if fname not in columns:
                        raise SearchError(f"unknown field {fname!r} in sort")
                    keys.append((columns.index(fname), direction))
                for idx in reversed(range(len(keys))):
                    col_i, direction = keys[idx]
                    rows.sort(key=lambda r: r[col_i], reverse=(direction == "desc"))
            elif pipe.name == "where":
                for cond in pipe.args:
                    m = re.fullmatch(r"([\w.]+)(==|>=|<=|>|<|=)(\S+)", cond)
                    if not m:
                        raise SearchError(f"malformed where condition: {cond!r}")
                    fname, op, val = m.groups()
                    if fname not in columns:
                        raise SearchError(f"unknown field {fname!r} in where")
                    col_i = columns.index(fname)
                    try:
                        cmp_val: Any = float(val)
                    except ValueError:
                        cmp_val = val
                    rows = [
                        r
                        for r in rows
                        if (lambda v: {
                            "==": v == cmp_val,
                            "=": v == cmp_val,
                            ">": v > cmp_val,
                            ">=": v >= cmp_val,
                            "<": v < cmp_val,
                            "<=": v <= cmp_val,
                        }[op])(r[col_i])
                    ]

    return SearchResult(
        columns=columns,
        rows=rows,
        total=len(rows),
        elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
        index=q.index,
        query=query,
    )


def _run_stats(db: Session, stmt, model, fields: dict, pipe: _Pipe):
    """Handle stats / top / rare pipes, returning (rows, columns)."""
    name, args = pipe.name, pipe.args
    group_by: list[str] = []
    aggs: list[tuple[str, str, str]] = []
    limit = 100
    if name == "stats":
        if not args or "by" not in args:
            raise SearchError("stats requires aggregations with 'by', e.g. | stats count by user")
        by_idx = args.index("by")
        agg_tokens, group_by = args[:by_idx], args[by_idx + 1 :]
        group_by = [g.strip().rstrip(",").strip() for g in group_by]
        if not group_by:
            raise SearchError("stats requires at least one group-by field after 'by'")
        aggs = _parse_aggs(agg_tokens, fields)
        order_agg, reverse = "count", True
    elif name in ("top", "rare"):
        limit = 10
        rest = list(args)
        if rest and rest[0].isdigit():
            limit = int(rest.pop(0))
        if not rest:
            raise SearchError(f"{name} requires a field, e.g. | {name} 10 user")
        field_tok = rest.pop(0)
        field_tok = field_tok.strip().rstrip(",").strip()
        if field_tok not in fields:
            raise SearchError(f"unknown field {field_tok!r}")
        group_by = [field_tok] + [g.strip().rstrip(",").strip() for g in rest]
        aggs = [("count", "count", None)]
        order_agg, reverse = "count", name == "top"
    else:
        raise SearchError(f"unknown pipe: {name!r}")

    for g in group_by:
        if g not in fields:
            raise SearchError(f"unknown field {g!r} in group-by")

    sub = stmt.subquery()
    cols = [sub.c[g] for g in group_by]
    for alias, fn, fld in aggs:
        cols.append(_agg_col(sub, fn, fld).label(alias))
    agg_stmt = (
        select(*cols)
        .select_from(sub)
        .group_by(*[sub.c[g] for g in group_by])
        .order_by(cols[-1].desc() if reverse else cols[-1].asc())
        .limit(limit)
    )
    db_rows = db.execute(agg_stmt).all()
    columns = group_by + [alias for alias, _, _ in aggs]
    return [[_coerce(v) for v in row] for row in db_rows], columns


def _run_timechart(
    db: Session, stmt, fields: dict, pipe: _Pipe
) -> tuple[list[list[Any]], list[str]]:
    """| timechart span=1h count [by field] - time-bucketed trend, pivoted."""
    args = list(pipe.args)
    span = "1h"
    if args and args[0].startswith("span="):
        span = args.pop(0).split("=", 1)[1]
    span_sec = _span_seconds(span)
    time_col_name = "timestamp" if "timestamp" in fields else "created_at"
    time_col = fields[time_col_name]

    group_by: list[str] = []
    agg_tokens: list[str] = []
    if "by" in args:
        by_idx = args.index("by")
        agg_tokens = args[:by_idx]
        group_by = [g.strip().rstrip(",").strip() for g in args[by_idx + 1 :]]
    else:
        agg_tokens = args
    if not agg_tokens:
        agg_tokens = ["count"]
    aggs = _parse_aggs(agg_tokens, fields)
    for g in group_by:
        if g not in fields:
            raise SearchError(f"unknown field {g!r} in timechart")

    sub = stmt.subquery()
    bucket = func.to_timestamp(
        func.floor(func.extract("epoch", sub.c[time_col_name]) / span_sec) * span_sec
    )
    cols = [bucket.label("_time")]
    for g in group_by:
        cols.append(sub.c[g])
    for alias, fn, fld in aggs:
        cols.append(_agg_col(sub, fn, fld).label(alias))
    agg_stmt = (
        select(*cols)
        .select_from(sub)
        .group_by(bucket, *[sub.c[g] for g in group_by])
        .order_by(bucket)
    )
    db_rows = db.execute(agg_stmt).all()

    if len(group_by) == 1 and len(aggs) == 1 and aggs[0][1] == "count":
        g = group_by[0]
        by_vals = sorted({r[1] for r in db_rows if r[1] is not None})
        columns = ["_time", "count"] + [str(v) for v in by_vals]
        pivot: dict = {}
        bucket_totals: dict = {}
        for row in db_rows:
            bucket_totals[row[0]] = bucket_totals.get(row[0], 0) + row[2]
            pivot.setdefault(row[0], {})[row[1]] = row[2]
        rows = []
        for b in sorted(bucket_totals):
            rows.append(
                [_coerce(b), bucket_totals[b]]
                + [pivot[b].get(v, 0) for v in by_vals]
            )
        return rows, columns

    columns = ["_time"] + group_by + [alias for alias, _, _ in aggs]
    return [[_coerce(v) for v in row] for row in db_rows], columns


def _run_transaction(
    db: Session, stmt, fields: dict, pipe: _Pipe, cap: int = 5000
) -> tuple[list[list[Any]], list[str]]:
    """| transaction by field [maxspan=5m] - group events into sessions."""
    args = list(pipe.args)
    by_field: str | None = None
    maxspan = 300
    for tok in args:
        if tok == "by":
            continue
        if tok.startswith("maxspan="):
            maxspan = _span_seconds(tok.split("=", 1)[1])
            continue
        if tok not in fields:
            raise SearchError(f"unknown field {tok!r} in transaction")
        by_field = tok
    if by_field is None:
        raise SearchError("transaction requires a field, e.g. | transaction by host")
    if maxspan <= 0:
        raise SearchError("maxspan must be positive")

    time_col_name = "timestamp" if "timestamp" in fields else "created_at"
    time_col = fields[time_col_name]
    objs = db.execute(stmt.order_by(time_col.asc()).limit(cap)).scalars().all()

    transactions: list[list[Any]] = []
    cur_key = None
    cur_start = None
    cur_last = None
    cur_count = 0
    for obj in objs:
        ts = getattr(obj, time_col_name)
        key = getattr(obj, by_field)
        if key is None:
            key = ""
        if (
            cur_key is not None
            and key == cur_key
            and ts is not None
            and cur_last is not None
            and (ts - cur_last).total_seconds() <= maxspan
        ):
            cur_last = ts
            cur_count += 1
        else:
            if cur_key is not None and cur_start is not None:
                transactions.append(
                    [
                        _coerce(cur_start),
                        round((cur_last - cur_start).total_seconds(), 1),
                        cur_count,
                        cur_key,
                    ]
                )
            cur_key = key
            cur_start = ts
            cur_last = ts
            cur_count = 1
    if cur_key is not None and cur_start is not None:
        transactions.append(
            [_coerce(cur_start), round((cur_last - cur_start).total_seconds(), 1), cur_count, cur_key]
        )
    transactions.sort(key=lambda r: r[0], reverse=True)
    return transactions, ["_time", "duration", "count", by_field]
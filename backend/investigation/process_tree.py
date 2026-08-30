"""Process tree reconstruction for the investigation view.

Rebuilds parent/child process lineage around an alert's evidence events
from Windows 4688 events (raw facts carry ``ProcessId`` = parent and
``NewProcessId`` = child), with a ``ProcessRecord`` snapshot fallback and
name-based parent matching for gaps, then identifies the root process and
the ``root -> seed -> aftermath`` chain that tells the full story.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from backend.database.models import NormalizedEvent, ProcessRecord

log = logging.getLogger("investigation.tree")

EVENT_PROCESS_CREATE = 4688
WINDOW_MINUTES = 90
MAX_TREE_EVENTS = 2000


def _norm_pid(value: Any) -> str | None:
    """Normalize a PID from hex (4688 facts) or decimal (ProcessRecord)."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("0", "-", "0x0"):
        return None
    try:
        if s.lower().startswith("0x"):
            return str(int(s, 16))
        return str(int(s))
    except ValueError:
        return None


@dataclass
class PNode:
    pid: str
    name: str = ""
    path: str = ""
    cmdline: str = ""
    user: str = ""
    host: str = ""
    guid: str = ""
    parent_guid: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    parent_pid: str | None = None
    parent_name: str = ""
    edge_verified: bool = False
    source: str = ""  # "event" | "snapshot" | "name-match"
    seed: bool = False
    event_ids: list[int] = field(default_factory=list)
    cmdlines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "cmdline": (self.cmdlines[0] if self.cmdlines else self.cmdline)[:400],
            "user": self.user,
            "host": self.host,
            "guid": self.guid,
            "parent_guid": self.parent_guid,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "verified": self.edge_verified,
            "seed": self.seed,
        }


def _node_key(pid: str, host: str) -> str:
    return f"{host}::{pid}"


def _fact(facts: dict, *keys: str) -> Any:
    for key in keys:
        for k in facts:
            if k.lower() == key.lower():
                return facts[k]
    return None


def _seed_pids(events: list[NormalizedEvent]) -> set[str]:
    """PIDs of processes directly mentioned in the alert's evidence events."""
    seeds: set[str] = set()
    for ev in events:
        facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
        pid = _norm_pid(_fact(facts, "NewProcessId", "ProcessId", "pid"))
        if pid:
            seeds.add(pid)
    return seeds


def build_process_tree(
    session,
    evidence_events: list[NormalizedEvent],
    org: str = "",
    window_minutes: int = WINDOW_MINUTES,
) -> dict:
    """Build the process tree(s) around the evidence events.

    Returns a dict with the primary tree (the host carrying most seed
    processes), other hosts' trees, the root process, the chain from
    root to the seed process and the completion story.
    """
    if not evidence_events:
        return _empty_tree("no evidence events")

    timestamps = [ev.timestamp for ev in evidence_events if ev.timestamp]
    if not timestamps:
        return _empty_tree("evidence events have no timestamps")
    ts_min = min(timestamps) - timedelta(minutes=window_minutes)
    ts_max = max(timestamps) + timedelta(minutes=window_minutes)

    {ev.host for ev in evidence_events if ev.host}

    # ---- 1) 4688 process-creation events in the window -------------------
    q = select(NormalizedEvent).where(
        NormalizedEvent.event_id == EVENT_PROCESS_CREATE,
        NormalizedEvent.timestamp >= ts_min,
        NormalizedEvent.timestamp <= ts_max,
    )
    if org:
        q = q.where(NormalizedEvent.org == org)
    else:
        q = q.where(NormalizedEvent.demo == False)
    q = q.order_by(NormalizedEvent.timestamp.asc()).limit(MAX_TREE_EVENTS)
    proc_events = session.scalars(q).all()

    # ---- 2) ProcessRecord snapshots in the window (supplement) -----------
    snapshots: list[ProcessRecord] = []
    try:
        snap_q = select(ProcessRecord).where(
            ProcessRecord.observed_at >= ts_min,
            ProcessRecord.observed_at <= ts_max,
        )
        if org:
            snap_q = snap_q.where(ProcessRecord.org == org)
        snap_q = snap_q.order_by(ProcessRecord.observed_at.desc()).limit(1500)
        snapshots = session.scalars(snap_q).all()
    except Exception:
        log.warning("ProcessRecord fallback unavailable", exc_info=True)

    # ---- 3) assemble nodes per host --------------------------------------
    per_host: dict[str, dict[str, PNode]] = {}
    link_order: list[tuple[str, str, str, str, datetime, bool, str]] = (
        []
    )  # (host, child, parent, parent_name, ts, verified, kind)

    def ensure_node(host: str, pid: str) -> PNode:
        key = _node_key(pid, host)
        nodes = per_host.setdefault(host, {})
        if key not in nodes:
            nodes[key] = PNode(pid=pid, host=host)
        return nodes[key]

    for ev in proc_events:
        host = ev.host or "?"
        facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
        child_pid = _norm_pid(_fact(facts, "NewProcessId", "ProcessId"))
        if not child_pid:
            continue
        parent_pid = _norm_pid(
            _fact(facts, "ProcessId", "ParentProcessId", "ParentPID")
        )
        node = ensure_node(host, child_pid)
        node.name = str(
            _fact(facts, "new_process", "NewProcessName", "Image") or node.name or ""
        )
        node.path = str(_fact(facts, "NewProcessName", "Image") or node.path or "")
        node.user = ev.user or node.user
        node.cmdline = str(_fact(facts, "CommandLine") or "")
        node.source = "event"
        node.event_ids.append(ev.id)
        if node.first_seen is None or ev.timestamp < node.first_seen:
            node.first_seen = ev.timestamp
        if node.last_seen is None or ev.timestamp > node.last_seen:
            node.last_seen = ev.timestamp
        if node.cmdline and node.cmdline not in node.cmdlines:
            node.cmdlines.append(node.cmdline)
        if parent_pid:
            link_order.append(
                (host, child_pid, parent_pid, "", ev.timestamp, True, "pid")
            )

    # supplement with snapshots (pids that do not collide with event nodes)
    for snap in snapshots:
        pid = _norm_pid(snap.pid)
        if not pid:
            continue
        host = getattr(snap, "host", "") or (snap.user or "?")
        if host in ("", "?"):
            host = "?"
        nodes = per_host.setdefault(host, {})
        key = _node_key(pid, host)
        if key in nodes and nodes[key].source == "event":
            existing = nodes[key]
            if not existing.name and snap.name:
                existing.name = snap.name
            if not existing.path and snap.path:
                existing.path = snap.path
            if not existing.user and snap.user:
                existing.user = snap.user
            continue
        node = ensure_node(host, pid)
        if not node.name and snap.name:
            node.name = snap.name
        if not node.path and snap.path:
            node.path = snap.path
        if not node.user and snap.user:
            node.user = snap.user
        if not node.guid and snap.guid:
            node.guid = snap.guid
        node.source = node.source or "snapshot"
        if snap.observed_at:
            if node.first_seen is None or snap.observed_at < node.first_seen:
                node.first_seen = snap.observed_at
            if node.last_seen is None or snap.observed_at > node.last_seen:
                node.last_seen = snap.observed_at
        parent_pid = _norm_pid(snap.ppid)
        parent_guid = (snap.parent_guid or "").strip()
        if parent_guid:
            # GUID-first linking: parent_guid names the exact parent process
            # even when PIDs were reused (Sysmon Event 1 identity).
            link_order.append(
                (
                    host,
                    pid,
                    parent_guid,
                    snap.parent_name or "",
                    snap.observed_at or ts_min,
                    True,
                    "guid",
                )
            )
        elif parent_pid and parent_pid != pid:
            link_order.append(
                (
                    host,
                    pid,
                    parent_pid,
                    snap.parent_name or "",
                    snap.observed_at or ts_min,
                    True,
                    "pid",
                )
            )

    # ---- 4) resolve parent links + name-based fallback --------------------
    for host, nodes in per_host.items():
        by_pid = {n.pid: n for n in nodes.values()}
        by_name: dict[str, list[PNode]] = {}
        by_guid: dict[str, PNode] = {}
        for node in nodes.values():
            if node.name:
                by_name.setdefault(node.name.lower(), []).append(node)
            if getattr(node, "guid", ""):
                by_guid[node.guid] = node
        for (
            link_host,
            child_pid,
            parent_ref,
            parent_name,
            _ts,
            verified,
            kind,
        ) in link_order:
            if link_host != host:
                continue
            child = by_pid.get(child_pid)
            if child is None:
                continue
            if kind == "guid" and parent_ref:
                # parent_ref is a ProcessGuid: prefer the exact identity even
                # when PIDs were reused (Sysmon Event 1 parent linkage).
                parent = by_guid.get(parent_ref)
                if parent is not None and parent.pid != child.pid:
                    child.parent_pid = parent.pid
                    child.edge_verified = True
                    continue
            if parent_ref and parent_ref in by_pid:
                child.parent_pid = parent_ref
                child.edge_verified = True
                continue
            if parent_ref and parent_ref != child_pid:
                child.parent_pid = parent_ref  # dangling: parent outside window
                child.edge_verified = verified
                continue
            # name-based fallback: earlier node with the same parent name
            if parent_name:
                candidates = [
                    n
                    for n in by_name.get(parent_name.lower(), [])
                    if n.pid != child.pid
                    and (n.last_seen or child.first_seen)
                    <= (child.first_seen or n.last_seen)
                ]
                if candidates:
                    best = min(candidates, key=lambda n: (n.last_seen or datetime.min))
                    child.parent_pid = best.pid
                    child.parent_name = parent_name
                    child.edge_verified = False

    # ---- 5) seed marking + root selection ---------------------------------
    seeds = _seed_pids(evidence_events)
    all_trees: list[dict] = []
    primary: dict | None = None

    for host, nodes in per_host.items():
        if not nodes:
            continue
        for node in nodes.values():
            if node.pid in seeds:
                node.seed = True

        roots = [
            n
            for n in nodes.values()
            if not n.parent_pid or n.parent_pid not in {x.pid for x in nodes.values()}
        ]
        if not roots:
            roots = [min(nodes.values(), key=lambda n: (n.first_seen or datetime.max))]

        seed_nodes = [n for n in nodes.values() if n.seed]
        best_root = None
        if seed_nodes:
            best_root = max(
                roots,
                key=lambda r: len(_reachable(r, nodes)),
            )
        else:
            best_root = min(roots, key=lambda r: (r.first_seen or datetime.max))

        chain = _chain_to(best_root, nodes, seed_nodes)
        aftermath = _aftermath(nodes, seed_nodes) if seed_nodes else []

        verified_edges = sum(1 for n in nodes.values() if n.edge_verified)
        completeness = verified_edges / len(nodes) if nodes else 0.0

        tree = {
            "host": host,
            "root": best_root.to_dict() if best_root else None,
            "chain": [n.to_dict() for n in chain],
            "aftermath": [n.to_dict() for n in aftermath],
            "nodes": [
                n.to_dict()
                for n in sorted(
                    nodes.values(), key=lambda n: n.first_seen or datetime.min
                )
            ],
            "seed_pids": sorted(seeds),
            "seed_found": bool(seed_nodes),
            "node_count": len(nodes),
            "edge_verified": verified_edges,
            "completeness": round(completeness, 3),
            "sources": sorted({n.source for n in nodes.values()}),
        }
        all_trees.append(tree)
        if primary is None or (len(tree["chain"]) > len(primary["chain"])):
            primary = tree

    if not all_trees:
        return _empty_tree("no process events in window")

    return {
        "trees": all_trees,
        "primary": primary,
        "chain": primary["chain"],
        "aftermath": primary["aftermath"],
        "root": primary["root"],
        "completeness": primary["completeness"],
        "node_count": primary["node_count"],
        "seed_found": primary["seed_found"],
        "seed_pids": sorted(seeds),
    }


def _reachable(root: PNode, nodes: dict[str, PNode]) -> set[str]:
    """All descendant pids reachable from root (BFS)."""
    seen: set[str] = set()
    stack = [root.pid]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for n in nodes.values():
            if n.parent_pid == pid and n.pid not in seen:
                stack.append(n.pid)
    return seen


def _chain_to(root: PNode, nodes: dict[str, PNode], seeds: list[PNode]) -> list[PNode]:
    """Path from root down to the first seed node (breadth-first by depth)."""
    if not seeds:
        return [root]
    parent_map = {n.pid: n for n in nodes.values()}
    seed = max(seeds, key=lambda s: (s.last_seen or datetime.min))
    path: list[PNode] = []
    cur: PNode | None = seed
    guard = 0
    while cur is not None and guard < 60:
        path.append(cur)
        if cur.pid == root.pid:
            break
        cur = parent_map.get(cur.parent_pid or "")
        guard += 1
    path.reverse()
    if path and path[0].pid != root.pid:
        path.insert(0, root)
    return path


def _aftermath(nodes: dict[str, PNode], seeds: list[PNode]) -> list[PNode]:
    """Direct children of seed processes (what ran after the trigger)."""
    seed_pids = {s.pid for s in seeds}
    return [n for n in nodes.values() if n.parent_pid in seed_pids][:25]


def _empty_tree(reason: str) -> dict:
    return {
        "trees": [],
        "primary": None,
        "chain": [],
        "aftermath": [],
        "root": None,
        "completeness": 0.0,
        "node_count": 0,
        "seed_found": False,
        "seed_pids": [],
        "reason": reason,
    }

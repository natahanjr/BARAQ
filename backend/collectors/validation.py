"""Data validation layer for the event pipeline (auto-fix corrupted data).

Windows SafeFormatMessage / event-render truncation can produce *corrupted*
values that look like security-relevant process activity but carry no real
information - classic 1-char "process names" such as ``C``, ``F``, ``\\``,
``g`` that drive false-positive alerts (e.g. a process-creation rule firing
on a truncated image).  This module separates three states:

* **valid** - the value is a real process image / command line;
* **truncated** - a full value was cut mid-way (handled by the normalizer's
  ``data_integrity`` flag and the rules engine's demotion path, NOT here);
* **corrupted** - the value is rendering debris with no signal at all.
  Corrupted events are *discarded before detection* so they can never
  generate alerts, and every discard is counted by the quality tracker.
"""

from __future__ import annotations

import re

#: 1-char (or symbol-only) values produced by truncated event rendering.
#: A real process image is at least "cmd" + an executable suffix; anything
#: in this set (or a <3-char stub without a path/extension separator) is
#: treated as corrupted rendering debris.
_DEBRIS = {
    *"abcdefghijklmnopqrstuvwxyz",
    *"0123456789",
    "\\",
    "/",
    "-",
    ".",
    "..",
    "...",
    "?",
    "*",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    '"',
    "'",
    ",",
    ":",
    ";",
    "|",
    "&",
    "<",
    ">",
    "=",
    "+",
    "_",
    "~",
    "`",
    "!",
    "@",
    "#",
    "$",
    "%",
    "^",
    "n/a",
    "na",
    "- ",
    " -",
}
#: Facts keys that carry a process image / creator / parent value.
_PROCESS_VALUE_KEYS = (
    "new_process",
    "image_path",
    "NewProcessName",
    "image",
    "creator_process",
    "parent_image",
    "old_process",
    "OldProcessName",
)
#: Facts keys that carry a command line / script block value.
_CMDLINE_VALUE_KEYS = (
    "command_line",
    "CommandLine",
    "script_block",
    "ScriptBlockText",
)

#: Structured process records (sysmon / agent) use these keys instead.
_RECORD_PROCESS_KEYS = ("name", "path", "process", "parent_name")
_RECORD_CMDLINE_KEYS = ("cmdline", "command_line")
_SEPARATOR = re.compile(r"[\\/.]")


def _strip(value) -> str:
    return str(value or "").strip()


def _debris_value(value: str) -> bool:
    """True when ``value`` is rendering debris (corrupted, not truncated)."""
    v = _strip(value)
    if not v:
        return False
    if v.lower() in _DEBRIS:
        return True
    return bool(len(v) < 3 and not _SEPARATOR.search(v))


def is_debris_value(value: str) -> bool:
    """Public alias: is this value corrupted rendering debris (no signal)?"""
    return _debris_value(value)


def is_corrupted_facts(facts: dict) -> tuple[bool, str]:
    """Check normalized facts for corrupted process / command-line values.

    Returns ``(True, reason)`` when the facts carry rendering debris.
    Missing values are NOT treated as corruption here - they are handled by
    the normalizer's truncation detection and the rules engine's
    data-integrity demotion so no real events are lost.
    """
    for key in _PROCESS_VALUE_KEYS:
        value = facts.get(key)
        if value and _debris_value(value):
            return True, f"{key} is rendering debris: {value!r}"
    for key in _CMDLINE_VALUE_KEYS:
        value = facts.get(key)
        if value and _debris_value(value):
            return True, f"{key} is rendering debris: {value!r}"
    return False, ""


def normalized_is_corrupted(normalized: dict) -> tuple[bool, str]:
    """Check a normalized event dict (as produced by the normalizer).

    Also flags an explicitly-empty user field (the event-log "-" placeholder
    is fine; an empty string on a real event is corruption).
    """
    facts = (normalized.get("raw_json") or {}).get("facts") or {}
    corrupted, reason = is_corrupted_facts(facts)
    if corrupted:
        return True, reason
    if normalized.get("user") == "":
        return True, "user field is empty"
    return False, ""


def orm_event_is_corrupted(event) -> tuple[bool, str]:
    """Check a stored ``NormalizedEvent`` row against the corruption rules.

    Used by the ML loaders and scoring loop so corrupted history that
    slipped in before the validation layer is never trained on or scored.
    """
    raw = getattr(event, "raw_json", None) or {}
    if getattr(event, "data_integrity", None) == "corrupted":
        return True, "event marked corrupted"
    return normalized_is_corrupted(
        {"user": getattr(event, "user", "-"), "raw_json": raw}
    )


def structured_record_is_corrupted(record: dict) -> tuple[bool, str]:
    """Check a structured (non-eventlog) collector record - process/network.

    ``source="process"`` records carry ``name``/``path``/``cmdline``; other
    structured sources are validated by presence of their core field.
    """
    source = record.get("source", "")
    for key in _RECORD_PROCESS_KEYS:
        value = record.get(key)
        if value and _debris_value(value):
            return True, f"{source}.{key} is rendering debris: {value!r}"
    for key in _RECORD_CMDLINE_KEYS:
        value = (record.get("raw") or {}).get(key) or record.get(key)
        if value and _debris_value(value):
            return True, f"{source}.{key} is rendering debris: {value!r}"
    return False, ""


def validate_raw_record(record: dict) -> tuple[bool, str]:
    """Lightweight structural validation for raw collector records.

    Cheap checks only (no parsing): the record must be a dict with a known
    source and, when a timestamp is present, it must be a parseable value.
    Semantic validation happens on the normalized event / structured record.
    """
    if not isinstance(record, dict):
        return False, "record is not a dict"
    source = record.get("source")
    if not source:
        return False, "record has no source"
    event_id = record.get("event_id")
    if event_id is not None:
        try:
            int(event_id)
        except (TypeError, ValueError):
            return False, f"event_id is not an integer: {event_id!r}"
    return True, ""

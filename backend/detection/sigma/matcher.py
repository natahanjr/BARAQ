"""Sigma detection matching: value comparison against event fields and
boolean condition evaluation (and/or/not, parentheses, 'N of ...').

Event fields are flattened to strings (plus EventID) before matching, so
Sigma field names and values can be compared with modifiers.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any

_VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "base64", "cidr", "null", "utf16"}

_TOKEN_RE = re.compile(r"(?:\d+)\s+of|\band\b|\bor\b|\bnot\b|[()]|[^\s()]+", re.IGNORECASE)

#: Fact-key spellings that should land on the canonical flattened field.
_ALIAS_KEYS = {
    "commandline": "command_line",
    "cmdline": "command_line",
    "imagepath": "image_path",
    "imagename": "image_path",
    "parentimage": "parent_image",
    "sourceimage": "source_image",
    "targetimage": "target_image",
    "eventid": "event_id",
    "ipaddress": "source_ip",
    "sourceip": "source_ip",
    "sourceaddress": "source_ip",
    "clientaddress": "client_ip",
}

#: Fields carrying process identity/activity. Rules depending on them cannot
#: be trusted when the event's process data is incomplete or truncated.
PROCESS_FIELDS = {
    "image", "image_path", "new_process", "parent_image", "source_image",
    "target_image", "image_loaded", "command_line", "script_block",
}


def event_data_integrity(event) -> dict:
    """Data-integrity flags for one event (set by the normalizer).

    Returns ``complete`` / ``truncated_fields`` / ``process_incomplete``
    (no process data captured at all) / ``process_truncated`` (process
    fields present but cut short).
    """
    raw = event.raw_json or {}
    integrity = raw.get("data_integrity")
    if not isinstance(integrity, dict):
        return {
            "complete": True,
            "truncated_fields": [],
            "process_incomplete": False,
            "process_truncated": False,
        }
    truncated = [str(f) for f in integrity.get("truncated_fields") or []]
    process_fields = {p.lower().replace("_", "") for p in PROCESS_FIELDS}
    process_bad = [
        f for f in truncated
        if f.lower().replace("_", "") in process_fields or f.lower() == "process_data"
    ]
    return {
        "complete": not truncated,
        "truncated_fields": truncated,
        "process_incomplete": "process_data" in truncated,
        "process_truncated": bool(process_bad),
    }


def build_event_fields(event) -> dict[str, str]:
    """Flatten a normalized event into Sigma-matchable string fields."""
    facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
    raw_json = event.raw_json or {}
    out: dict[str, str] = {"event_id": str(event.event_id)}
    out["channel"] = str(raw_json.get("channel", "")).lower()
    out["message"] = str(event.message or "").lower()
    out["user"] = str(event.user or "")
    out["category"] = str(event.category or "")
    out["command_line"] = ""
    out["image_path"] = ""
    #: Data-integrity status so rules can filter incomplete events, e.g.
    #: ``data_integrity: complete`` or a ``filter`` selection on it.
    integrity = raw_json.get("data_integrity")
    if isinstance(integrity, dict):
        out["data_integrity"] = "truncated" if integrity.get("truncated_fields") else "complete"
    else:
        out["data_integrity"] = str(integrity or "complete").lower()
    for key, value in facts.items():
        normalized = _ALIAS_KEYS.get(str(key).lower(), str(key).lower())
        out[normalized] = str(value)
    #: Canonical Sigma process fields -> BARAQ fact vocabulary, so community
    #: rules written against Sysmon/Windows "Image", "ParentImage" and
    #: "CommandLine" match what the collectors actually ship.
    proc = str(facts.get("new_process") or facts.get("NewProcessName") or "")
    if proc:
        out["image"] = proc
        out["image_path"] = proc
    parent = str(facts.get("ParentProcessName") or "")
    if parent:
        out["parent_image"] = parent
    if facts.get("CommandLine"):
        out["command_line"] = str(facts["CommandLine"])
    return out


def _lookup(fields: dict[str, str], name: str) -> str | None:
    key = name.lower()
    key = _ALIAS_KEYS.get(key, key)
    if key in fields:
        return fields[key]
    key = key.replace("_", "").replace(".", "").replace("-", "")
    for field_key, value in fields.items():
        if field_key.replace("_", "").replace(".", "").replace("-", "") == key:
            return value
    return None


def _as_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def _expand_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_as_str(v) for v in value]
    return [_as_str(value)]


def _match_value(field_value: str, expected: str, modifiers: set[str]) -> bool:
    """Match one field value against one expected value with modifiers."""
    if "base64" in modifiers:
        try:
            field_value = base64.b64decode(field_value).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            return False
    if "re" in modifiers:
        try:
            return re.search(expected, field_value, re.IGNORECASE) is not None
        except re.error:
            return False
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(field_value) in ipaddress.ip_network(expected, strict=False)
        except ValueError:
            return False
    if "contains" in modifiers:
        return expected.lower() in field_value.lower()
    if "startswith" in modifiers:
        return field_value.lower().startswith(expected.lower())
    if "endswith" in modifiers:
        return field_value.lower().endswith(expected.lower())
    return field_value.lower() == expected.lower()


def _selection_matches(fields: dict[str, str], selection: Any) -> bool:
    """A selection matches when all its field comparisons succeed (dict) or
    any keyword is contained in any field (bare list)."""
    if isinstance(selection, dict):
        for key, value in selection.items():
            key_parts = str(key).split("|")
            field_name = key_parts[0]
            modifiers = {m.lower() for m in key_parts[1:] if m.lower() in _VALUE_MODIFIERS}
            field_value = _lookup(fields, field_name)
            if value is None or "null" in modifiers:
                # Sigma semantics: ``field: null`` (bare YAML null value or
                # the explicit ``|null`` modifier) matches a missing OR empty
                # field. Missing keys must not fail the comparison before the
                # null check.
                if not field_value:
                    continue
                return False
            if field_value is None:
                return False
            expected = _expand_value(value)
            if "all" in modifiers:
                if not all(_match_value(field_value, e, modifiers) for e in expected):
                    return False
            elif not any(_match_value(field_value, e, modifiers) for e in expected):
                return False
        return True

    if isinstance(selection, list):
        haystack = " ".join(fields.values()).lower()
        keywords = [_as_str(v).lower() for v in selection]
        return any(k in haystack for k in keywords)

    return bool(selection)


def _of_matches(names: dict[str, Any], fields: dict[str, str], needed: int, pattern: str) -> bool:
    matched = 0
    pattern = pattern.lower()
    for name, selection in names.items():
        if pattern == "them":
            ok = _selection_matches(fields, selection)
        elif pattern.endswith("*"):
            ok = name.lower().startswith(pattern.rstrip("*"))
        else:
            ok = name.lower() == pattern
        if ok and _selection_matches(fields, selection):
            matched += 1
            if matched >= needed:
                return True
    return False


class SigmaCondition:
    """Pre-parsed boolean condition over named selections (recursive descent:
    or < and < not; operands are selection names, 'them', or 'N of pattern')."""

    def __init__(self, condition: str):
        self.condition = condition
        self.tokens = [t for t in _TOKEN_RE.findall(condition) if t.strip()]

    def evaluate(self, names: dict[str, Any], fields: dict[str, str]) -> bool:
        if not self.tokens:
            return False
        self._pos = 0
        self._names = names
        self._fields = fields
        try:
            return bool(self._parse_or())
        except (IndexError, ValueError):
            return False

    def _peek(self) -> str:
        return self.tokens[self._pos]

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._pos < len(self.tokens) and self._peek().lower() == "or":
            self._pos += 1
            value = value or self._parse_and()
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._pos < len(self.tokens) and self._peek().lower() == "and":
            self._pos += 1
            value = value and self._parse_not()
        return value

    def _parse_not(self) -> bool:
        if self._pos < len(self.tokens) and self._peek().lower() == "not":
            self._pos += 1
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        token = self.tokens[self._pos]
        if token == "(":
            self._pos += 1
            value = self._parse_or()
            if self._pos < len(self.tokens) and self._peek() == ")":
                self._pos += 1
            return value
        self._pos += 1
        return self._parse_operand(token)

    def _parse_operand(self, token: str) -> bool:
        lower = token.lower()
        if lower == "them":
            return all(_selection_matches(self._fields, s) for s in self._names.values())
        if lower in self._names:
            return _selection_matches(self._fields, self._names[lower])
        #: The tokenizer joins ``N of`` into a single token; ``N of X``
        #: means: at least N selections whose name matches X evaluate True.
        m = re.fullmatch(r"(\d+)\s+of", lower)
        if m:
            if self._pos >= len(self.tokens):
                return False
            pattern = self.tokens[self._pos].lower()
            self._pos += 1
            return _of_matches(self._names, self._fields, int(m.group(1)), pattern)
        if token.isdigit() and self._pos < len(self.tokens) and self._peek().lower() == "of":
            self._pos += 1
            pattern = self.tokens[self._pos].lower()
            self._pos += 1
            return _of_matches(self._names, self._fields, int(token), pattern)
        if re.fullmatch(r"\d+", token):
            # bare number with no following 'of' - not a valid operand
            return False
        return False

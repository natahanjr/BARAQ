"""Sigma detection matching: value comparison against event fields and
boolean condition evaluation (and/or/not, parentheses, 'N of ...').

Event fields are flattened to strings (plus EventID) before matching, so
Sigma field names and values can be compared with modifiers.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from functools import lru_cache
from typing import Any

_VALUE_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "all",
    "base64",
    "cidr",
    "null",
    "utf16",
}

_TOKEN_RE = re.compile(
    r"(?:\d+)\s+of|\band\b|\bor\b|\bnot\b|[()]|[^\s()]+", re.IGNORECASE
)

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
    "image",
    "image_path",
    "new_process",
    "parent_image",
    "source_image",
    "target_image",
    "image_loaded",
    "command_line",
    "script_block",
}

#: Normalized (no underscores) spellings of PROCESS_FIELDS, precomputed once:
#: event_data_integrity() runs per (rule x event) in the hot loops and used to
#: rebuild this set on every call.
_PROCESS_FIELDS_NORM = {p.lower().replace("_", "") for p in PROCESS_FIELDS}


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
    process_bad = [
        f
        for f in truncated
        if f.lower().replace("_", "") in _PROCESS_FIELDS_NORM
        or f.lower() == "process_data"
    ]
    return {
        "complete": not truncated,
        "truncated_fields": truncated,
        "process_incomplete": "process_data" in truncated,
        "process_truncated": bool(process_bad),
    }


def build_event_fields(event) -> dict[str, str]:
    """Flatten a normalized event into Sigma-matchable string fields."""
    facts = event.facts or {}
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
        out["data_integrity"] = (
            "truncated" if integrity.get("truncated_fields") else "complete"
        )
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
    return EventFields(out)


class EventFields(dict[str, str]):
    """Per-event flattened fields with a lazily built normalized-key index.

    ``_lookup`` needs a normalized view of the key names (Sigma writes
    ``TargetFilename`` while facts may carry ``target_filename``). Building
    that index once per event instead of once per (rule, selection, event)
    lookup removes a hot O(fields) scan from the matching loop.
    """

    __slots__ = ("_norm_index", "_haystack")

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._norm_index: dict[str, str] | None = None
        self._haystack: str | None = None


@lru_cache(maxsize=4096)
def _lookup_candidates(name: str) -> tuple[str, str]:
    """Canonical (exact_key, normalized_key) probes for one Sigma field name.

    Cached because rule field names repeat across every event the rule is
    evaluated against - re-lowering and re-stripping them per lookup was a
    measurable share of the hot matching loop.
    """
    key = name.lower()
    key = _ALIAS_KEYS.get(key, key)
    norm = key.replace("_", "").replace(".", "").replace("-", "")
    return key, norm


def _lookup(fields: dict[str, str], name: str) -> str | None:
    exact, norm = _lookup_candidates(name)
    if exact in fields:
        return fields[exact]
    if norm == exact:
        # Already normalized - the fallback scan cannot match anything new.
        return None
    if isinstance(fields, EventFields):
        idx = fields._norm_index
        if idx is None:
            idx = {}
            for field_key in fields:
                nk = field_key.replace("_", "").replace(".", "").replace("-", "")
                idx.setdefault(nk, field_key)
            fields._norm_index = idx
        field_key = idx.get(norm)
        return fields[field_key] if field_key is not None else None
    # Plain dict (tests, ad-hoc maps): scan like the original implementation.
    for field_key, value in fields.items():
        if field_key.replace("_", "").replace(".", "").replace("-", "") == norm:
            return value
    return None


def _as_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def _expand_value(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [_as_str(value)]
    if isinstance(value, list):
        return [_as_str(v) for v in value]
    return [_as_str(value)]


def _match_value(field_value: str, expected: str, modifiers: Any) -> bool:
    """Match one field value against one expected value with modifiers.

    Thin wrapper around a memoized core: (value, expected, modifier) triples
    repeat heavily across the 2500-rule x event hot loop, and the core path
    re-lowercases both sides on every call without the cache. ``modifiers``
    arrives as a frozenset from the cached ``_split_key`` and is used directly
    as part of the cache key (no re-encoding per call).
    """
    if not isinstance(modifiers, frozenset):
        modifiers = frozenset(modifiers)
    return _match_value_cached(field_value, expected, modifiers)


@lru_cache(maxsize=131072)
def _match_value_cached(
    field_value: str, expected: str, modifiers: frozenset[str]
) -> bool:
    if "base64" in modifiers:
        try:
            field_value = base64.b64decode(field_value).decode("utf-8", "ignore")
        except Exception:
            return False
    if "re" in modifiers:
        try:
            return re.search(expected, field_value, re.IGNORECASE) is not None
        except re.error:
            return False
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(field_value) in ipaddress.ip_network(
                expected, strict=False
            )
        except ValueError:
            return False
    if "contains" in modifiers:
        return expected.lower() in field_value.lower()
    if "startswith" in modifiers:
        return field_value.lower().startswith(expected.lower())
    if "endswith" in modifiers:
        return field_value.lower().endswith(expected.lower())
    return field_value.lower() == expected.lower()


@lru_cache(maxsize=8192)
def _split_key(key: str) -> tuple[str, frozenset[str]]:
    """Split a selection key into (field_name, modifiers).

    Accepts both Sigma spellings: ``CommandLine|contains`` (standard) and
    ``CommandLine:contains`` (legacy / generator style used by many custom
    rules). Unknown segments are treated as field-name parts, not modifiers.

    Cached: selection keys come from static rule files and repeat for every
    event the rule is evaluated against. Returns a frozenset so the cached
    result can never be mutated by callers.
    """
    raw = str(key)
    if "|" in raw:
        parts = raw.split("|")
        field = parts[0]
        mods = {p.strip().lower() for p in parts[1:] if p.strip()}
        return field, frozenset(mods & _VALUE_MODIFIERS)
    if ":" in raw:
        # Trailing modifier after the last colon (e.g. "CommandLine:contains").
        head, _, tail = raw.rpartition(":")
        tail_l = tail.strip().lower()
        if head and tail_l in _VALUE_MODIFIERS:
            return head, frozenset({tail_l})
    return raw, frozenset()


def _selection_matches(fields: dict[str, str], selection: Any) -> bool:
    """A selection matches when all its field comparisons succeed (dict) or
    any keyword is contained in any field (bare list)."""
    if isinstance(selection, dict):
        for key, value in selection.items():
            field_name, modifiers = _split_key(key)
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
            if len(expected) == 1:
                # Scalar YAML values (the common case) skip the any()/all()
                # generator machinery entirely in the hot loop.
                if not _match_value(field_value, expected[0], modifiers):
                    return False
            elif "all" in modifiers:
                if not all(_match_value(field_value, e, modifiers) for e in expected):
                    return False
            elif not any(_match_value(field_value, e, modifiers) for e in expected):
                return False
        return True

    if isinstance(selection, list):
        haystack = None
        if isinstance(fields, EventFields):
            haystack = fields._haystack
            if haystack is None:
                haystack = " ".join(fields.values()).lower()
                fields._haystack = haystack
        if haystack is None:
            haystack = " ".join(fields.values()).lower()
        keywords = [_as_str(v).lower() for v in selection]
        return any(k in haystack for k in keywords)

    return bool(selection)


def _of_matches(
    names: dict[str, Any], fields: dict[str, str], needed: int, pattern: str
) -> bool:
    matched = 0
    pattern = pattern.lower()
    for name, selection in names.items():
        if pattern == "them":
            # 'them' selects every selection - the name test *is* the
            # selection test (the old code evaluated it twice per name).
            ok = _selection_matches(fields, selection)
        elif pattern.endswith("*"):
            ok = name.lower().startswith(pattern.rstrip("*")) and (
                _selection_matches(fields, selection)
            )
        else:
            ok = name.lower() == pattern and _selection_matches(fields, selection)
        if ok:
            matched += 1
            if matched >= needed:
                return True
    return False


_N_OF_RE = re.compile(r"(\d+)\s+of")
_DIGITS_RE = re.compile(r"\d+")


class SigmaCondition:
    """Boolean condition over named selections.

    The condition string is tokenized and compiled **once** into a tree of
    closures at construction (or < and < not; operands are selection names,
    'them', or 'N of pattern'). The previous design re-walked the token
    stream with a mutable-position recursive descent on *every* evaluate()
    call - with hundreds of candidate rules per event that interpret loop
    dominated the Sigma matching cost. evaluate() is now stateless (safe to
    share across passes) and preserves the original short-circuit and
    failure semantics: an unparseable condition evaluates to False.
    """

    def __init__(self, condition: str):
        self.condition = condition
        self.tokens = [t for t in _TOKEN_RE.findall(condition) if t.strip()]
        self._root = None
        if not self.tokens:
            return
        self._pos = 0
        try:
            self._root = self._compile_or()
        except (IndexError, ValueError):
            self._root = None

    def evaluate(self, names: dict[str, Any], fields: dict[str, str]) -> bool:
        root = self._root
        if root is None:
            return False
        try:
            return bool(root(names, fields))
        except (IndexError, ValueError):
            return False

    # --- compile-time recursive descent (mirrors the old runtime parser) ---

    def _peek(self) -> str:
        return self.tokens[self._pos]

    def _compile_or(self):
        node = self._compile_and()
        while self._pos < len(self.tokens) and self._peek().lower() == "or":
            self._pos += 1
            right = self._compile_and()
            node = self._make_or(node, right)
        return node

    def _compile_and(self):
        node = self._compile_not()
        while self._pos < len(self.tokens) and self._peek().lower() == "and":
            self._pos += 1
            right = self._compile_not()
            node = self._make_and(node, right)
        return node

    def _compile_not(self):
        if self._pos < len(self.tokens) and self._peek().lower() == "not":
            self._pos += 1
            inner = self._compile_not()
            return self._make_not(inner)
        return self._compile_primary()

    def _compile_primary(self):
        token = self.tokens[self._pos]
        if token == "(":
            self._pos += 1
            node = self._compile_or()
            if self._pos < len(self.tokens) and self._peek() == ")":
                self._pos += 1
            return node
        self._pos += 1
        return self._compile_operand(token)

    @staticmethod
    def _make_or(left, right):
        return lambda names, fields: left(names, fields) or right(names, fields)

    @staticmethod
    def _make_and(left, right):
        return lambda names, fields: left(names, fields) and right(names, fields)

    @staticmethod
    def _make_not(inner):
        return lambda names, fields: not inner(names, fields)

    @staticmethod
    def _them_node():
        return lambda names, fields: all(
            _selection_matches(fields, s) for s in names.values()
        )

    @staticmethod
    def _name_node(lower: str):
        # Unknown-at-compile-time selection names resolve per evaluate(), so
        # a missing selection yields False exactly like the old parser.
        def op(names: dict[str, Any], fields: dict[str, str]) -> bool:
            if lower in names:
                return _selection_matches(fields, names[lower])
            return False

        return op

    @staticmethod
    def _of_node(lower: str, needed: int, pattern: str):
        # Runtime order preserved: a selection literally named like the
        # 'N of' token would take priority (unreachable in practice - the
        # tokenizer only emits 'N of' for digit-prefixed phrases).
        def op(names: dict[str, Any], fields: dict[str, str]) -> bool:
            if lower in names:
                return _selection_matches(fields, names[lower])
            return _of_matches(names, fields, needed, pattern)

        return op

    @staticmethod
    def _false_node():
        return lambda names, fields: False

    def _compile_operand(self, token: str):
        lower = token.lower()
        if lower == "them":
            return self._them_node()
        m = _N_OF_RE.fullmatch(lower)
        if m:
            # Tokenizer joined 'N of' into one token; the following token is
            # the selection-name pattern (runtime consumed it at this point).
            if self._pos >= len(self.tokens):
                return self._false_node()
            pattern = self.tokens[self._pos].lower()
            self._pos += 1
            return self._of_node(lower, int(m.group(1)), pattern)
        if (
            token.isdigit()
            and self._pos < len(self.tokens)
            and self._peek().lower() == "of"
        ):
            self._pos += 1  # consume 'of'
            pattern = self.tokens[self._pos].lower()
            self._pos += 1
            return self._of_node(lower, int(token), pattern)
        if _DIGITS_RE.fullmatch(token):
            # bare number with no following 'of' - not a valid operand
            return self._false_node()
        return self._name_node(lower)

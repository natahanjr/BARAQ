"""Shared false-positive filters for detection rules.

Local automation tooling (coding assistants, package managers, CI agents)
legitimately runs scripts from user-writable directories with flags such as
``-NoProfile -ExecutionPolicy Bypass``. Those executions are indistinguishable
from malware by command line alone, so rules can opt out of alerting on them
via a configurable allowlist of trusted paths.

Configure extra allowed path fragments with ``BARAQ_FP_ALLOW_PATHS``
(semicolon-separated, matched case-insensitively anywhere in the text).
"""

from __future__ import annotations

import os
import re

#: Path fragments that identify known-local automation tooling.
_DEFAULT_TRUSTED_FRAGMENTS = (
    r"AppData\\Local\\Temp\\opencode\\",
    r"AppData/Local/Temp/opencode/",
    # Baraq project directory — user's own scripts (toast notifications, helpers).
    r"F:\\My Project\\Baraq\\",
    r"F:/My Project/Baraq/",
    # Common user project directories.
    r"\\Documents\\",
    r"\\Desktop\\",
    r"\\Repos\\",
    r"\\Projects\\",
)


def _compile_patterns() -> re.Pattern[str]:
    fragments = list(_DEFAULT_TRUSTED_FRAGMENTS)
    extra = os.environ.get("BARAQ_FP_ALLOW_PATHS", "")
    for part in extra.split(";"):
        part = part.strip()
        if part:
            fragments.append(re.escape(part))
    return re.compile("|".join(fragments), re.IGNORECASE) if fragments else None


_TRUSTED_PATH_RE = _compile_patterns()


def is_trusted_agent_activity(*texts: str) -> bool:
    """True when any text references a trusted automation path.

    Deliberately permissive (substring match): a benign helper script that
    merely mentions the agent directory is far more likely than an attacker
    colliding with this exact local path.
    """
    if _TRUSTED_PATH_RE is None:
        return False
    for text in texts:
        if text and _TRUSTED_PATH_RE.search(text):
            return True
    return False

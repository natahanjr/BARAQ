"""Generate .env.example from backend config: every BARAQ_* flag with its
default and doc comment. Run from repo root:
    python scripts/gen_env_example.py > .env.example
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SEP_RE = re.compile(r"#\s*-{3,}")

VAR_RE = re.compile(
    r'(?:os\.environ\.get|_secret)\("(BARAQ_[A-Z0-9_]+)"(?:\s*,\s*(.*?))?\)'
)
NAME_RE = re.compile(r'"?(BARAQ_[A-Z0-9_]+)"?')


def _is_header(text: str) -> bool:
    stripped = text.lstrip("#").strip()
    if not stripped:
        return True
    return bool(len(stripped) < 60 and not stripped.endswith((".", ":", ";", ")", '"')))


def collect(path: Path) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return found
    for i, line in enumerate(lines):
        if "_secret(" not in line and "os.environ.get(" not in line:
            continue
        m = VAR_RE.search(line)
        if m:
            name = m.group(1)
            default = m.group(2)
            if default is not None:
                default = default.rstrip(")").strip()
            else:
                default = ""
            if default and (default.startswith(('"', "'"))):
                default = default[1:-1] if len(default) >= 2 else ""
            if default and not re.fullmatch(r"[0-9A-Za-z_\-./: %=]+", default):
                default = ""
        else:
            # Multi-line call: `os.environ.get(` / `_secret(` on this line,
            # name (and maybe default) on the following lines.
            m2 = NAME_RE.search(line)
            if not m2:
                window = "\n".join(lines[i : i + 3])
                m2 = NAME_RE.search(window)
            if not m2:
                continue
            name = m2.group(1)
            default = ""
            window = "\n".join(lines[i : i + 4])
            md = re.search(r'"BARAQ_[A-Z0-9_]+"\s*,\s*(.+?)\)', window)
            if md:
                default = md.group(1).strip()
                if default.startswith(('"', "'")):
                    default = default[1:-1] if len(default) >= 2 else ""
                if default and not re.fullmatch(r"[0-9A-Za-z_\-./: %=]+", default):
                    default = ""
        comment: list[str] = []
        for prev in lines[max(0, i - 8) : i]:
            t = prev.strip()
            if not t.startswith("#"):
                break
            if _SEP_RE.match(t):
                break
            comment.insert(0, t.lstrip("#").lstrip(":").strip())
        while comment and _is_header(comment[0]):
            comment.pop(0)
        found[name] = (default, "\n".join(comment))
    return found


def main() -> None:
    all_vars: dict[str, tuple[str, str]] = {}
    for py in sorted((ROOT / "backend").rglob("*.py")):
        if "__pycache__" in str(py):
            continue
        for name, info in collect(py).items():
            all_vars.setdefault(name, info)

    out = [
        "# BARAQ environment template. Copy to .env and edit.",
        "# Every flag in this file is read by backend/config.py (and the",
        "# collector/agent modules); defaults match a fresh development setup.",
        "# Secrets prefer the DPAPI vault over environment / .env.",
        "",
    ]
    for name in sorted(all_vars):
        default, comment = all_vars[name]
        default = default.replace('"', "")
        if comment:
            for cl in comment.splitlines():
                out.append(f"# {cl}")
        out.append(f"{name}={default}")
        out.append("")

    target = ROOT / ".env.example"
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(all_vars)} flags)")


if __name__ == "__main__":
    main()

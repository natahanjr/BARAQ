"""Alert context engine - enriches detections with environmental context.

The roadmap's context dimensions, computed from the evidence of a finding:

* **process reputation** - known system / Microsoft tooling vs developer
  tooling vs unknown binaries (unknown = most suspicious).
* **developer environment** - venv / site-packages / node_modules / package
  managers / git / jupyter / linters in the command line or paths.
* **localhost flows** - destinations that never leave the box
  (127.0.0.1 / ::1 / localhost).
* **known project paths** - processes launched from dev workspaces
  (Projects / Repos / Workspace / src / Documents / Desktop / Downloads).
* **parent/child context** - which parent image spawned the process.
* **user context** - interactive analyst account vs SYSTEM / service.
* **command-line context** - the triggering command line, extracted from the
  linked evidence.

The engine produces two calibrations used by the alerting layer:

* ``risk_modifier`` - a 0..1 multiplier for the alert's hybrid risk score
  (dev/system context dampens the score; unknown reputation keeps it at 1.0).
* ``severity_adjust`` - a one-step demotion for *developer-sensitive* rules
  (powershell, python, screen capture, account/filesystem discovery, git)
  when the evidence is strongly developmental and confidence is low - the
  classic false-positive profile on a developer laptop.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from sqlalchemy import select

logger = logging.getLogger("baraq.context")

# ---------------------------------------------------------------------------
# static knowledge
# ---------------------------------------------------------------------------

_SYSTEM_ROOT_MARKERS = (
    "C:\\windows",
    "C:\\program files\\microsoft",
    "C:\\program files (x86)\\microsoft",
    "C:\\programdata\\microsoft",
    "C:\\program files\\windowsapps",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\systemapps",
)

_KNOWN_SERVICE_PROCESSES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "smss.exe", "spoolsv.exe", "SearchHost.exe",
    "SearchIndexer.exe", "OneDrive.exe", "Teams.exe", "MsMpEng.exe",
    "MsMpEngCp.exe", "TrustedInstaller.exe", "TiWorker.exe", "conhost.exe",
    "sihost.exe", "taskhostw.exe", "RuntimeBroker.exe", "dllhost.exe",
    "registry.exe", "wmiprvse.exe", "WmiPrvSE.exe", "audiodg.exe",
    "fontdrvhost.exe", "dwm.exe", "ShellExperienceHost.exe",
    "StartMenuExperienceHost.exe", "Widgets.exe", "ctfmon.exe",
    "PresentationFontCache.exe", "PcaSvc.exe", "consent.exe", "explorer.exe",
    "agent_service.exe", "securityhealthservice.exe", "SecurityHealthSystray.exe",
    "msiexec.exe", "sihost.exe", "taskhostex.exe", "fontdrvhost.exe",
    "winlogon.exe", "LogonUI.exe", "userinit.exe", "dllhost.exe",
    "postgres.exe", "postmaster.exe", "sqlservr.exe", "mysqld.exe", "mongod.exe",
    "redis-server.exe", "nginx.exe", "httpd.exe", "w3wp.exe", "node-red.exe",
}

_KNOWN_TOOL_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "WindowsTerminal.exe", "wt.exe",
    "conhost.exe", "notepad.exe", "mspaint.exe", "calc.exe", "explorer.exe",
    "taskmgr.exe", "regedit.exe", "mmc.exe", "powershell_ise.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "opera.exe", "brave.exe",
    "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe",
    "teams.exe", "slack.exe", "discord.exe", "zoom.exe", "code.exe",
    "code-insiders.exe", "winpty.exe", "agent.exe", "grep.exe", "find.exe",
}

_DEV_PROCESSES = {
    "python.exe", "pythonw.exe", "py.exe", "python3.exe", "pip.exe", "pip3.exe",
    "node.exe", "npm.exe", "npx.exe", "yarn.exe", "pnpm.exe", "tsc.exe",
    "tsx.exe", "vite.exe", "git.exe", "git-bash.exe", "bash.exe", "sh.exe",
    "jupyter-notebook.exe", "jupyter.exe", "ipython.exe", "conda.exe",
    "mamba.exe", "poetry.exe", "uv.exe", "docker.exe", "docker-compose.exe",
    "wsl.exe", "wslhost.exe", "sqlite3.exe", "psql.exe", "mysql.exe",
    "redis-cli.exe", "mongod.exe", "go.exe", "cargo.exe", "rustc.exe",
    "javac.exe", "java.exe", "gradle.exe", "mvn.exe", "dotnet.exe",
    "dotnet.exe", "cl.exe", "gcc.exe", "g++.exe", "make.exe", "cmake.exe",
    "ninja.exe", "bun.exe", "deno.exe", "php.exe", "ruby.exe", "perl.exe",
    "lua.exe", "rscript.exe", "swift.exe", "kotlinc.exe", "flutter.exe",
    "adb.exe", "kubectl.exe", "terraform.exe", "ansible.exe", "scp.exe",
    "ssh.exe", "curl.exe", "wget.exe", "jq.exe", "rg.exe", "ripgrep.exe",
    "eslint.exe", "prettier.exe", "ruff.exe", "black.exe", "mypy.exe",
    "pytest.exe", "jest.exe", "next.exe", "ng.exe", "nest.exe", "create-react-app.exe",
    # Agentic / AI coding CLIs - developer workflow by definition.
    "opencode.exe", "aider.exe", "claude.exe", "codex.exe", "gemini.exe",
    "cursor.exe", "copilot.exe",
}

_DEV_PATH_MARKERS = (
    "\\venv\\", "\\.venv\\", "\\site-packages\\", "\\node_modules\\",
    "\\PycharmProjects\\", "\\IdeaProjects\\", "\\WebstormProjects\\",
    "\\Projects\\", "\\Repos\\", "\\Workspace\\", "\\workspace\\", "\\src\\",
    "\\Sources\\", "\\Code\\", "\\dev\\", "\\Development\\",
    "\\AppData\\Local\\Programs\\Python",
)

_DEV_CMD_MARKERS = (
    "python -m ", "py -m ", "python3 -m ", "pip install", "pip3 install",
    "uv run", "uv pip", "poetry run", "poetry install", "conda run",
    "npm ", "npx ", "yarn ", "pnpm ", "bun ", "deno run", "tsx ",
    "git ", "git.exe", "git-bash", "git checkout", "git pull", "git push",
    "git clone", "git status", "git add", "git commit",
    "jupyter", "ipython", "pytest", "nose ", "unittest", "mypy", "ruff ",
    "black ", "eslint", "prettier", "vitest", "jest", "playwright",
    "node ", "node.exe", "vite ", "next dev", "ng serve", "nest start",
    "make ", "cmake", "cargo ", "go run", "go build", "dotnet run",
    "dotnet build", "flutter run", "docker compose", "docker-compose",
    "terraform ", "kubectl ", "ansible-playbook", "sqlite3 ",
    "ssh ", "scp ", "curl http://localhost", "curl 127.0.0.1",
    "localhost:", "127.0.0.1:", "::1",
)

_LOCALHOST_DSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::", "127.0.0.0"}

#: Rules whose findings are frequently developer workflow noise on an analyst
#: laptop - the context engine demotes them one step when the evidence is
#: strongly developmental and the rule confidence is low.
DEV_SENSITIVE_RULES = (
    "suspicious_powershell", "python_execution", "screen_capture",
    "account_discovery", "filesystem_discovery", "git_activity",
    "cmd_script_execution", "archive_collection", "local_data_collection",
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ContextFacts:
    """Contextual facts extracted from a finding's evidence."""

    rule: str = ""
    processes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    _paths: dict[str, str] = field(default_factory=dict)
    command_lines: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    parent_names: list[str] = field(default_factory=list)
    reputation: dict[str, str] = field(default_factory=dict)
    dev_signals: list[str] = field(default_factory=list)
    project_paths: list[str] = field(default_factory=list)
    localhost_flows: int = 0
    evidence_text: str = ""
    #: Set by the alerting gate from the per-host behavioural baseline:
    #: True when the observed parent->child chain is normal for this host.
    chain_known: bool = False

    # ------------------------------------------------------------------
    # extraction helpers
    # ------------------------------------------------------------------
    def add_process(self, name: str | None, path: str | None = None) -> None:
        name = (name or "").strip()
        if not name:
            return
        if "\\" in name or "/" in name:
            path = path or name
            name = name.replace("\\", "/").rsplit("/", 1)[-1]
        if not name or name in self.processes:
            return
        self.processes.append(name)
        self._paths[name] = path or ""
        self.reputation[name.lower()] = self._reputation(name, path)
        if path:
            self._note_path(path)

    def add_command_line(self, cmdline: str | None) -> None:
        cmdline = (cmdline or "").strip()
        if not cmdline or cmdline in self.command_lines:
            return
        self.command_lines.append(cmdline[:512])
        self._scan_command_line(cmdline)

    def add_user(self, user: str | None) -> None:
        user = (user or "").strip()
        if user and user not in self.users and user not in ("-", "?"):
            self.users.append(user[:128])

    def add_ip(self, ip: str | None) -> None:
        ip = (ip or "").strip()
        if not ip or ip in self.ips:
            return
        if ip in _LOCALHOST_DSTS or ip.startswith("127."):
            self.localhost_flows += 1
            return
        self.ips.append(ip[:64])

    def _note_path(self, path: str) -> None:
        lower = path.lower()
        if any(marker in lower for marker in _DEV_PATH_MARKERS):
            self.project_paths.append(path)
        if "\\windows\\system32" in lower or "\\windows\\syswow64" in lower:
            pass  # system path, implied by reputation tier

    def _scan_command_line(self, cmdline: str) -> None:
        lower = cmdline.lower()
        for marker in _DEV_CMD_MARKERS:
            if marker in lower:
                self.dev_signals.append(marker.strip())
                break
        for m in _IP_RE.finditer(cmdline):
            self.add_ip(m.group(0))

    def _reputation(self, name: str, path: str | None = None) -> str:
        """Classify a process image into a reputation tier.

        tiers: ``system`` (Windows internals), ``trusted`` (known tooling),
        ``developer`` (dev runtimes / CLIs), ``unknown`` (everything else).
        """
        lower = name.lower()
        if lower in _KNOWN_SERVICE_PROCESSES:
            return "system"
        if lower in _KNOWN_TOOL_PROCESSES:
            return "trusted"
        if lower in _DEV_PROCESSES:
            return "developer"
        if path:
            pl = path.lower()
            if any(pl.startswith(m) or m in pl for m in _SYSTEM_ROOT_MARKERS):
                return "system"
            if any(marker in pl for marker in ("\\node_modules\\", "\\venv\\", "\\.venv\\")):
                return "developer"
        return "unknown"

    # ------------------------------------------------------------------
    # calibration
    # ------------------------------------------------------------------
    @property
    def git_activity(self) -> bool:
        """git.exe / git-* process or a git command-line marker."""
        if any(p.lower().startswith("git") for p in self.processes):
            return True
        return any(s in ("git ", "git.exe", "git-bash") for s in self.dev_signals)

    @property
    def vscode_activity(self) -> bool:
        """VS Code family: code.exe / code-insiders.exe or .vscode paths."""
        if any(p.lower() in ("code.exe", "code-insiders.exe") for p in self.processes):
            return True
        return any("vscode" in p.lower() for p in self.paths + self.project_paths)

    @property
    def python_venv(self) -> bool:
        """A virtual environment (venv/.venv) or Python dev runtime in paths."""
        lower_paths = [p.lower() for p in self.paths + self.project_paths]
        return any(
            m in p for p in lower_paths
            for m in ("\\venv\\", "\\.venv\\", "\\site-packages\\", "\\pycharmprojects\\")
        )

    @property
    def repository_paths(self) -> bool:
        """Processes launched from dev workspaces / source trees."""
        return bool(self.project_paths) or any(
            "\\src\\" in p.lower() or "\\repos\\" in p.lower() for p in self.paths
        )

    @property
    def signed_binaries(self) -> bool:
        """All observed processes are known system/trusted tooling (signed
        locations implied by the reputation tier) and none are unknown."""
        if not self.processes:
            return False
        tiers = {self.reputation.get(p.lower(), "unknown") for p in self.processes}
        return tiers <= {"system", "trusted"} and bool(tiers)

    def developer_workflow(self) -> dict:
        """Phase-2 developer-workflow detection: named signal set + verdict.

        Signals: git_activity, vscode_activity, python_venv,
        repository_paths, signed_binaries. Workflow is detected when at
        least two distinct signals agree.
        """
        signals = {
            "git_activity": self.git_activity,
            "vscode_activity": self.vscode_activity,
            "python_venv": self.python_venv,
            "repository_paths": self.repository_paths,
            "signed_binaries": self.signed_binaries,
        }
        present = [name for name, on in signals.items() if on]
        return {
            "detected": len(present) >= 2,
            "signals": present,
            "strength": len(present),
        }

    def _dev_parent_present(self) -> bool:
        """Any parent process is a known developer runtime / CLI.

        Deliberately ``_DEV_PROCESSES`` only - browsers and Office tools are
        "known" but not developmental, and chrome.exe -> powershell.exe is a
        real attack pattern that must never auto-demote.
        """
        return any(p.lower() in _DEV_PROCESSES for p in self.parent_names)

    @property
    def strong_dev_context(self) -> bool:
        """True when the evidence is clearly developer workflow, not attack.

        A trusted subject spawned by a dev runtime (python.exe ->
        powershell.exe -Command ...) is the signature analyst-laptop pattern;
        the parent chain alone establishes it as long as no unknown-reputation
        binary is part of the finding.
        """
        subjects_unknown = any(
            self.reputation.get(p.lower()) == "unknown" for p in self.processes
        )
        if self._dev_parent_present() and not subjects_unknown:
            return True
        dev_bits = 0
        if any(p for p in self.processes if self.reputation.get(p.lower()) == "developer"):
            dev_bits += 1
        if self.dev_signals:
            dev_bits += 1
        if self.project_paths:
            dev_bits += 1
        if self.localhost_flows:
            dev_bits += 1
        return dev_bits >= 2

    def risk_modifier(self) -> float:
        """0..1 multiplier for the hybrid risk score.

        Unknown-reputation processes keep risk at 1.0 (most suspicious);
        system/trusted tooling and strong developer context dampen it.
        """
        modifier = 1.0
        unknown = [p for p in self.processes if self.reputation.get(p.lower()) == "unknown"]
        dev = [p for p in self.processes if self.reputation.get(p.lower()) == "developer"]
        if unknown:
            modifier = min(modifier, 1.0)  # unknown reputation: no dampening
        elif dev and not unknown:
            modifier = min(modifier, 0.85)
        if dev and not unknown:
            modifier = min(modifier, 0.85)
        elif not unknown and not dev and self.processes:
            modifier = min(modifier, 0.9)  # only known/trusted/system processes
        if self.strong_dev_context:
            modifier = min(modifier, 0.75)
        if self.localhost_flows and not unknown:
            modifier = min(modifier, 0.9)
        return max(0.5, modifier)

    def severity_adjust(self, confidence: float | None = None) -> str | None:
        """One-step demotion for findings under strong developer context.

        The classic analyst-laptop false positive: a trusted, signed tool
        (powershell.exe) launched by developer tooling trips generic Sigma
        rules. Two structural gaps used to defeat this demotion:

        * Sigma findings arrive with ``rule == "sigma_rules"`` (never in
          ``DEV_SENSITIVE_RULES``), so they were never eligible;
        * the Sigma engine reports a hardcoded confidence of 0.8, so the
          low-confidence test never fired either.

        Sigma results therefore lean on the context verdict itself: when the
        surrounding facts are strongly developmental, the finding is demoted
        regardless of the canned confidence. Native rules keep the original
        low-confidence requirement.
        """
        eligible = self.rule in DEV_SENSITIVE_RULES or self.rule in ("", "sigma_rules")
        if not eligible:
            return None
        if not self.strong_dev_context:
            return None
        if self.rule in ("", "sigma_rules"):
            return "demote"
        conf = float(confidence or 0.5)
        if conf >= 0.8:
            return None
        return "demote"

    def notes(self) -> list[str]:
        """Human-readable context lines appended to the alert evidence."""
        out: list[str] = []
        for proc in self.processes:
            tier = self.reputation.get(proc.lower(), "unknown")
            path = self._paths.get(proc, "")
            display = f"process '{proc}' reputation={tier}"
            if path:
                display += f" ({path})"
            out.append(display)
        if self.project_paths:
            out.append("  project/workspace paths: " + "; ".join(self.project_paths[:3]))
        if self.dev_signals:
            out.append("  dev workflow signals: " + ", ".join(self.dev_signals[:4]))
        workflow = self.developer_workflow()
        if workflow["detected"]:
            out.append(
                "  developer workflow detected ("
                + ", ".join(workflow["signals"])
                + ")"
            )
        if self.localhost_flows:
            out.append("  localhost-only flow (never leaves the host)")
        if self.parent_names:
            out.append("  parent process(es): " + ", ".join(self.parent_names[:3]))
        if self.users:
            out.append("  user context: " + ", ".join(self.users[:3]))
        if self.strong_dev_context:
            out.append("  context verdict: strong developer-workflow context")
        elif not self.processes:
            out.append("  context verdict: no process evidence available")
        return out


# ---------------------------------------------------------------------------
# fact extraction from stored evidence
# ---------------------------------------------------------------------------

def _facts_of_event(event) -> dict:
    """The fact payload of a normalized event, best-effort."""
    raw = getattr(event, "raw_json", None)
    if isinstance(raw, dict) and isinstance(raw.get("facts"), dict):
        return raw["facts"]
    return {}


def _first_fact(facts: dict, *keys: str) -> str:
    """First non-empty fact value, case-insensitive on the key.

    Collectors emit mixed-case keys (``CommandLine``, ``NewProcessName``)
    while seeded/demo data uses lowercase - normalize once per call.
    """
    lowered = {str(k).lower(): v for k, v in facts.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, (str, dict, list)):
            return str(value)
    return ""


def assess_events(events: list, rule: str = "") -> ContextFacts:
    """Build context facts from linked normalized events."""
    facts = ContextFacts(rule=rule)
    for event in events or []:
        payload = _facts_of_event(event)
        image = _first_fact(payload, "image_path", "image", "process_path",
                            "process_image", "new_process_name", "source_image",
                            "newprocessname", "newprocess", "imagepath")
        name = _first_fact(payload, "process_name", "image_name", "new_process_name",
                           "newprocessname", "processname")
        if not name and image:
            name = image.replace("\\", "/").rsplit("/", 1)[-1]
        if name:
            facts.add_process(name, image)
        parent = _first_fact(payload, "parent_image", "parent_process",
                             "parent_process_name", "parent_name",
                             "parentimage", "parentprocessname",
                             "parentprocess")
        if parent and parent not in facts.parent_names:
            facts.parent_names.append(parent.replace("\\", "/").rsplit("/", 1)[-1][:128])
        cmdline = _first_fact(payload, "command_line", "cmdline", "command",
                              "full_command_line", "commandline",
                              "fullcommandline", "processcommandline")
        if cmdline:
            facts.add_command_line(cmdline)
        user = _first_fact(payload, "user", "subject_user_name", "account",
                           "target_user_name", "subjectusername",
                           "accountname", "targetusername", "username")
        if user:
            facts.add_user(user)
        else:
            facts.add_user(getattr(event, "user", "") or "")
        host = getattr(event, "host", "") or ""
        if host and host not in facts.hosts:
            facts.hosts.append(host[:128])
        for ip_key in ("dst_ip", "destination_ip", "src_ip", "source_ip",
                       "remote_ip", "local_ip"):
            ip = _first_fact(payload, ip_key)
            if ip:
                facts.add_ip(ip)
    return facts


def assess_text(evidence: str, rule: str = "") -> ContextFacts:
    """Best-effort context from evidence text alone (rules without links)."""
    facts = ContextFacts(rule=rule, evidence_text=(evidence or "")[:4000])
    text = facts.evidence_text
    for m in re.finditer(r"process '([^']+)'", text, re.IGNORECASE):
        facts.add_process(m.group(1))
    for m in re.finditer(r"(?:command|cmdline|command_line) '([^']+)'", text, re.IGNORECASE):
        facts.add_command_line(m.group(1))
    for m in _IP_RE.finditer(text):
        facts.add_ip(m.group(0))
    for m in re.finditer(r"(?:user|account) '([^']+)'", text, re.IGNORECASE):
        facts.add_user(m.group(1))
    # Parent chain from composed evidence ("parent process(es): a.exe b.exe")
    # - parents are prime dev-context evidence and were invisible to the
    # text-only fallback path.
    for m in re.finditer(
        r"parent process(?:es)?[:\s]+((?:[A-Za-z0-9_.\\/-]+\.exe[,\s]*)+)",
        text,
        re.IGNORECASE,
    ):
        for tok in m.group(1).replace(",", " ").split():
            tok = tok.strip().strip("'\"")
            if tok.lower().endswith(".exe") and tok not in facts.parent_names:
                facts.parent_names.append(tok)
    for m in re.finditer(r"([A-Za-z]:[\\/][^'\"\r\n ]+\.exe)", text, re.IGNORECASE):
        path = m.group(1)
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        facts.add_process(name, path)
    return facts


def assess_for_alert(session, alert, events: list | None = None) -> ContextFacts:
    """Full context assessment for one alert (DB session for fallback)."""
    rule = getattr(alert, "rule", "") or ""
    if events is None:
        from backend.database.models import AlertEventLink

        links = session.scalars(
            select(AlertEventLink).where(AlertEventLink.alert_id == alert.id).limit(50)
        ).all()
        events = [link.event for link in links if getattr(link, "event", None)]
    facts = assess_events(events, rule=rule)
    if not facts.processes:
        text = getattr(alert, "evidence", "") or ""
        if text:
            facts = assess_text(text, rule=rule)
    return facts
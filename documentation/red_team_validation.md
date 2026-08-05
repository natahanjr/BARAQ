# SentinelSOC — Red-Team Validation

**Document:** Independent Detection Validation Against Realistic Attacks
**Version:** 1.0
**Date:** 2026-08-05

---

## 1. Objective

The evaluation framework (see `security_evaluation_report.md`) measures the
detection engine against deterministic fixture scenarios. This document
records a complementary validation: realistic attacks executed against the
live host, with detections captured honestly — including false negatives.

Red-team validation is the external face of the thesis claim: *the platform
detects real Windows attack behavior, not just its own simulator data.*

---

## 2. Methodology

| Phase | Action |
|---|---|
| 1. Baseline | Run `/api/system/collect`; record `security_score` and open-alert count before each test |
| 2. Attack | Execute a single realistic attack technique against the host |
| 3. Observe | Wait 1 collection cycle (15 s); capture alerts via `/api/alerts` |
| 4. Record | For each attack: detected (alert + MITRE mapping), detection time, false negative? |
| 5. Cleanup | Reverse the change (delete scheduled task / restore account / kill process) |

All tests run in the isolated hold-out evaluation harness when `use_real_baseline=True`;
the manual procedure below is for the live dashboard validation.

---

## 3. Attack Scenarios

### 3.1 Brute Force (T1110)

```powershell
# Real failed-logon burst against a local account
$user = "administrator"
1..12 | ForEach-Object {
  net use "\\localhost\IPC$" /user:$user "WrongPassword$_" 2>$null
}
```

**Expected:** `Brute Force Attack` alert (rule + MITRE T1110).

### 3.2 Suspicious PowerShell (T1059.001)

```powershell
# Encoded, hidden download-execute pattern
$payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Process calc.exe'))
powershell.exe -NoP -NonI -W Hidden -EncodedCommand $payload
```

**Expected:** `Suspicious PowerShell Activity` alert (T1059.001).

### 3.3 Persistence via Scheduled Task (T1547)

```powershell
schtasks /create /tn "SentinelTestPersistence" /tr "C:\Users\Public\svchost_test.exe" /sc onlogon /ru SYSTEM
# ... then remove: schtasks /delete /tn "SentinelTestPersistence" /f
```

**Expected:** `Persistence Mechanism Installed` alert (T1547).

### 3.4 Port Scan / Network Recon (T1046)

```powershell
$target = "192.168.1.1"
1..30 | ForEach-Object { Test-NetConnection $target -Port $_ -WarningAction SilentlyContinue }
```

**Expected:** `Network Service Discovery (Port Scan)` alert (T1046).

### 3.5 Privilege Escalation (T1068)

```powershell
# Requires admin; creates a local user and adds it to Administrators
net user SentinelTestPass /add
net localgroup Administrators SentinelTestPass /add
# ... then remove: net localgroup Administrators SentinelTestPass /delete; net user SentinelTestPass /delete
```

**Expected:** `Suspicious Privilege Escalation` alert (T1068).

### 3.6 File Staging (T1074)

```powershell
# Compress user documents into an archive in a hidden temp location
Compress-Archive -Path $env:USERPROFILE\Documents\* -DestinationPath "$env:TEMP\backup_data.zip" -Force
```

**Expected:** `Data Staging` alert (T1074) — collection phase of the kill chain.

---

## 4. Results Table

| Scenario | MITRE | Detected | Detection Time | False Negative |
|---|---|---|---|---|
| Brute force burst (12 logons) | T1110 | ✅ | ≤ 1 cycle | — |
| Encoded PowerShell | T1059.001 | ✅ | ≤ 1 cycle | — |
| Scheduled-task persistence | T1547 | ✅ | ≤ 1 cycle | — |
| Port scan (30 ports) | T1046 | ✅ | ≤ 1 cycle | — |
| Admin account creation | T1068 | ✅ | ≤ 1 cycle | — |
| Data staging archive | T1074 | ✅ | ≤ 1 cycle | — |

### 4.1 Documented False Negatives

Honesty over polish — known detection gaps observed during validation:

1. **Single-shot payloads with no command line evidence.** PowerShell 4104
   events without `-EncodedCommand`/download indicators and no script block
   text are scored `Low` risk and do not alert (false negative by design).
2. **In-memory-only attacks.** Mimikatz-style LSASS access (T1003) is not
   detectable without Sysmon Event 10 (ProcessAccess); Sysmon must be
   installed and the event 10 stream enabled.
3. **Obfuscated-but-legitimate automation.** Heavy normal automation
   (pip install loops, build scripts) can trigger the PowerShell rule —
   a documented false-positive class that the analyst triage workflow handles.
4. **Uninstalled Sysmon.** Process tree depth (T1059/T1218 parent-child
   anomalies) is only available when the Sysmon channel is present.

---

## 5. Interpreting the Results

- **Rule layer:** all six live scenarios were detected within one collection
  cycle; alerts carry MITRE mappings and remediation guidance.
- **Hybrid layer:** when the ML detector has been trained (`POST /api/system/ml/train`),
  alert risk becomes `0.6 × rule + 0.4 × ML anomaly`, visible in `detection_method`.
- **Repeated trigger escalation:** re-running the same scenario against an
  open alert increments `trigger_count`; after the configured threshold the
  severity escalates one level (see `ALERT_ESCALATE_AFTER` in `backend/config.py`).

---

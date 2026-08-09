# SentinelSOC — Sysmon Wiring & Configuration Guide

**Document:** Installing, configuring and verifying the Sysmon telemetry
channel that the platform's advanced rules consume.
**Version:** 1.0
**Date:** 2026-08-08

---

## 1. Why Sysmon

Sysmon (System Monitor, from Microsoft Sysinternals) exposes telemetry the
native Windows Security log does not provide. The platform's collector
(`backend/collectors/sysmon.py`) reads the live Sysmon channel and maps the
high-value event types onto the native pipeline shapes:

| Sysmon event | Meaning | Pipeline source | Rules that gain signal |
|---|---|---|---|
| 1 — Process Create | image + command line + parent tree | `process` | masquerading, hidden artifacts, lolbin_execution, suspicious_powershell |
| 3 — Network Connect | source/dest IP + port + protocol | `network` | network_recon, c2_beacon, exfiltration_volume, lateral_movement |
| 10 — Process Access | who accessed what process (LSASS!) | `eventlog` E10 | credential_access (T1003.001) |
| 11 — File Create | new files + hashes | `eventlog` E11 | data_staging, malware drop |
| 13 — Registry Event | value set/delete (Run keys) | `eventlog` E13 | registry_run_key (T1547.001) |
| 23 — File Delete | file removals | `eventlog` E23 | log/artifact cleanup |

Without Sysmon the platform still works — the collector degrades gracefully
and returns no records — but the rules above fall back to weaker signals
(see `documentation/red_team_validation.md` §4.2 documented false negatives).

---

## 2. Install Sysmon

```powershell
# Download from Sysinternals (or winget)
winget install Microsoft.Sysinternals.Sysmon --accept-package-agreements

# Or manually:
#   curl -LO https://download.sysinternals.com/files/Sysmon.zip
#   Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon
```

## 3. Configure and install the driver

The collector reads whatever the channel carries, so the **config file must
enable** the event types you want. Minimal config that covers the mapping
table above (save as `sysmon-config.xml`):

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process create (Event 1) - everything -->
    <ProcessCreate onmatch="exclude"/>

    <!-- Network connect (Event 3) - everything -->
    <NetworkConnect onmatch="exclude"/>

    <!-- Process access (Event 10) - ONLY lsass and protected processes:
         keepless noise is high, so filter to credential-access targets -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
      <GrantedAccess condition="contains">0x1000</GrantedAccess>
    </ProcessAccess>

    <!-- File create (Event 11) - archive/binary drops under user dirs -->
    <FileCreate onmatch="exclude"/>

    <!-- Registry value set (Event 13) - autostart keys -->
    <RegistryEvent onmatch="exclude"/>
    <RegistryEvent onmatch="include">
      <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      <TargetObject condition="begin with">HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
    </RegistryEvent>

    <!-- File delete (Event 23) - everything -->
    <FileDelete onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
```

Install with the config (elevated PowerShell):

```powershell
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml
```

Verify the driver is loaded and the channel exists:

```powershell
Get-Service Sysmon            # should be Running
wevtutil gl "Microsoft-Windows-Sysmon/Operational" | Select-String "enabled|retention"
# enabled = true means events are being recorded
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Select TimeCreated, Id
```

## 4. Wiring into SentinelSOC

No code change is needed — the collector is registered in
`backend/collectors/__init__.py::CollectorManager` and reads the channel on
every collection cycle:

- Channel override (if your Sysmon logs to a renamed/extra channel):
  `SENTINEL_SYSMON_CHANNELS=Microsoft-Windows-Sysmon/Operational` (comma-separated list).
- The collector requires `pywin32` on the host. Without it the collector
  stays disabled and the pipeline logs `pywin32 unavailable; skipping Sysmon read`.
- Event 1/3 records flow straight into the process/network rules; E10/E11/
  E13/E23 are normalized as `eventlog` events and consumed by the
  credential-access, registry-run-key and data-staging rules.

## 5. Verification

1. Start the platform: `uvicorn backend.main:app` (or `python -m backend.main`).
2. Watch the collection log — a line like
   `Read N raw records from Microsoft-Windows-Sysmon/Operational` confirms reads.
3. Generate a test signal, e.g. a Run-key write:
   ```powershell
   New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SentinelTest -Value "calc.exe"
   # then remove:
   Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SentinelTest
   ```
   Expect a `Registry Run Key Persistence` alert (T1547.001).
4. LSASS access test (credential-access rule, requires admin):
   ```powershell
   # use any tool that opens lsass.exe with PROCESS_VM_READ - e.g. procdump64
   C:\Tools\procdump64.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
   # cleanup: Remove-Item C:\Temp\lsass.dmp
   ```
   Expect a `Credential Access` alert (T1003.001) on Event 10 targeting lsass.exe.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pywin32 unavailable` log line | pywin32 not installed | `pip install pywin32` and restart the agent |
| Channel exists but 0 events | Config filtered everything or channel disabled | check `wevtutil gl`, reinstall driver with a permissive config |
| No Event 10 alerts | ProcessAccess filter misses the access pattern | verify `GrantedAccess` value; widen to `condition="is"` on `lsass.exe` |
| No Event 1/3 data | `ProcessCreate`/`NetworkConnect` section missing | add the sections to the config and `-u C:\path\config.xml` |
| `Access is denied` reading channel | Collector runs without admin | run the agent elevated (Sysmon channel reads require it) |

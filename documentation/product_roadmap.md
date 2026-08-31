# BARAQ — Product Roadmap

**Assessment: 8.3/10** — Strong concept, unusually large scope. The gap is not features, it's product cohesion.

> "A lot of powerful cybersecurity components assembled into one platform"
> → **"One coherent SOC experience where every component naturally connects to the next."**

---

## The Core Workflow

Every part of BARAQ should connect to this:

```
TELEMETRY
    ↓
DETECTION
    ↓
ALERT
    ↓
INVESTIGATION
    ↓
INCIDENT
    ↓
RESPONSE
```

---

## V0.9 — Stabilize

**No major new features. Everything currently implemented must work reliably.**

### Core Platform
- [ ] Clean startup/shutdown
- [ ] Reliable database initialization
- [ ] Reliable migrations
- [ ] Proper configuration validation
- [ ] Consistent error handling
- [ ] Centralized logging
- [ ] Health-check endpoint
- [ ] Service health dashboard
- [ ] Graceful failure/recovery

### Authentication
- [ ] Login
- [ ] Logout
- [ ] Session handling
- [ ] RBAC
- [ ] MFA
- [ ] Password reset
- [ ] Account management
- [ ] Session expiration

### Agent
- [ ] Install agent
- [ ] Register agent
- [ ] Agent authentication
- [ ] Telemetry transmission
- [ ] Agent heartbeat
- [ ] Agent status
- [ ] Agent disconnect handling
- [ ] Agent upgrade/version information

### Detection
- [ ] Rule loading
- [ ] Rule validation
- [ ] Rule execution
- [ ] Sigma execution
- [ ] Correlation
- [ ] Alert generation
- [ ] Duplicate handling
- [ ] Severity calculation

### ML
- [ ] Model loading
- [ ] Model versioning
- [ ] Prediction
- [ ] Anomaly score
- [ ] Model failure handling
- [ ] Model status

**Deliverable: BARAQ runs reliably from clean installation to first alert.**

---

## V1.0 — SOC Core

**Make this workflow excellent: Telemetry → Detection → Alert → Investigation → Incident**

### Alert Queue
- [ ] Filtering (severity, status, host, user, technique)
- [ ] Sorting (time, severity, risk, confidence)
- [ ] Severity display
- [ ] Status workflow
- [ ] Timestamps
- [ ] Affected host
- [ ] Affected user
- [ ] Detection source
- [ ] MITRE technique
- [ ] Confidence score
- [ ] Risk score

An analyst should understand an alert in seconds.

### Alert Detail — One of BARAQ's Strongest Screens
```
Alert
│
├── What happened?
├── Why was it detected?
├── Who?
├── What host?
├── When?
├── Evidence
├── Related events
├── Related alerts
├── MITRE ATT&CK
├── Threat intelligence
├── Risk
└── Recommended actions
```

### Investigation
- [ ] Entity relationships (User→Host, Host→Process, Process→Network, Process→File)
- [ ] Entity timeline
- [ ] Related alerts
- [ ] Attack-chain visualization
- [ ] Investigation bookmarks
- [ ] Analyst notes

**Deliverable: An analyst can open BARAQ, see an alert, understand what happened, and know what to do next.**

---

## V1.1 — Intelligence

**MITRE + Threat Intelligence + Entity Risk + Correlation**

### Detection Engine
```
                  ┌── Native Rules
Telemetry ────────┼── Sigma
                  ├── Correlation
                  └── ML
                       ↓
                 Detection Result
                       ↓
                 Risk Engine
                       ↓
                     Alert
```

- [ ] Detection versioning
- [ ] Rule enable/disable
- [ ] Rule testing
- [ ] Rule validation
- [ ] Detection performance metrics
- [ ] Detection hit statistics
- [ ] False-positive tracking
- [ ] Detection coverage
- [ ] Rule search
- [ ] Rule categories
- [ ] Rule import/export

### Risk Engine
```
                    Risk
                     │
       ┌─────────────┼─────────────┐
       ↓             ↓             ↓
Alert Severity   ML Score    Entity Risk
       │             │             │
       └─────────────┼─────────────┘
                     ↓
                Risk Score
```

Calculate risk for: Alert, User, Host, IP, Process, Incident

Answer: **"What is the most dangerous thing happening in my environment right now?"**

### Threat Intelligence
- [ ] Contextual investigation: Host→Process→Connection→IP→Threat Intel→Campaign/IOC
- [ ] Not just "IP: 1.2.3.4, Malicious: Yes" — connect to the actual event

### MITRE ATT&CK
- [ ] Every alert mapped to technique
- [ ] Technique → detection coverage view
- [ ] Gap analysis: which techniques have no detection?

---

## V1.2 — AI

**AI deeply integrated into investigations, not a chatbot in the corner.**

For every alert, the AI should be able to:

- [ ] **Explain** — Why did this alert trigger?
- [ ] **Investigate** — What related activity happened?
- [ ] **Summarize** — Give me the attack story
- [ ] **Assess** — How serious is this?
- [ ] **Recommend** — What should the analyst investigate next?
- [ ] **Report** — Generate the incident report

AI should have access to BARAQ's actual evidence and context.

Not: *"Here's a generic explanation of Kerberoasting."*

But: *"User X generated these events on Host Y. The sequence matches these behaviors..."*

---

## V1.3 — Response (SOAR)

**Investigation → Decision → SOAR**

### Response Actions
- [ ] Isolate host
- [ ] Terminate process
- [ ] Disable account
- [ ] Block IP
- [ ] Quarantine file
- [ ] Collect additional evidence

### Safety Controls
- [ ] Dry-run mode
- [ ] Approval workflow
- [ ] Action history
- [ ] Rollback where possible
- [ ] Response permissions
- [ ] Audit trail

---

## V1.4 — Scale

**What happens when BARAQ receives 100 events/sec? 1,000? 10,000?**

- [ ] Large telemetry ingestion test
- [ ] High alert volume test
- [ ] Database query optimization
- [ ] API latency monitoring
- [ ] WebSocket/stream optimization
- [ ] Memory profiling
- [ ] CPU profiling
- [ ] Background task optimization
- [ ] Log retention
- [ ] Data cleanup
- [ ] Pagination everywhere
- [ ] Search optimization

---

## V2.0 — Full BARAQ

```
             ┌───────────────┐
             │    ENDPOINTS  │
             └───────┬───────┘
                     ↓
             ┌───────────────┐
             │   TELEMETRY   │
             └───────┬───────┘
                     ↓
        ┌────────────────────────┐
        │     BARAQ ENGINE       │
        │                        │
        │ Rules │ Sigma │ ML     │
        │ Correlation │ Risk     │
        └───────────┬────────────┘
                    ↓
              ┌───────────┐
              │   ALERTS  │
              └─────┬─────┘
                    ↓
           ┌────────────────┐
           │ INVESTIGATION  │
           │                │
           │ Graph          │
           │ Timeline       │
           │ MITRE          │
           │ Threat Intel   │
           │ AI             │
           └───────┬────────┘
                   ↓
             ┌───────────┐
             │ INCIDENT  │
             └─────┬─────┘
                   ↓
             ┌───────────┐
             │   SOAR    │
             └───────────┘
```

---

## What To Work On Tomorrow

**Don't add another feature.**

Pick one attack. Run it through BARAQ:

```
Endpoint telemetry → Detection → Alert → Investigation → MITRE → Risk → AI explanation → Response
```

Make that entire experience flawless.

Then repeat for 5–10 important attack scenarios.

That's how you turn a large codebase into a coherent security product.

---

## Product Navigation (Target)

```
BARAQ

Overview
Alerts
Incidents
Investigate
Threat Hunting
Assets
Detections
Intelligence
Automation
Analytics
Administration
```

Don't expose every internal subsystem as a top-level menu item.
The analyst thinks in terms of **work**, not software architecture.

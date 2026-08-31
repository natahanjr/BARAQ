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

## V0.9 — Stabilize ✅

**No major new features. Everything currently implemented must work reliably.**

### Core Platform
- [x] Clean startup/shutdown
- [x] Reliable database initialization
- [x] Reliable migrations
- [x] Proper configuration validation
- [x] Consistent error handling
- [x] Centralized logging
- [x] Health-check endpoint
- [x] Service health dashboard
- [x] Graceful failure/recovery

### Authentication
- [x] Login
- [x] Logout
- [x] Session handling
- [x] RBAC
- [x] MFA
- [x] Password reset
- [x] Account management
- [x] Session expiration

### Agent
- [x] Install agent
- [x] Register agent
- [x] Agent authentication
- [x] Telemetry transmission
- [x] Agent heartbeat
- [x] Agent status
- [x] Agent disconnect handling
- [x] Agent upgrade/version information

### Detection
- [x] Rule loading
- [x] Rule validation
- [x] Rule execution
- [x] Sigma execution
- [x] Correlation
- [x] Alert generation
- [x] Duplicate handling
- [x] Severity calculation

### ML
- [x] Model loading
- [x] Model versioning
- [x] Prediction
- [x] Anomaly score
- [x] Model failure handling
- [x] Model status

**Deliverable: BARAQ runs reliably from clean installation to first alert.**

---

## V1.0 — SOC Core ✅

**Make this workflow excellent: Telemetry → Detection → Alert → Investigation → Incident**

### Alert Queue
- [x] Filtering (severity, status, host, user, technique)
- [x] Sorting (time, severity, risk, confidence)
- [x] Severity display
- [x] Status workflow
- [x] Timestamps
- [x] Affected host
- [x] Affected user
- [x] Detection source
- [x] MITRE technique
- [x] Confidence score
- [x] Risk score

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
- [x] Entity relationships (User→Host, Host→Process, Process→Network, Process→File)
- [x] Entity timeline
- [x] Related alerts
- [x] Attack-chain visualization
- [x] Investigation bookmarks
- [x] Analyst notes

**Deliverable: An analyst can open BARAQ, see an alert, understand what happened, and know what to do next.**

---

## V1.1 — Intelligence ✅

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

- [x] Detection versioning
- [x] Rule enable/disable
- [x] Rule testing
- [x] Rule validation
- [x] Detection performance metrics
- [x] Detection hit statistics
- [x] False-positive tracking
- [x] Detection coverage
- [x] Rule search
- [x] Rule categories
- [x] Rule import/export

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
- [x] Contextual investigation: Host→Process→Connection→IP→Threat Intel→Campaign/IOC
- [x] Not just "IP: 1.2.3.4, Malicious: Yes" — connect to the actual event

### MITRE ATT&CK
- [x] Every alert mapped to technique
- [x] Technique → detection coverage view
- [x] Gap analysis: which techniques have no detection?

---

## V1.2 — AI ✅

**AI deeply integrated into investigations, not a chatbot in the corner.**

For every alert, the AI should be able to:

- [x] **Explain** — Why did this alert trigger?
- [x] **Investigate** — What related activity happened?
- [x] **Summarize** — Give me the attack story
- [x] **Assess** — How serious is this?
- [x] **Recommend** — What should the analyst investigate next?
- [x] **Report** — Generate the incident report

AI should have access to BARAQ's actual evidence and context.

Not: *"Here's a generic explanation of Kerberoasting."*

But: *"User X generated these events on Host Y. The sequence matches these behaviors..."*

---

## V1.3 — Response (SOAR) ✅

**Investigation → Decision → SOAR**

### Response Actions
- [x] Isolate host
- [x] Terminate process
- [x] Disable account
- [x] Block IP
- [x] Quarantine file
- [x] Collect additional evidence

### Safety Controls
- [x] Dry-run mode
- [x] Approval workflow
- [x] Action history
- [x] Rollback where possible
- [x] Response permissions
- [x] Audit trail

---

## V1.4 — Scale ✅

**What happens when BARAQ receives 100 events/sec? 1,000? 10,000?**

- [x] Large telemetry ingestion test
- [x] High alert volume test
- [x] Database query optimization
- [x] API latency monitoring
- [x] WebSocket/stream optimization
- [x] Memory profiling
- [x] CPU profiling
- [x] Background task optimization
- [x] Log retention
- [x] Data cleanup
- [x] Pagination everywhere
- [x] Search optimization

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

---

## Future Work Roadmap

### V2.1 — Multi-Tenancy & Enterprise
- [ ] Multi-tenant isolation (data, users, alerts per tenant)
- [ ] Tenant provisioning & lifecycle management
- [ ] Cross-tenant threat intelligence sharing
- [ ] Enterprise SSO (SAML 2.0, OIDC)
- [ ] Hierarchical RBAC (Tenant Admin → SOC Lead → Analyst → Read-Only)
- [ ] Tenant-level dashboards & reporting
- [ ] Data residency controls

### V2.2 — Advanced Threat Hunting
- [ ] Hypothesis-driven threat hunting workflows
- [ ] Saved hunt templates
- [ ] Query builder for custom telemetry searches
- [ ] Hunt result annotation & sharing
- [ ] IOC pivot hunting (follow an indicator across all entities)
- [ ] Behavioral baseline deviation alerts
- [ ] Threat hunt coverage reporting

### V2.3 — Compliance & Reporting
- [ ] Compliance frameworks (PCI-DSS, HIPAA, SOC 2, ISO 27001)
- [ ] Automated compliance evidence collection
- [ ] Compliance gap analysis
- [ ] Executive summary reports
- [ ] Scheduled report delivery (email, webhook)
- [ ] Audit log export
- [ ] Risk posture dashboard

### V2.4 — Integration Ecosystem
- [ ] SIEM forwarding (CEF, LEEF, Syslog)
- [ ] Ticketing integrations (Jira, ServiceNow, PagerDuty)
- [ ] SOAR platform connectors (Cortex XSOAR, Splunk SOAR)
- [ ] Cloud provider integrations (AWS CloudTrail, Azure AD, GCP Audit)
- [ ] Endpoint platform connectors (CrowdStrike, SentinelOne, Defender)
- [ ] Webhook & custom integration framework
- [ ] API key management & rate limiting per integration

### V2.5 — Fleet Management & Agent Intelligence
- [ ] Agent deployment automation (GPO, SCCM, Intune)
- [ ] Agent configuration profiles
- [ ] Agent health monitoring & alerting
- [ ] Remote agent commands
- [ ] Agent log collection & forwarding
- [ ] Agent performance metrics
- [ ] Automatic agent updates

### V2.6 — Advanced ML & Analytics
- [ ] User & Entity Behavior Analytics (UEBA)
- [ ] Lateral movement detection
- [ ] Data exfiltration detection
- [ ] Insider threat detection
- [ ] Attack path prediction
- [ ] Blast radius analysis
- [ ] ML model marketplace (share detection models)

### V2.7 — Security Orchestration
- [ ] Visual playbook builder
- [ ] Playbook versioning & rollback
- [ ] Custom action development framework
- [ ] Response action marketplace
- [ ] Incident workflow automation
- [ ] SLA enforcement automation
- [ ] Cross-platform response orchestration


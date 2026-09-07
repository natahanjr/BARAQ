# BARAQ User Guide

## Getting Started

### Login

1. Open your browser to `http://localhost:5173`
2. Enter your username and password
3. Click "Sign In"

### First-Time Setup

1. Change your admin password
2. Configure MFA (recommended)
3. Set up your organization settings

## Dashboard

The dashboard provides an overview of your security posture.

### Key Metrics

- **Total Alerts:** Current alert count by severity
- **Open Incidents:** Active incidents requiring attention
- **Endpoints:** Monitored endpoints status
- **Risk Score:** Overall risk assessment

### Quick Actions

- View critical alerts
- Create new incident
- Search for indicators
- Run automation playbook

## Alert Management

### Viewing Alerts

1. Navigate to **Alerts** in the sidebar
2. Use filters to narrow results:
   - Severity (Critical, High, Medium, Low)
   - Status (New, Investigating, Resolved)
   - Time range

### Investigating Alerts

1. Click on an alert to view details
2. Review the alert timeline
3. Check related alerts and incidents
4. Add notes and observations

### Taking Action

1. **Change Status:** Mark as investigating or resolved
2. **Assign:** Assign to team member
3. **Create Incident:** Link to existing or new incident
4. **Run Playbook:** Execute automated response

### Alert Verdicts

Submit your verdict to improve detection accuracy:

- **True Positive:** Confirmed threat
- **False Positive:** Benign activity
- **Suspicious:** Requires further investigation

## Incident Response

### Creating Incidents

1. Go to **Incidents**
2. Click **+ New Incident**
3. Provide:
   - Title and description
   - Severity level
   - Related alerts
   - Assigned analyst

### Managing Incidents

1. Update status as investigation progresses
2. Add notes and evidence
3. Link additional alerts
4. Mark as resolved when complete

### Incident Timeline

View chronological events:
- Alert creation
- Status changes
- Notes and actions
- Related events

## Investigation

### Search

Use the search bar to find:
- IP addresses
- Hostnames
- User accounts
- File hashes
- Process names

### Threat Intelligence

Look up indicators to check if they're known threats:
1. Enter indicator in search
2. View threat intelligence results
3. Check reputation and history

### Process Tree

Analyze process relationships:
- Parent-child relationships
- Command line arguments
- File operations
- Network connections

## Automation

### Playbooks

Pre-defined response procedures:

1. **View Playbooks:** See all available playbooks
2. **Run Playbook:** Execute on specific alert/incident
3. **Monitor Execution:** Track playbook progress

### Creating Playbooks

1. Go to **Automation**
2. Click **+ New Playbook**
3. Define:
   - Name and description
   - Trigger conditions
   - Actions to execute

### Available Actions

- Block IP address
- Kill malicious process
- Quarantine file
- Isolate endpoint
- Disable user account
- Create incident
- Send notification

## Reports

### Generating Reports

1. Go to **Reports**
2. Select report type:
   - Alert summary
   - Incident report
   - Threat analysis
   - Compliance report

3. Configure parameters:
   - Date range
   - Severity filters
   - Export format

### Downloading Reports

- PDF format for printing
- CSV format for data analysis
- JSON format for integration

## Settings

### Profile Settings

1. Change password
2. Configure MFA
3. Set notification preferences

### Organization Settings

1. User management
2. Role assignments
3. API key management

### System Settings

1. Feature flags
2. Integration configuration
3. Retention policies

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` | Command palette |
| `Ctrl+/` | Search |
| `Esc` | Close dialog |

## Notifications

### Real-time Alerts

- Browser notifications for critical alerts
- Sound alerts for urgent items
- Toast notifications for actions

### Notification Settings

Configure in **Settings > Notifications**:
- Alert severity threshold
- Notification method (browser, email)
- Quiet hours

## Tips and Best Practices

### Alert Investigation

1. Start with critical alerts first
2. Use filters to focus on relevant alerts
3. Add notes to document your investigation
4. Submit verdicts to improve detection

### Incident Management

1. Keep incidents updated with latest status
2. Link all related alerts
3. Document all actions taken
4. Close incidents only when fully resolved

### Automation

1. Test playbooks before production use
2. Monitor playbook execution
3. Review and update playbooks regularly

### Security

1. Use strong, unique passwords
2. Enable MFA when available
3. Log out when finished
4. Report suspicious activity

## Getting Help

### In-App Help

- Click the help icon (?) in the top right
- Use the command palette (`Ctrl+K`) to search
- Check the FAQ section

### Support

- Email: support@baraq.example.com
- Documentation: See docs/ directory
- GitHub: https://github.com/natahanjr/BARAQ

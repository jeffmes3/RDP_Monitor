Enterprise RDP Monitor
Enterprise-grade PowerShell monitoring framework for detecting RDP activity, privilege changes, persistence behavior, and security control tampering across Windows endpoints and Domain Controllers.
Designed for:
SOC monitoring
Compliance auditing
Threat hunting
Enterprise security validation
Community security research
##################
 Overview
Enterprise RDP Monitor analyzes Windows Security Event Logs against a structured monitoring guide and produces:
Executive Summary (color-coded console output)
Full structured TXT report
Machine-readable CSV report
Detailed event-level CSV + TXT logs
#################
Coverage scoring
Compliance scoring
Risk rating
Category-based telemetry breakdown
#################
It supports:
Standalone endpoints
Domain-joined systems
Domain Controllers
Enterprise rollout via Scheduled Tasks or GPO
#################
 What It Detects
The tool aligns monitoring to four core security domains.

 Authentication
Event ID	Description
4624	Successful RDP logon (LogonType 10 only)
4625	Failed logon
4740	Account lockout
4825	Denied Remote Desktop access

Use case:
Brute-force detection
Credential abuse
RDP lateral movement

 Privilege
Event ID	Description
4720	User account created
4722	User account enabled
4724	Password reset attempt
4727	Global group created
4732	User added to privileged group

Use case:
Privilege escalation monitoring
Identity abuse detection

 Persistence
Event ID	Description
4688	Process creation
4700	Scheduled task enabled
4702	Scheduled task updated
4657	Registry modification
4663	Object access
#################
Use case:
Persistence detection
Suspicious process activity
Scheduled task abuse
#################
🛡 Defense Evasion
Event ID	Description
1102	Audit log cleared
4719	Audit policy changed
4739	Domain policy changed
4946	Firewall rule added
4948	Firewall rule deleted

Use case:
Logging tampering detection
Policy weakening detection
Firewall manipulation
#################
 Executive Summary Output
After execution, the tool produces a structured enterprise summary:

================ ENTERPRISE SUMMARY =================
Total Events Processed : 2665
Alerts Triggered       : 0
Coverage               : 10.5% (2/19 guide events observed)
Key Telemetry Score    : 20%
Compliance Score       : 14/100
Risk Rating            : Medium
=====================================================


It then prints a full category breakdown with:
FOUND / MISSING per event
Event count
Category activity status
Risk is color-coded:
🔴 High / Critical
🟡 Medium
🟢 Low

📈 Scoring Model
Coverage %
How many of the defined guide events were observed.
Key Telemetry Score
Weighted critical events:
4625
4719
4688
1102
4946

Compliance Score
Weighted blend of coverage + telemetry quality.

Risk Rating
Derived from compliance posture + active alerts.

 Features
24-hour default lookback window
SOC or Compliance profile mode
Brute-force detection (5 failed logons in 2 minutes)
Alert cooldown logic
Structured CSV export
Structured TXT export
Detailed event-level logging
Schedule monitor (Daily / Weekly / Monthly)
GPO Hardening / Audit checklist
StrictMode-safe
Enterprise menu-driven interface
Runs on endpoints + domain controllers
#################
 Menu Options
When executed:

================ Enterprise RDP Monitor ================
1. Run monitor now (Reports + Full Executive Summary)
2. Schedule monitor (Daily/Weekly/Monthly)
3. GPO Hardening / Audit
4. Exit
#################
📂 Report Output

Reports are saved to:
C:\ProgramData\RDPMonitor\


Generated files:
RDP_Summary_<timestamp>.txt
RDP_Summary_<timestamp>.csv
RDP_Detail_<timestamp>.txt
RDP_Detail_<timestamp>.csv

🗓 Scheduling

Supports:
Daily execution
Weekly execution
Monthly execution
Runs as SYSTEM with highest privileges.

🏢 Enterprise Deployment
Recommended approach:

Place script in:
C:\ProgramData\RDPMonitor\

Deploy via GPO Scheduled Task
Enable Advanced Audit Policy
Ensure Security Log retention is sufficient
Optionally forward to SIEM

🔍 GPO Hardening Audit Mode
Option 3 prints:
Current audit policy configuration
High-level recommended settings
Telemetry validation checklist

Designed for:
Compliance audits
Security posture reviews
Hardening validation

🔒 Requirements

Windows PowerShell 5.1
Run as Administrator
Security Event Logging enabled
Advanced Audit Policy recommended

🛠 Usage
Run interactively:
.\rdp_monitor_enterprise.ps1

Run directly:

.\rdp_monitor_enterprise.ps1 -Mode Run

🎯 Use Cases

Blue Team monitoring
RDP abuse detection
Internal threat hunting
Compliance validation
Domain controller security review
Endpoint telemetry validation
Security baseline scoring

⚠ Disclaimer
This tool reads Windows Security Event Logs.
Detection quality depends on audit policy configuration.

It does not replace SIEM, EDR, or XDR.
It complements them by validating telemetry and coverage.

📌 Roadmap
Planned enhancements:
Central collection mode
Windows service version
JSON export mode
Email alerting
SIEM forwarding integration
Baseline comparison between runs
Trend analysis dashboard

🤝 Contributing

Pull requests are welcome.
Improvements around scoring logic, reporting structure, and detection coverage are encouraged.

📜 License
MIT License

⭐ If This Project Helps You
Consider starring the repository.

Enterprise RDP monitoring is still widely under-validated.
Better telemetry validation improves security posture for everyone.


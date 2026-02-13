# RDP_Monitor
# Enterprise RDP Monitor v2.2.0

# Enterprise RDP Monitor | Coverage Scoring + Compliance Engine

Enterprise-grade PowerShell monitoring tool for RDP activity, privilege changes, persistence detection, and security policy tampering across Windows endpoints and Domain Controllers.

---

## 🔍 What This Tool Does

This release introduces a structured enterprise monitoring engine aligned to a full event coverage guide across four domains:

- Authentication
- Privilege Escalation
- Persistence
- Defense Evasion

Instead of just detecting RDP brute-force attempts, this tool evaluates monitoring coverage and compliance posture.

---

## 🚨 Events Covered

### Authentication
- 4624 – Successful RDP logon (LogonType 10)
- 4625 – Failed logon
- 4740 – Account lockout
- 4825 – Denied RDP access

### Privilege
- 4720 / 4722 – Account creation / enablement
- 4724 – Password reset
- 4727 / 4732 – Group membership changes

### Persistence
- 4688 – Process creation
- 4700 / 4702 – Scheduled task changes
- 4657 / 4663 – Registry & object access

### Defense Evasion
- 1102 – Audit log cleared
- 4719 – Audit policy changed
- 4739 – Domain policy changed
- 4946 / 4948 – Firewall rule changes

---

## 📊 Executive Summary Output

The tool produces a structured enterprise summary:

#####

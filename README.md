# Enterprise RDP Monitor

Enterprise RDP Monitor is a PowerShell-based security telemetry
validation and RDP monitoring framework designed to evaluate
authentication activity, privilege manipulation, persistence behaviors,
and defense evasion across Windows endpoints and Domain Controllers.

This tool provides structured telemetry coverage validation, executive
risk scoring, compliance scoring, and full reporting in TXT and CSV
formats.

------------------------------------------------------------------------

# 🔎 Purpose

Many environments collect Windows Security logs but do not validate:

-   Whether critical security events are enabled
-   Whether telemetry coverage is complete
-   Whether brute-force detection is active
-   Whether audit policy tampering is observable
-   Whether security posture can be quantified

Enterprise RDP Monitor provides measurable telemetry visibility and
compliance scoring.

------------------------------------------------------------------------

# 🏗 Architecture Overview

The engine consists of five core layers:

1.  Event Acquisition Layer\
2.  Event Classification Layer\
3.  Detection & Alert Engine\
4.  Telemetry Coverage & Compliance Scoring Engine\
5.  Reporting & Output Engine

------------------------------------------------------------------------

# 1️⃣ Event Acquisition

Uses:

    Get-WinEvent -FilterHashtable

Filtered by: - Security Log - Defined monitoring guide event IDs -
Configurable lookback window (default: 1440 minutes / 24 hours)

Supports two profiles:

-   Compliance Mode → Reduces high-volume noise events\
-   SOC Mode → Enables full telemetry visibility

------------------------------------------------------------------------

# 2️⃣ Event Classification

Events are grouped into structured security domains:

## 🔐 Authentication

-   4624 (RDP LogonType 10 only)
-   4625
-   4740
-   4825

## 🔑 Privilege

-   4720
-   4722
-   4724
-   4727
-   4732

## 🧬 Persistence

-   4688
-   4700
-   4702
-   4657
-   4663

## 🛡 Defense Evasion

-   1102
-   4719
-   4739
-   4946
-   4948

------------------------------------------------------------------------

# 3️⃣ Detection Engine

Built-in brute-force detection:

-   Event ID 4625
-   5 failed attempts
-   2 minute window (configurable)
-   Cooldown control (default 10 minutes)

Prevents alert flooding while maintaining SOC visibility.

------------------------------------------------------------------------

# 4️⃣ Scoring Model

## Coverage %

Coverage = (Observed Guide Events / Total Guide Events) × 100

## Key Telemetry Score

Critical weighted events:

-   4625
-   4719
-   4688
-   1102
-   4946

## Compliance Score

Compliance = (Coverage × 0.6) + (Key Telemetry Score × 0.4)

## Risk Rating

-   High → Active alerts detected
-   Medium → Compliance below threshold
-   Low → Healthy telemetry posture

Console output is color-coded.

------------------------------------------------------------------------

# 📊 Executive Output

Example:

================ ENTERPRISE SUMMARY =================\
Total Events Processed : 2665\
Alerts Triggered : 0\
Coverage : 10.5%\
Key Telemetry Score : 20%\
Compliance Score : 14/100\
Risk Rating : Medium\
=====================================================

Followed by full category breakdown with FOUND / MISSING status.

------------------------------------------------------------------------

# 📁 Report Output

Reports saved to:

    C:\ProgramData\RDPMonitor\

Generated files:

-   RDP_Summary\_`<timestamp>`{=html}.txt
-   RDP_Summary\_`<timestamp>`{=html}.csv
-   RDP_Detail\_`<timestamp>`{=html}.txt
-   RDP_Detail\_`<timestamp>`{=html}.csv

------------------------------------------------------------------------

# 🗓 Scheduling

Supports:

-   Daily
-   Weekly
-   Monthly

Runs under SYSTEM with highest privileges.

------------------------------------------------------------------------

# 🏢 GPO Hardening / Audit Mode

Runs:

    auditpol /get /category:*

Validates audit configuration and provides recommended hardening
checklist.

------------------------------------------------------------------------

# 🛡 Security Design

-   StrictMode enforced
-   No external dependencies
-   No network communication
-   Safe XML parsing
-   Controlled file writes

------------------------------------------------------------------------

# 🎯 Use Cases

-   RDP abuse detection
-   Security telemetry validation
-   Domain controller auditing
-   Compliance assessment
-   Threat hunting
-   Enterprise monitoring baselines

------------------------------------------------------------------------

# 📌 Requirements

-   Windows PowerShell 5.1
-   Administrator privileges
-   Security auditing enabled

------------------------------------------------------------------------

# 📜 License

MIT License

------------------------------------------------------------------------

If this project improves your telemetry visibility or compliance
posture, consider starring the repository.

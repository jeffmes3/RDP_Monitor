#Requires -Version 5.1
#Requires -RunAsAdministrator
#Designed by- Jeffrey Misquita
param(
    [ValidateSet("Menu","Run","Schedule","Audit","Exit")]
    [string]$Mode = "Menu",

    [ValidateSet("Compliance","SOC")]
    [string]$Profile = "Compliance",

    [int]$LookbackMinutes = 1440,
    [int]$FailThresholdCount = 5,
    [int]$FailWindowMinutes = 2,
    [int]$AlertCooldownMinutes = 10,

    [string]$OutputDir = "C:\ProgramData\RDPMonitor"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =====================================================
# EVENT GUIDE
# =====================================================

$Guide = @(
    @{ Id=4624; Category="Authentication"; Description="Successful logon (RDP LogonType 10 only)" },
    @{ Id=4625; Category="Authentication"; Description="Failed logon" },
    @{ Id=4740; Category="Authentication"; Description="Account lockout" },
    @{ Id=4825; Category="Authentication"; Description="Denied Remote Desktop access" },

    @{ Id=4720; Category="Privilege"; Description="User account created" },
    @{ Id=4722; Category="Privilege"; Description="User account enabled" },
    @{ Id=4724; Category="Privilege"; Description="Password reset attempt" },
    @{ Id=4727; Category="Privilege"; Description="Security-enabled global group created" },
    @{ Id=4732; Category="Privilege"; Description="User added to privileged group" },

    @{ Id=4688; Category="Persistence"; Description="Process creation" },
    @{ Id=4700; Category="Persistence"; Description="Scheduled task enabled" },
    @{ Id=4702; Category="Persistence"; Description="Scheduled task updated" },
    @{ Id=4657; Category="Persistence"; Description="Registry value modified" },
    @{ Id=4663; Category="Persistence"; Description="Object access" },

    @{ Id=1102; Category="Defense"; Description="Audit log cleared" },
    @{ Id=4719; Category="Defense"; Description="Audit policy changed" },
    @{ Id=4739; Category="Defense"; Description="Domain policy changed" },
    @{ Id=4946; Category="Defense"; Description="Firewall rule added" },
    @{ Id=4948; Category="Defense"; Description="Firewall rule deleted" }
)

$AllCategories = @("Authentication","Privilege","Persistence","Defense")
$AllEventIds = @($Guide | ForEach-Object { [int]$_.Id })

# =====================================================
# SAFE XML PARSER
# =====================================================

function Get-EventDataMap {
    param($evt)
    $map = @{}
    try {
        $xml = [xml]$evt.ToXml()
        if ($xml -and $xml.Event -and $xml.Event.EventData -and $xml.Event.EventData.Data) {
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $map[$d.Name] = $d.InnerText }
            }
        }
    } catch {}
    return $map
}

# =====================================================
# EXECUTIVE REPORT PRINTER (FULL STRUCTURED OUTPUT)
# =====================================================

function Write-ExecutiveReport {
    param(
        [int]$TotalProcessed,
        [int]$Alerts,
        [double]$Coverage,
        [int]$FoundCount,
        [int]$TotalGuide,
        [int]$KeyScore,
        [int]$Compliance,
        [string]$Risk,
        [hashtable]$Found,
        [hashtable]$CategoryTotals
    )

    Write-Host ""
    Write-Host "================ ENTERPRISE SUMMARY =================" -ForegroundColor Cyan
    Write-Host ("Total Events Processed : {0}" -f $TotalProcessed)

    if ($Alerts -gt 0) {
        Write-Host ("Alerts Triggered       : {0}" -f $Alerts) -ForegroundColor Red
    } else {
        Write-Host ("Alerts Triggered       : {0}" -f $Alerts) -ForegroundColor Green
    }

    $covLine = ("Coverage               : {0}% ({1}/{2} guide events observed)" -f $Coverage, $FoundCount, $TotalGuide)
    if ($Coverage -lt 30) { Write-Host $covLine -ForegroundColor Red }
    elseif ($Coverage -lt 70) { Write-Host $covLine -ForegroundColor Yellow }
    else { Write-Host $covLine -ForegroundColor Green }

    $keyLine = ("Key Telemetry Score    : {0}%" -f $KeyScore)
    if ($KeyScore -lt 40) { Write-Host $keyLine -ForegroundColor Red }
    elseif ($KeyScore -lt 75) { Write-Host $keyLine -ForegroundColor Yellow }
    else { Write-Host $keyLine -ForegroundColor Green }

    $compLine = ("Compliance Score       : {0}/100" -f $Compliance)
    if ($Compliance -lt 40) { Write-Host $compLine -ForegroundColor Red }
    elseif ($Compliance -lt 75) { Write-Host $compLine -ForegroundColor Yellow }
    else { Write-Host $compLine -ForegroundColor Green }

    switch ($Risk) {
        "Critical" { Write-Host ("Risk Rating            : {0}" -f $Risk) -ForegroundColor Red }
        "High"     { Write-Host ("Risk Rating            : {0}" -f $Risk) -ForegroundColor Red }
        "Medium"   { Write-Host ("Risk Rating            : {0}" -f $Risk) -ForegroundColor Yellow }
        "Low"      { Write-Host ("Risk Rating            : {0}" -f $Risk) -ForegroundColor Green }
        default    { Write-Host ("Risk Rating            : {0}" -f $Risk) }
    }

    Write-Host "====================================================="
    Write-Host ""

    foreach ($cat in $AllCategories) {

        Write-Host ("Category: {0} | Total Events: {1}" -f $cat, $CategoryTotals[$cat])

        $catEvents = $Guide | Where-Object { $_.Category -eq $cat }
        foreach ($evt in $catEvents) {
            $eid = [int]$evt.Id
            if ($Found.ContainsKey($eid)) {
                Write-Host ("  EID {0} : FOUND (Count={1}) - {2}" -f $eid, $Found[$eid], $evt.Description)
            } else {
                Write-Host ("  EID {0} : MISSING (Count=0) - {1}" -f $eid, $evt.Description)
            }
        }

        if ($CategoryTotals[$cat] -eq 0) {
            Write-Host "  Category status: No activity observed in this window."
        } else {
            Write-Host "  Category status: Activity observed."
        }

        Write-Host ""
    }
}

# =====================================================
# MONITOR
# =====================================================

function Invoke-Monitor {

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $Stamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $SummaryTxt = Join-Path $OutputDir "RDP_Summary_$Stamp.txt"
    $SummaryCsv = Join-Path $OutputDir "RDP_Summary_$Stamp.csv"
    $DetailCsv  = Join-Path $OutputDir "RDP_Detail_$Stamp.csv"
    $DetailTxt  = Join-Path $OutputDir "RDP_Detail_$Stamp.txt"

    "Time,EventID,Category" | Out-File -LiteralPath $DetailCsv -Encoding ascii
    "Enterprise RDP Monitor Detail Report - $Stamp" | Out-File -LiteralPath $DetailTxt -Encoding ascii
    "Section,Metric,Value" | Out-File -LiteralPath $SummaryCsv -Encoding ascii

    $StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)

    # Profile handling: Compliance excludes 4663 (noise), SOC includes it
    $MonitorIds = $AllEventIds
    if ($Profile -eq "Compliance") {
        $MonitorIds = $MonitorIds | Where-Object { $_ -ne 4663 }
    }

    $Events = @()
    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=$MonitorIds
            StartTime=$StartTime
        } -ErrorAction SilentlyContinue
    } catch {
        $Events = @()
    }

    if (-not $Events) { $Events = @() }

    $Found = @{}
    $CategoryTotals = @{}
    foreach ($cat in $AllCategories) { $CategoryTotals[$cat] = 0 }

    $TotalProcessed = 0
    $Alerts = 0

    # brute-force detection
    $FailWindowSeconds = $FailWindowMinutes * 60
    $FailedAttempts = @{}
    $Cooldown = @{}

    foreach ($e in $Events) {

        $id = [int]$e.Id
        $data = Get-EventDataMap $e

        # Filter 4624 to RDP only
        if ($id -eq 4624 -and $data["LogonType"] -ne "10") { continue }

        $TotalProcessed++

        if (-not $Found.ContainsKey($id)) { $Found[$id]=0 }
        $Found[$id]++

        $cat = ($Guide | Where-Object { $_.Id -eq $id }).Category
        $CategoryTotals[$cat]++

        # detail logs
        ("{0},{1},{2}" -f $e.TimeCreated, $id, $cat) | Add-Content -LiteralPath $DetailCsv -Encoding ascii
        ("{0} | {1} | {2}" -f $e.TimeCreated, $id, $cat) | Add-Content -LiteralPath $DetailTxt -Encoding ascii

        # brute-force alerts: 5 failed logons in 2 minutes with cooldown
        if ($id -eq 4625) {
            $user = $data["TargetUserName"]
            $ip = $data["IpAddress"]
            $key = "{0}|{1}" -f $user, $ip

            if (-not $FailedAttempts.ContainsKey($key)) { $FailedAttempts[$key] = @() }
            $FailedAttempts[$key] += $e.TimeCreated

            $cut = (Get-Date).AddSeconds(-$FailWindowSeconds)
            $FailedAttempts[$key] = $FailedAttempts[$key] | Where-Object { $_ -gt $cut }

            $coolOk = $true
            if ($Cooldown.ContainsKey($key)) {
                $coolOk = ($Cooldown[$key] -lt (Get-Date).AddMinutes(-$AlertCooldownMinutes))
            }

            if ($FailedAttempts[$key].Count -ge $FailThresholdCount -and $coolOk) {
                $Alerts++
                $Cooldown[$key] = Get-Date
            }
        }
    }

    # =========================
    # SCORING
    # =========================
    $foundCount = @($Found.Keys).Count
    $totalGuide = $AllEventIds.Count
    $coverage = 0
    if ($totalGuide -gt 0) {
        $coverage = [Math]::Round(($foundCount/$totalGuide)*100,1)
    }

    $KeyTelemetry = @(4625,4719,4688,1102,4946)
    $keyFound = @($KeyTelemetry | Where-Object { $Found.ContainsKey($_) }).Count
    $keyScore = [Math]::Round(($keyFound/$KeyTelemetry.Count)*100,0)

    $compliance = [Math]::Round(($coverage*0.6)+($keyScore*0.4),0)

    # risk logic (kept simple; you can expand later)
    $risk = "Low"
    if ($Alerts -gt 0) { $risk = "High" }
    elseif ($compliance -lt 50) { $risk = "Medium" }
    else { $risk = "Low" }

    # =========================
    # WRITE FILE REPORTS FIRST
    # =========================

@"
================ ENTERPRISE SUMMARY =================
Total Events Processed : $TotalProcessed
Alerts Triggered       : $Alerts
Coverage               : $coverage% ($foundCount/$totalGuide guide events observed)
Key Telemetry Score    : $keyScore%
Compliance Score       : $compliance/100
Risk Rating            : $risk
=====================================================
"@ | Out-File -LiteralPath $SummaryTxt -Encoding ascii

    "Summary,TotalEventsProcessed,$TotalProcessed" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
    "Summary,AlertsTriggered,$Alerts" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
    "Summary,CoveragePercent,$coverage" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
    "Summary,KeyTelemetryScore,$keyScore" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
    "Summary,ComplianceScore,$compliance" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
    "Summary,RiskRating,$risk" | Add-Content -LiteralPath $SummaryCsv -Encoding ascii

    foreach ($cat in $AllCategories) {

        Add-Content -LiteralPath $SummaryTxt -Value ""
        Add-Content -LiteralPath $SummaryTxt -Value ("Category: {0} | Total Events: {1}" -f $cat, $CategoryTotals[$cat])
        ("Category,{0},{1}" -f $cat, $CategoryTotals[$cat]) | Add-Content -LiteralPath $SummaryCsv -Encoding ascii

        $catEvents = $Guide | Where-Object { $_.Category -eq $cat }
        foreach ($evt in $catEvents) {
            $eid = [int]$evt.Id
            if ($Found.ContainsKey($eid)) {
                $line = ("  EID {0} : FOUND (Count={1}) - {2}" -f $eid, $Found[$eid], $evt.Description)
                ("Event,{0},FOUND,{1}" -f $eid, $Found[$eid]) | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
            } else {
                $line = ("  EID {0} : MISSING (Count=0) - {1}" -f $eid, $evt.Description)
                ("Event,{0},MISSING,0" -f $eid) | Add-Content -LiteralPath $SummaryCsv -Encoding ascii
            }
            Add-Content -LiteralPath $SummaryTxt -Value $line
        }

        if ($CategoryTotals[$cat] -eq 0) {
            Add-Content -LiteralPath $SummaryTxt -Value "  Category status: No activity observed in this window."
        } else {
            Add-Content -LiteralPath $SummaryTxt -Value "  Category status: Activity observed."
        }

        Add-Content -LiteralPath $SummaryTxt -Value ""
    }

    # =========================
    # THEN PRINT FULL EXECUTIVE REPORT ON SCREEN
    # =========================
    Write-Host ("Reports saved to {0}" -f $OutputDir) -ForegroundColor Cyan
    Write-Host ("Summary TXT: {0}" -f $SummaryTxt)
    Write-Host ("Summary CSV: {0}" -f $SummaryCsv)
    Write-Host ("Detail  TXT: {0}" -f $DetailTxt)
    Write-Host ("Detail  CSV: {0}" -f $DetailCsv)

    Write-ExecutiveReport `
        -TotalProcessed $TotalProcessed `
        -Alerts $Alerts `
        -Coverage $coverage `
        -FoundCount $foundCount `
        -TotalGuide $totalGuide `
        -KeyScore $keyScore `
        -Compliance $compliance `
        -Risk $risk `
        -Found $Found `
        -CategoryTotals $CategoryTotals
}

# =====================================================
# SCHEDULE
# =====================================================

function Invoke-Schedule {

    Write-Host ""
    Write-Host "1. Daily"
    Write-Host "2. Weekly"
    Write-Host "3. Monthly"
    $choice = Read-Host "Select schedule type"

    $ScriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
        throw "Unable to resolve script path. Run the script from a saved .ps1 file (not pasted)."
    }

    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Mode Run -Profile $Profile -LookbackMinutes $LookbackMinutes -FailThresholdCount $FailThresholdCount -FailWindowMinutes $FailWindowMinutes -AlertCooldownMinutes $AlertCooldownMinutes -OutputDir `"$OutputDir`""

    switch($choice){
        1{
            $time=Read-Host "Enter time (HH:MM)"
            $Trigger=New-ScheduledTaskTrigger -Daily -At $time
        }
        2{
            $time=Read-Host "Enter time (HH:MM)"
            $day=Read-Host "Enter weekday (Monday..Sunday)"
            $Trigger=New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
        }
        3{
            $time=Read-Host "Enter time (HH:MM)"
            $dom=[int](Read-Host "Enter day of month (1-31)")
            $Trigger=New-ScheduledTaskTrigger -Monthly -DaysOfMonth $dom -At $time
        }
        default { return }
    }

    Register-ScheduledTask -TaskName "Enterprise-RDP-Monitor" `
        -Action $Action -Trigger $Trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null

    Write-Host "Scheduled Task Created/Updated: Enterprise-RDP-Monitor" -ForegroundColor Green
}

# =====================================================
# GPO HARDENING / AUDIT
# =====================================================

function Invoke-Audit {

    Write-Host ""
    Write-Host "===== GPO HARDENING / AUDIT =====" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Audit Policy (auditpol /get /category:*):" -ForegroundColor Cyan
    try { auditpol /get /category:* } catch { Write-Host "auditpol failed." -ForegroundColor Yellow }

    Write-Host ""
    Write-Host "Recommended checklist (high-level):"
    Write-Host " - Enable Advanced Audit Policy (Computer Config -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy)"
    Write-Host " - Enable Logon/Logoff auditing (success/failure) for 4624/4625"
    Write-Host " - Enable Account Management auditing (4720/4722/4724/4727/4732)"
    Write-Host " - Enable Policy Change auditing (4719/4739)"
    Write-Host " - Enable Process Creation (4688) + command line logging"
    Write-Host " - Ensure Security log size/retention is adequate"
    Write-Host ""
}

# =====================================================
# MENU
# =====================================================

if ($Mode -eq "Menu") {
    Write-Host ""
    Write-Host "================ Enterprise RDP Monitor ================"
    Write-Host "1. Run monitor now (Reports + Full Executive Summary)"
    Write-Host "2. Schedule monitor (Daily/Weekly/Monthly)"
    Write-Host "3. GPO Hardening / Audit"
    Write-Host "4. Exit"
    $sel = Read-Host "Select option (1-4)"

    switch($sel){
        1{ Invoke-Monitor }
        2{ Invoke-Schedule }
        3{ Invoke-Audit }
        default{ return }
    }
}
elseif ($Mode -eq "Run"){ Invoke-Monitor }
elseif ($Mode -eq "Schedule"){ Invoke-Schedule }
elseif ($Mode -eq "Audit"){ Invoke-Audit }


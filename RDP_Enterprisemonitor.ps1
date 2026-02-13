#Requires -Version 5.1
#Requires -RunAsAdministrator

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
# GUIDE DEFINITION
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
$AllEventIds = $Guide | ForEach-Object { $_.Id }

# =====================================================
# SAFE XML PARSER
# =====================================================

function Get-EventDataMap {
    param($evt)
    $map = @{}
    try {
        $xml = [xml]$evt.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $map[$d.Name] = $d.InnerText }
        }
    } catch {}
    return $map
}

# =====================================================
# ENTERPRISE RUN
# =====================================================

function Invoke-Monitor {

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)

    $MonitorIds = $AllEventIds
    if ($Profile -eq "Compliance") {
        $MonitorIds = $MonitorIds | Where-Object { $_ -ne 4663 }
    }

    $Events = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=$MonitorIds
        StartTime=$StartTime
    } -ErrorAction SilentlyContinue

    if (-not $Events) { $Events = @() }

    $Found = @{}
    $CategoryTotals = @{}
    foreach ($cat in $AllCategories) { $CategoryTotals[$cat]=0 }

    $TotalProcessed = 0
    $Alerts = 0

    $FailWindowSeconds = $FailWindowMinutes * 60
    $FailedAttempts = @{}
    $Cooldown = @{}

    foreach ($e in $Events) {

        $id = $e.Id
        $data = Get-EventDataMap $e

        if ($id -eq 4624 -and $data["LogonType"] -ne "10") { continue }

        $TotalProcessed++

        if (!$Found.ContainsKey($id)) { $Found[$id]=0 }
        $Found[$id]++

        $cat = ($Guide | Where-Object { $_.Id -eq $id }).Category
        $CategoryTotals[$cat]++

        if ($id -eq 4625) {

            $user = $data["TargetUserName"]
            $ip = $data["IpAddress"]
            $key = "$user|$ip"

            if (!$FailedAttempts.ContainsKey($key)) { $FailedAttempts[$key]=@() }

            $FailedAttempts[$key]+=$e.TimeCreated
            $cut=(Get-Date).AddSeconds(-$FailWindowSeconds)
            $FailedAttempts[$key]=$FailedAttempts[$key]|Where-Object{$_ -gt $cut}

            if ($FailedAttempts[$key].Count -ge $FailThresholdCount) {
                if (!$Cooldown.ContainsKey($key) -or
                    $Cooldown[$key] -lt (Get-Date).AddMinutes(-$AlertCooldownMinutes)) {
                    $Alerts++
                    $Cooldown[$key]=Get-Date
                }
            }
        }
    }

    # =========================
    # SCORING (SAFE COUNT FIX)
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

    if ($Alerts -gt 0) { $risk="High" }
    elseif ($compliance -lt 50) { $risk="Medium" }
    else { $risk="Low" }

    # =========================
    # EXECUTIVE SUMMARY OUTPUT
    # =========================

    Write-Host ""
    Write-Host "================ ENTERPRISE SUMMARY ================="
    Write-Host "Total Events Processed : $TotalProcessed"
    Write-Host "Alerts Triggered       : $Alerts"
    Write-Host "Coverage               : $coverage% ($foundCount/$totalGuide guide events observed)"
    Write-Host "Key Telemetry Score    : $keyScore%"
    Write-Host "Compliance Score       : $compliance/100"
    Write-Host "Risk Rating            : $risk"
    Write-Host "====================================================="
    Write-Host ""

    foreach ($cat in $AllCategories) {

        Write-Host "Category: $cat | Total Events: $($CategoryTotals[$cat])"

        $catEvents = $Guide | Where-Object { $_.Category -eq $cat }

        foreach ($evt in $catEvents) {

            if ($Found.ContainsKey($evt.Id)) {
                Write-Host "  EID $($evt.Id) : FOUND (Count=$($Found[$evt.Id])) - $($evt.Description)"
            } else {
                Write-Host "  EID $($evt.Id) : MISSING (Count=0) - $($evt.Description)"
            }
        }

        if ($CategoryTotals[$cat] -eq 0) {
            Write-Host "  Category status: No activity observed in this window."
        } else {
            Write-Host "  Category status: Activity observed."
        }

        Write-Host ""
    }

    Write-Host "====================================================="
    Write-Host ""
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
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Mode Run"

    switch($choice){
        1{
            $time=Read-Host "Enter time (HH:MM)"
            $Trigger=New-ScheduledTaskTrigger -Daily -At $time
        }
        2{
            $time=Read-Host "Enter time (HH:MM)"
            $day=Read-Host "Enter weekday"
            $Trigger=New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
        }
        3{
            $time=Read-Host "Enter time (HH:MM)"
            $day=Read-Host "Enter day of month"
            $Trigger=New-ScheduledTaskTrigger -Monthly -DaysOfMonth $day -At $time
        }
        default{ return }
    }

    Register-ScheduledTask -TaskName "Enterprise-RDP-Monitor" `
        -Action $Action -Trigger $Trigger -User "SYSTEM" -RunLevel Highest -Force

    Write-Host "Scheduled Task Created."
}

# =====================================================
# AUDIT
# =====================================================

function Invoke-Audit {
    Write-Host ""
    Write-Host "===== GPO HARDENING / AUDIT ====="
    auditpol /get /category:* 
    Write-Host ""
}

# =====================================================
# MENU
# =====================================================

if ($Mode -eq "Menu") {

    Write-Host ""
    Write-Host "================ Enterprise RDP Monitor ================"
    Write-Host "1. Run monitor now (Executive Summary)"
    Write-Host "2. Schedule monitor"
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

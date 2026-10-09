# Test Script for Logon Events BOF
#
# This script helps test the logon-events BOF by:
# 1. Showing existing Event ID 4624 events from the Security log
# 2. (Optionally) Generating test logon events
#
# Usage: Run as Administrator
#   .\test-logon-events.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Logon Events BOF Test Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] This script requires Administrator privileges to access the Security event log." -ForegroundColor Red
    Write-Host "[!] Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Running as Administrator" -ForegroundColor Green
Write-Host ""

# Function to display recent logon events
function Show-RecentLogonEvents {
    param(
        [int]$Days = 7,
        [int]$MaxEvents = 20
    )

    Write-Host "[*] Querying Security event log for Event ID 4624 (last $Days days, max $MaxEvents events)..." -ForegroundColor Yellow
    Write-Host ""

    $startTime = (Get-Date).AddDays(-$Days)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop

        Write-Host "[+] Found $($events.Count) events" -ForegroundColor Green
        Write-Host ""

        foreach ($event in $events | Select-Object -First 10) {
            $xml = [xml]$event.ToXml()
            $eventData = $xml.Event.EventData.Data

            $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $targetDomain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
            $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $ipAddress = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            $authPackage = ($eventData | Where-Object { $_.Name -eq 'AuthenticationPackageName' }).'#text'

            $logonTypeStr = switch ($logonType) {
                "2" { "Interactive" }
                "3" { "Network" }
                "4" { "Batch" }
                "5" { "Service" }
                "7" { "Unlock" }
                "8" { "NetworkCleartext" }
                "9" { "NewCredentials" }
                "10" { "RemoteInteractive" }
                "11" { "CachedInteractive" }
                default { "Unknown($logonType)" }
            }

            Write-Host "[$logonTypeStr] $($event.TimeCreated.ToLocalTime())" -ForegroundColor Cyan
            Write-Host "  User:    $targetDomain\$targetUser" -ForegroundColor White
            if ($ipAddress -and $ipAddress -ne "-") {
                Write-Host "  From:    $ipAddress" -ForegroundColor White
            }
            Write-Host "  Auth:    $authPackage" -ForegroundColor White
            Write-Host ""
        }

        if ($events.Count -gt 10) {
            Write-Host "[...] Showing first 10 of $($events.Count) events" -ForegroundColor DarkGray
            Write-Host ""
        }

    } catch {
        Write-Host "[!] Error querying event log: $_" -ForegroundColor Red
        Write-Host ""
    }
}

# Function to show statistics
function Show-LogonStatistics {
    param([int]$Days = 7)

    Write-Host "[*] Logon Statistics (last $Days days)..." -ForegroundColor Yellow

    $startTime = (Get-Date).AddDays(-$Days)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624
            StartTime = $startTime
        } -MaxEvents 5000 -ErrorAction Stop

        $logonTypes = @{}
        $users = @{}
        $authMethods = @{}

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $eventData = $xml.Event.EventData.Data

            $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $authPackage = ($eventData | Where-Object { $_.Name -eq 'AuthenticationPackageName' }).'#text'

            # Count logon types
            if ($logonTypes.ContainsKey($logonType)) {
                $logonTypes[$logonType]++
            } else {
                $logonTypes[$logonType] = 1
            }

            # Count unique users
            if ($users.ContainsKey($targetUser)) {
                $users[$targetUser]++
            } else {
                $users[$targetUser] = 1
            }

            # Count auth methods
            if ($authMethods.ContainsKey($authPackage)) {
                $authMethods[$authPackage]++
            } else {
                $authMethods[$authPackage] = 1
            }
        }

        Write-Host ""
        Write-Host "Total Events: $($events.Count)" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "Logon Types:" -ForegroundColor Cyan
        $logonTypes.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            $typeStr = switch ($_.Key) {
                "2" { "Interactive" }
                "3" { "Network" }
                "10" { "RemoteInteractive" }
                default { "Type $($_.Key)" }
            }
            Write-Host "  $($typeStr.PadRight(20)) : $($_.Value)" -ForegroundColor White
        }

        Write-Host ""
        Write-Host "Authentication Methods:" -ForegroundColor Cyan
        $authMethods.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            Write-Host "  $($_.Key.PadRight(20)) : $($_.Value)" -ForegroundColor White
        }

        Write-Host ""
        Write-Host "Top 10 Users by Logon Count:" -ForegroundColor Cyan
        $users.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Key.PadRight(30)) : $($_.Value)" -ForegroundColor White
        }

    } catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }

    Write-Host ""
}

# Main menu
Write-Host "Choose an option:" -ForegroundColor Yellow
Write-Host "  1) Show recent logon events (last 7 days)" -ForegroundColor White
Write-Host "  2) Show logon statistics" -ForegroundColor White
Write-Host "  3) Both" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice (1-3)"

switch ($choice) {
    "1" {
        Show-RecentLogonEvents -Days 7 -MaxEvents 20
    }
    "2" {
        Show-LogonStatistics -Days 7
    }
    "3" {
        Show-RecentLogonEvents -Days 7 -MaxEvents 20
        Show-LogonStatistics -Days 7
    }
    default {
        Write-Host "[!] Invalid choice" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Script Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now test the logon-events BOF with:" -ForegroundColor Yellow
Write-Host "  logon-events" -ForegroundColor White
Write-Host "  logon-events --days 1" -ForegroundColor White
Write-Host "  logon-events --days 7 --max-events 100" -ForegroundColor White
Write-Host ""

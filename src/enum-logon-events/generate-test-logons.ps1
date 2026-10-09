# Generate Test Logon Events
#
# This script generates various types of logon events (Event ID 4624)
# to test the logon-events BOF's ability to detect and categorize them.
#
# Usage: Run as Administrator
#   .\generate-test-logons.ps1
#
# IMPORTANT: This script is for testing in authorized lab environments only.

#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Generate Test Logon Events" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] This script generates various logon events for testing" -ForegroundColor Yellow
Write-Host "[!] Use in authorized lab environments only" -ForegroundColor Yellow
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] This script requires Administrator privileges." -ForegroundColor Red
    exit 1
}

# Function to generate Network Logon (Type 3)
function Generate-NetworkLogon {
    Write-Host "[*] Generating Network Logon (Type 3)..." -ForegroundColor Cyan

    # Access a local share (generates network logon)
    $null = Get-ChildItem "\\localhost\C$" -ErrorAction SilentlyContinue

    Write-Host "[+] Network logon generated (accessed \\localhost\C$)" -ForegroundColor Green
}

# Function to generate Batch Logon (Type 4) via Scheduled Task
function Generate-BatchLogon {
    param(
        [string]$Username = $env:USERNAME,
        [string]$TaskName = "BOFTestTask_$(Get-Random)"
    )

    Write-Host "[*] Generating Batch Logon (Type 4) via Scheduled Task..." -ForegroundColor Cyan
    Write-Host "    This requires credentials for: $Username" -ForegroundColor Yellow

    # Prompt for password
    $credential = Get-Credential -UserName $Username -Message "Enter password to create test scheduled task"

    if (-not $credential) {
        Write-Host "[!] Cancelled" -ForegroundColor Red
        return
    }

    try {
        # Create a simple scheduled task that runs immediately
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Test"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
        $principal = New-ScheduledTaskPrincipal -UserId $Username -LogonType Password

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
            -User $credential.UserName -Password $credential.GetNetworkCredential().Password | Out-Null

        Write-Host "[+] Scheduled task created: $TaskName" -ForegroundColor Green
        Write-Host "    Waiting for task to run (generates Batch logon)..." -ForegroundColor Yellow

        Start-Sleep -Seconds 7

        # Clean up
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[+] Batch logon generated and task cleaned up" -ForegroundColor Green

    } catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }
}

# Function to generate Service Logon (Type 5)
function Generate-ServiceLogon {
    param(
        [string]$Username = $env:USERNAME,
        [string]$ServiceName = "BOFTestService_$(Get-Random)"
    )

    Write-Host "[*] Generating Service Logon (Type 5)..." -ForegroundColor Cyan
    Write-Host "    This requires credentials and will create a temporary Windows service" -ForegroundColor Yellow
    Write-Host "    (Requires sc.exe and Administrator privileges)" -ForegroundColor Yellow

    # Prompt for password
    $credential = Get-Credential -UserName $Username -Message "Enter password to create test service"

    if (-not $credential) {
        Write-Host "[!] Cancelled" -ForegroundColor Red
        return
    }

    try {
        # Create a dummy service (using cmd.exe as the binary, will fail but generates logon event)
        $domain = $env:USERDOMAIN
        $user = $credential.UserName
        $password = $credential.GetNetworkCredential().Password

        # Create service
        $null = sc.exe create $ServiceName binPath= "cmd.exe /c echo test" obj= "$domain\$user" password= $password type= own start= demand 2>&1

        Write-Host "[+] Service created: $ServiceName" -ForegroundColor Green
        Write-Host "    Attempting to start service (generates Service logon)..." -ForegroundColor Yellow

        # Try to start it (will likely fail, but generates logon event)
        $null = sc.exe start $ServiceName 2>&1

        Start-Sleep -Seconds 2

        # Clean up
        $null = sc.exe delete $ServiceName 2>&1
        Write-Host "[+] Service logon generated and service cleaned up" -ForegroundColor Green

    } catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
        # Try to clean up anyway
        $null = sc.exe delete $ServiceName 2>&1
    }
}

# Function to show recent logon events after generation
function Show-RecentLogons {
    Write-Host ""
    Write-Host "[*] Recent logon events (last 5 minutes):" -ForegroundColor Cyan
    Write-Host ""

    $startTime = (Get-Date).AddMinutes(-5)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624
            StartTime = $startTime
        } -MaxEvents 20 -ErrorAction Stop

        foreach ($event in $events | Select-Object -First 10) {
            $xml = [xml]$event.ToXml()
            $eventData = $xml.Event.EventData.Data

            $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $targetDomain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
            $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'

            $logonTypeStr = switch ($logonType) {
                "2" { "Interactive" }
                "3" { "Network" }
                "4" { "Batch" }
                "5" { "Service" }
                "7" { "Unlock" }
                "10" { "RemoteInteractive" }
                default { "Type $logonType" }
            }

            # Filter out noise
            if ($targetUser -notmatch '\$' -and $targetUser -ne 'SYSTEM' -and $targetUser -ne 'LOCAL SERVICE') {
                Write-Host "[$logonTypeStr] $($event.TimeCreated.ToLocalTime()) - $targetDomain\$targetUser" -ForegroundColor White
            }
        }
    } catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }

    Write-Host ""
}

# Main Menu
Write-Host "Choose logon type to generate:" -ForegroundColor Yellow
Write-Host "  1) Network Logon (Type 3) - Quick, no credentials needed" -ForegroundColor White
Write-Host "  2) Batch Logon (Type 4) - Scheduled task (requires credentials)" -ForegroundColor White
Write-Host "  3) Service Logon (Type 5) - Windows service (requires credentials)" -ForegroundColor White
Write-Host "  4) All automated tests (Network only)" -ForegroundColor White
Write-Host "  5) Show recent logon events" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice (1-5)"

Write-Host ""

switch ($choice) {
    "1" {
        Generate-NetworkLogon
        Start-Sleep -Seconds 2
        Show-RecentLogons
    }
    "2" {
        Generate-BatchLogon
        Start-Sleep -Seconds 2
        Show-RecentLogons
    }
    "3" {
        Generate-ServiceLogon
        Start-Sleep -Seconds 2
        Show-RecentLogons
    }
    "4" {
        Write-Host "[*] Running automated tests (Network logons only)..." -ForegroundColor Cyan
        Write-Host ""

        Generate-NetworkLogon
        Start-Sleep -Seconds 1

        Write-Host "[+] Test complete!" -ForegroundColor Green
        Start-Sleep -Seconds 2
        Show-RecentLogons
    }
    "5" {
        Show-RecentLogons
    }
    default {
        Write-Host "[!] Invalid choice" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Now test with the BOF:" -ForegroundColor Yellow
Write-Host "  logon-events" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

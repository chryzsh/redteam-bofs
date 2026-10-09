# Quick script to check what logon events were actually generated
# Shows ALL events including SYSTEM/noise to see what's happening

#Requires -RunAsAdministrator

$startTime = (Get-Date).AddMinutes(-10)

Write-Host "[*] Checking ALL Event ID 4624 events from last 10 minutes..." -ForegroundColor Cyan
Write-Host "[*] Start time: $startTime" -ForegroundColor Yellow
Write-Host ""

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -MaxEvents 50 -ErrorAction Stop

    Write-Host "[+] Found $($events.Count) total events (including noise)" -ForegroundColor Green
    Write-Host ""

    # Group by logon type
    $byType = @{}

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = $xml.Event.EventData.Data

        $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $targetDomain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $authPackage = ($eventData | Where-Object { $_.Name -eq 'AuthenticationPackageName' }).'#text'

        $logonTypeStr = switch ($logonType) {
            "2" { "Interactive" }
            "3" { "Network" }
            "4" { "Batch" }
            "5" { "Service" }
            "7" { "Unlock" }
            "8" { "NetworkCleartext" }
            "10" { "RemoteInteractive" }
            "11" { "CachedInteractive" }
            default { "Type$logonType" }
        }

        if (-not $byType.ContainsKey($logonTypeStr)) {
            $byType[$logonTypeStr] = @()
        }

        $byType[$logonTypeStr] += @{
            Time = $event.TimeCreated.ToString("HH:mm:ss")
            User = "$targetDomain\$targetUser"
            Auth = $authPackage
        }
    }

    # Display summary by type
    Write-Host "Events by Logon Type:" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor DarkGray

    foreach ($type in $byType.Keys | Sort-Object) {
        $count = $byType[$type].Count
        Write-Host ""
        Write-Host "[$type] - $count events" -ForegroundColor Yellow

        # Show first 5 of each type
        $byType[$type] | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Time) - $($_.User) - $($_.Auth)" -ForegroundColor White
        }

        if ($count -gt 5) {
            Write-Host "  ... and $($count - 5) more" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor DarkGray
    Write-Host ""

} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host "[!] Make sure you're running as Administrator" -ForegroundColor Red
}

Write-Host ""
Write-Host "[*] This shows ALL events including SYSTEM/noise" -ForegroundColor Yellow
Write-Host "[*] The BOF filters out SYSTEM, computer accounts, etc." -ForegroundColor Yellow
Write-Host ""

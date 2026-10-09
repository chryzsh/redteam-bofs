# Create Test Credentials for Credential Manager Enumeration BOF
#
# This script creates various test credentials in Windows Credential Manager
# to validate the credential-manager-enum BOF functionality.
#
# Usage: Run as normal user (no admin required)
#   .\create-test-credentials.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Credential Manager Test Data Creator" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to add a generic credential
function Add-TestGenericCredential {
    param(
        [string]$Target,
        [string]$Username,
        [string]$Password
    )

    Write-Host "[+] Adding GENERIC credential: $Target" -ForegroundColor Green
    try {
        # Using cmdkey to add generic credentials
        $output = cmdkey /generic:$Target /user:$Username /pass:$Password 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Success: $Target" -ForegroundColor DarkGreen
        } else {
            Write-Host "    Failed: $output" -ForegroundColor Red
        }
    } catch {
        Write-Host "    Error: $_" -ForegroundColor Red
    }
}

# Function to add a domain credential
function Add-TestDomainCredential {
    param(
        [string]$Target,
        [string]$Username,
        [string]$Password
    )

    Write-Host "[+] Adding DOMAIN credential: $Target" -ForegroundColor Green
    try {
        $output = cmdkey /add:$Target /user:$Username /pass:$Password 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Success: $Target" -ForegroundColor DarkGreen
        } else {
            Write-Host "    Failed: $output" -ForegroundColor Red
        }
    } catch {
        Write-Host "    Error: $_" -ForegroundColor Red
    }
}

Write-Host "Creating test credentials..." -ForegroundColor Yellow
Write-Host ""

# Create various generic credentials
Write-Host "[*] Creating GENERIC credentials (Web/App)" -ForegroundColor Cyan
Add-TestGenericCredential -Target "LegacyGeneric:target=https://github.com" -Username "testuser@github.com" -Password "GitHubTestPassword123!"
Add-TestGenericCredential -Target "LegacyGeneric:target=https://gitlab.com" -Username "devuser@gitlab.com" -Password "GitLabTestPassword456!"
Add-TestGenericCredential -Target "LegacyGeneric:target=https://bitbucket.org" -Username "coder@bitbucket.org" -Password "BitbucketTestPass789!"
Add-TestGenericCredential -Target "LegacyGeneric:target=https://dev.azure.com" -Username "azure_dev@microsoft.com" -Password "AzureDevOpsPass321!"
Add-TestGenericCredential -Target "LegacyGeneric:target=myapp" -Username "appuser" -Password "MyAppPassword999!"

Write-Host ""

# Create domain-style credentials (network/RDP)
Write-Host "[*] Creating DOMAIN-style credentials (Network/RDP)" -ForegroundColor Cyan
Add-TestDomainCredential -Target "server01.corp.local" -Username "CORP\admin" -Password "ServerAdminPass123!"
Add-TestDomainCredential -Target "database.internal.local" -Username "INTERNAL\dbuser" -Password "DatabasePass456!"
Add-TestDomainCredential -Target "fileserver.corp.local" -Username "CORP\fileadmin" -Password "FileServerPass789!"
Add-TestDomainCredential -Target "rdp.remote.com" -Username "remote\rdpuser" -Password "RDPTestPassword321!"

Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Credential Creation Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Created credentials:" -ForegroundColor Yellow
Write-Host "  - 5 Generic credentials (web/app services)" -ForegroundColor White
Write-Host "  - 4 Domain credentials (network/RDP)" -ForegroundColor White
Write-Host ""
Write-Host "You can now test the BOF with:" -ForegroundColor Yellow
Write-Host "  credential-manager-enum" -ForegroundColor White
Write-Host "  credential-manager-enum -f github" -ForegroundColor White
Write-Host "  credential-manager-enum --filter corp.local" -ForegroundColor White
Write-Host ""

# Offer to view credentials
Write-Host "Would you like to view the credentials in Windows Credential Manager? (y/n): " -ForegroundColor Cyan -NoNewline
$response = Read-Host

if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "[*] Opening Credential Manager..." -ForegroundColor Green
    Start-Process "rundll32.exe" -ArgumentList "keymgr.dll,KRShowKeyMgr"
}

Write-Host ""
Write-Host "To remove all test credentials later, run:" -ForegroundColor Yellow
Write-Host '  Get-StoredCredential | Where-Object {$_.Target -match "github|gitlab|bitbucket|azure|myapp|server01|database|fileserver|rdp"} | ForEach-Object {cmdkey /delete:$_.Target}' -ForegroundColor DarkGray
Write-Host ""

# Alternative cleanup command
Write-Host "Or manually remove with:" -ForegroundColor Yellow
Write-Host "  cmdkey /delete:LegacyGeneric:target=https://github.com" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:server01.corp.local" -ForegroundColor DarkGray
Write-Host "  etc..." -ForegroundColor DarkGray
Write-Host ""

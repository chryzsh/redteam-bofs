# Create Test Credentials for Credential Manager Decryption BOF
#
# This script creates various test credentials in Windows Credential Manager
# to validate the credential-manager-decrypt BOF functionality.
#
# Usage: Run as normal user (no admin required)
#   .\create-test-credentials.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Credential Manager Test Data Creator" -ForegroundColor Cyan
Write-Host "for Decryption BOF Testing" -ForegroundColor Cyan
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
            Write-Host "    Username: $Username" -ForegroundColor DarkGray
            Write-Host "    Password: $Password" -ForegroundColor DarkGray
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
            Write-Host "    Username: $Username" -ForegroundColor DarkGray
            Write-Host "    Password: $Password" -ForegroundColor DarkGray
        } else {
            Write-Host "    Failed: $output" -ForegroundColor Red
        }
    } catch {
        Write-Host "    Error: $_" -ForegroundColor Red
    }
}

Write-Host "Creating test credentials with known passwords..." -ForegroundColor Yellow
Write-Host "These passwords will be used to verify decryption works correctly." -ForegroundColor Yellow
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
Write-Host "Known passwords for verification:" -ForegroundColor Yellow
Write-Host "  - GitHubTestPassword123!" -ForegroundColor DarkGray
Write-Host "  - GitLabTestPassword456!" -ForegroundColor DarkGray
Write-Host "  - BitbucketTestPass789!" -ForegroundColor DarkGray
Write-Host "  - AzureDevOpsPass321!" -ForegroundColor DarkGray
Write-Host "  - MyAppPassword999!" -ForegroundColor DarkGray
Write-Host "  - ServerAdminPass123!" -ForegroundColor DarkGray
Write-Host "  - DatabasePass456!" -ForegroundColor DarkGray
Write-Host "  - FileServerPass789!" -ForegroundColor DarkGray
Write-Host "  - RDPTestPassword321!" -ForegroundColor DarkGray
Write-Host ""
Write-Host "You can now test the BOF with:" -ForegroundColor Yellow
Write-Host "  credential-manager-decrypt" -ForegroundColor White
Write-Host "  credential-manager-decrypt -f github" -ForegroundColor White
Write-Host "  credential-manager-decrypt --filter corp.local" -ForegroundColor White
Write-Host ""
Write-Host "The BOF should decrypt and display all these passwords." -ForegroundColor Green
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
Write-Host "  cmdkey /delete:LegacyGeneric:target=https://github.com" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:LegacyGeneric:target=https://gitlab.com" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:LegacyGeneric:target=https://bitbucket.org" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:LegacyGeneric:target=https://dev.azure.com" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:LegacyGeneric:target=myapp" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:server01.corp.local" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:database.internal.local" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:fileserver.corp.local" -ForegroundColor DarkGray
Write-Host "  cmdkey /delete:rdp.remote.com" -ForegroundColor DarkGray
Write-Host ""

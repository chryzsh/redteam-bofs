# Create Test Registry Keys for registry-intel BOF
# Creates safe test registry entries to validate registry-intel functionality

Write-Host "[*] Creating test registry keys for registry-intel BOF..." -ForegroundColor Cyan
Write-Host ""

# ====================
# RDP History Test Keys
# ====================
Write-Host "[+] Creating RDP connection history..." -ForegroundColor Green

$rdpServersPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
$rdpDefaultPath = "HKCU:\Software\Microsoft\Terminal Server Client\Default"

# Ensure base paths exist
if (!(Test-Path $rdpServersPath)) {
    New-Item -Path $rdpServersPath -Force | Out-Null
}

if (!(Test-Path $rdpDefaultPath)) {
    New-Item -Path $rdpDefaultPath -Force | Out-Null
}

# Create test RDP server entries
$testServers = @(
    "server01.example.com",
    "rdp.corporate.local",
    "10.0.1.50",
    "jumpbox-prod.internal",
    "dev-machine.lab"
)

foreach ($server in $testServers) {
    $serverPath = "$rdpServersPath\$server"
    if (!(Test-Path $serverPath)) {
        New-Item -Path $serverPath -Force | Out-Null
        Write-Host "  [+] Created RDP server entry: $server"
    }
}

# Create MRU (Most Recently Used) entries
Set-ItemProperty -Path $rdpDefaultPath -Name "MRU0" -Value "server01.example.com" -Type String -Force
Set-ItemProperty -Path $rdpDefaultPath -Name "MRU1" -Value "10.0.1.50" -Type String -Force
Set-ItemProperty -Path $rdpDefaultPath -Name "MRU2" -Value "jumpbox-prod.internal" -Type String -Force

Write-Host "  [+] Created MRU entries"

# ====================
# Environment Variables
# ====================
Write-Host "`n[+] Creating test environment variables..." -ForegroundColor Green

$envPath = "HKCU:\Environment"

# Create test user environment variables
$testEnvVars = @{
    "TEST_API_KEY" = "fake-api-key-12345"
    "TEST_DATABASE_URL" = "postgresql://test:pass@localhost:5432/testdb"
    "TEST_AWS_PROFILE" = "development"
    "TEST_PYTHON_PATH" = "C:\Dev\Python310"
    "TEST_PROJECT_ROOT" = "C:\Projects\MyApp"
}

foreach ($var in $testEnvVars.GetEnumerator()) {
    Set-ItemProperty -Path $envPath -Name $var.Key -Value $var.Value -Type String -Force
    Write-Host "  [+] Created env var: $($var.Key)"
}

# ====================
# WSL Test Detection
# ====================
Write-Host "`n[+] Creating WSL test registry entries..." -ForegroundColor Green

$wslPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"

if (!(Test-Path $wslPath)) {
    New-Item -Path $wslPath -Force | Out-Null
}

# Create fake WSL distribution entries
$testDistros = @{
    "{12345678-1234-1234-1234-123456789012}" = "Ubuntu-22.04"
    "{87654321-4321-4321-4321-210987654321}" = "Debian"
    "{ABCDEFGH-ABCD-ABCD-ABCD-ABCDEFGHIJKL}" = "kali-linux"
}

foreach ($distro in $testDistros.GetEnumerator()) {
    $distroPath = "$wslPath\$($distro.Key)"
    if (!(Test-Path $distroPath)) {
        New-Item -Path $distroPath -Force | Out-Null
    }
    Set-ItemProperty -Path $distroPath -Name "DistributionName" -Value $distro.Value -Type String -Force
    Set-ItemProperty -Path $distroPath -Name "BasePath" -Value "C:\Users\$env:USERNAME\AppData\Local\Packages\$($distro.Value)" -Type String -Force
    Write-Host "  [+] Created WSL distro: $($distro.Value)"
}

# ====================
# Software Entries (User-level)
# ====================
Write-Host "`n[+] Creating test software entries (user-level)..." -ForegroundColor Green

$uninstallPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

if (!(Test-Path $uninstallPath)) {
    New-Item -Path $uninstallPath -Force | Out-Null
}

# Create fake software entries
$testSoftware = @(
    @{Name="TestApp Pro"; Version="3.14.159"; Publisher="Example Software Inc."},
    @{Name="Developer Tools Suite"; Version="2.0.1"; Publisher="DevTools Corp"},
    @{Name="Security Scanner"; Version="1.5.0"; Publisher="SecTools Ltd"}
)

foreach ($software in $testSoftware) {
    $guid = [guid]::NewGuid().ToString()
    $softwarePath = "$uninstallPath\$guid"

    New-Item -Path $softwarePath -Force | Out-Null
    Set-ItemProperty -Path $softwarePath -Name "DisplayName" -Value $software.Name -Type String -Force
    Set-ItemProperty -Path $softwarePath -Name "DisplayVersion" -Value $software.Version -Type String -Force
    Set-ItemProperty -Path $softwarePath -Name "Publisher" -Value $software.Publisher -Type String -Force
    Set-ItemProperty -Path $softwarePath -Name "InstallDate" -Value (Get-Date -Format "yyyyMMdd") -Type String -Force

    Write-Host "  [+] Created software entry: $($software.Name) v$($software.Version)"
}

# ====================
# Summary
# ====================
Write-Host "`n[*] Test registry creation complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test with registry-intel:" -ForegroundColor Yellow
Write-Host "  registry-intel" -ForegroundColor White
Write-Host "  registry-intel --rdp" -ForegroundColor White
Write-Host "  registry-intel --software" -ForegroundColor White
Write-Host "  registry-intel --env" -ForegroundColor White
Write-Host "  registry-intel --wsl" -ForegroundColor White
Write-Host "  registry-intel --all" -ForegroundColor White
Write-Host ""

# Create cleanup script
$cleanupScript = @"
# Cleanup script for registry-intel test keys
Write-Host "[*] Cleaning up registry-intel test keys..." -ForegroundColor Yellow

# Remove RDP test servers
Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\server01.example.com" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\rdp.corporate.local" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\10.0.1.50" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\jumpbox-prod.internal" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\dev-machine.lab" -ErrorAction SilentlyContinue

# Remove MRU entries
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Default" -Name "MRU0" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Default" -Name "MRU1" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Default" -Name "MRU2" -ErrorAction SilentlyContinue

# Remove test environment variables
Remove-ItemProperty -Path "HKCU:\Environment" -Name "TEST_API_KEY" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Environment" -Name "TEST_DATABASE_URL" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Environment" -Name "TEST_AWS_PROFILE" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Environment" -Name "TEST_PYTHON_PATH" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Environment" -Name "TEST_PROJECT_ROOT" -ErrorAction SilentlyContinue

# Remove WSL test entries
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -Recurse -ErrorAction SilentlyContinue

# Remove test software entries (user-level uninstall keys with test names)
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object {
    `$displayName = (Get-ItemProperty -Path `$_.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue).DisplayName
    if (`$displayName -like "TestApp*" -or `$displayName -like "Developer Tools*" -or `$displayName -like "Security Scanner*") {
        Remove-Item -Path `$_.PSPath -Force
        Write-Host "[+] Removed: `$displayName"
    }
}

Write-Host "[*] Cleanup complete!" -ForegroundColor Green
"@

$cleanupScript | Out-File -FilePath "cleanup-test-registry.ps1" -Encoding UTF8
Write-Host "Cleanup script created: cleanup-test-registry.ps1" -ForegroundColor Yellow
Write-Host "  Run: .\cleanup-test-registry.ps1" -ForegroundColor White
Write-Host ""

# Display expected results
Write-Host "[*] Expected Results:" -ForegroundColor Cyan
Write-Host "  - RDP Connections: 5 servers + 3 MRU entries" -ForegroundColor White
Write-Host "  - Software: 3 applications (user-level)" -ForegroundColor White
Write-Host "  - Environment Variables: 5 test variables" -ForegroundColor White
Write-Host "  - WSL: 3 distributions detected" -ForegroundColor White
Write-Host ""

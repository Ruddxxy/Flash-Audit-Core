#Requires -Version 5.1
# =============================================================================
# FlashAudit Windows Installer
# Usage: irm https://raw.githubusercontent.com/Ruddxxy/Flash-Audit/main/install.ps1 | iex
# =============================================================================

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\FlashAudit\bin"
)

$ErrorActionPreference = "Stop"
$Repo = "Ruddxxy/Flash-Audit"

function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Write-Warn { param($Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  _____ _           _      _             _ _ _   " -ForegroundColor Cyan
Write-Host " |  ___| | __ _ ___| |__  / \  _   _  __| (_) |_ " -ForegroundColor Cyan
Write-Host " | |_  | |/ _`` / __| '_ \/ _ \| | | |/ _`` | | __|" -ForegroundColor Cyan
Write-Host " |  _| | | (_| \__ \ | | / ___ \ |_| | (_| | | |_ " -ForegroundColor Cyan
Write-Host " |_|   |_|\__,_|___/_| |_\_/ \_\__,_|\__,_|_|\__|" -ForegroundColor Cyan
Write-Host ""
Write-Host " High-performance secrets scanner" -ForegroundColor White
Write-Host ""

# Get latest version if not specified
if ($Version -eq "latest") {
    Write-Info "Fetching latest version..."
    try {
        $Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $Release.tag_name -replace '^v', ''
    } catch {
        Write-Err "Failed to fetch latest version. Check https://github.com/$Repo/releases"
    }
}
$Version = $Version -replace '^v', ''
Write-Info "Installing FlashAudit version: $Version"

# Determine architecture
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
if ($Arch -eq "x86") {
    Write-Err "32-bit Windows is not supported"
}

$FileName = "flash_audit-windows-x86_64.exe"
$DownloadUrl = "https://github.com/$Repo/releases/download/v$Version/$FileName.zip"

# Create temp directory
$TempDir = Join-Path $env:TEMP "flashaudit-install-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
$ZipFile = Join-Path $TempDir "flashaudit.zip"

Write-Info "Downloading from: $DownloadUrl"
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile -UseBasicParsing
} catch {
    Write-Err "Failed to download. Check if version $Version exists at https://github.com/$Repo/releases"
}

# Extract
Write-Info "Extracting..."
Expand-Archive -Path $ZipFile -DestinationPath $TempDir -Force

# Find binary
$Binary = Get-ChildItem -Path $TempDir -Recurse -Filter "*.exe" | Select-Object -First 1
if (-not $Binary) {
    Write-Err "Binary not found in archive"
}

# Install
Write-Info "Installing to $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $Binary.FullName -Destination (Join-Path $InstallDir "flash_audit.exe") -Force

# Add to PATH if not already there
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Info "Adding $InstallDir to PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
}

# Cleanup
Remove-Item -Recurse -Force $TempDir

# Verify
Write-Info "FlashAudit installed successfully!"
Write-Host ""

try {
    & (Join-Path $InstallDir "flash_audit.exe") --version
} catch {
    Write-Host "  flash_audit v$Version"
}

Write-Host ""
Write-Info "Get started:"
Write-Host "    flash_audit C:\path\to\repo"
Write-Host "    flash_audit --help"
Write-Host ""
Write-Warn "Restart your terminal to use flash_audit from any directory"
Write-Host ""
Write-Host " Documentation: https://github.com/$Repo" -ForegroundColor Gray
Write-Host ""

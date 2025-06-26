# Start-AzureSecurityReport.ps1
# Wrapper script to ensure clean execution of Azure Security Report

param(
    [switch]$Modular,
    [switch]$SingleFile
)

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "PowerShell 7 or higher is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host "Please install PowerShell 7 from: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
    exit 1
}

# Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Azure Security Report Launcher" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Determine which script to run
$ScriptToRun = $null

if ($Modular) {
    $ScriptToRun = "AzureSecurityReport-Modular.ps1"
} elseif ($SingleFile) {
    $ScriptToRun = "AzureSecurityReport.ps1"
} else {
    Write-Host "Which version would you like to run?" -ForegroundColor Cyan
    Write-Host "1. Modular version (recommended)" -ForegroundColor White
    Write-Host "2. Single-file version" -ForegroundColor White
    Write-Host ""
    
    do {
        $Choice = Read-Host "Select option (1 or 2)"
        switch ($Choice) {
            "1" { 
                $ScriptToRun = "AzureSecurityReport-Modular.ps1"
                break
            }
            "2" { 
                $ScriptToRun = "AzureSecurityReport.ps1"
                break
            }
            default { 
                Write-Host "Invalid selection. Please enter 1 or 2." -ForegroundColor Red 
            }
        }
    } while (-not $ScriptToRun)
}

# Check if script exists
$ScriptPath = Join-Path $PSScriptRoot $ScriptToRun
if (-not (Test-Path $ScriptPath)) {
    Write-Host "Error: Script not found at $ScriptPath" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting $ScriptToRun..." -ForegroundColor Green
Write-Host "Note: If you encounter Microsoft Graph assembly conflicts, this script will offer to restart PowerShell automatically." -ForegroundColor Yellow
Write-Host ""

# Run the selected script
try {
    & $ScriptPath
} catch {
    Write-Host "Error running script: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Message -like "*Assembly with same name is already loaded*") {
        Write-Host ""
        Write-Host "Assembly conflict detected. Would you like to restart PowerShell? (Y/N)" -ForegroundColor Yellow
        $Restart = Read-Host
        
        if ($Restart -eq 'Y' -or $Restart -eq 'y') {
            $RestartScript = Join-Path $PSScriptRoot "Restart-PowerShellSession.ps1"
            if (Test-Path $RestartScript) {
                & $RestartScript
            } else {
                Write-Host "Please close PowerShell and start a new session, then run this script again." -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Gray
Read-Host

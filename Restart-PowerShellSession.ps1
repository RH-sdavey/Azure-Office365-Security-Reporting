# Restart-PowerShellSession.ps1
# This script restarts PowerShell to completely clear Graph module assemblies

Write-Host "Microsoft Graph assembly conflicts detected." -ForegroundColor Yellow
Write-Host "PowerShell session restart is required to resolve this issue." -ForegroundColor Yellow
Write-Host ""
Write-Host "Options:" -ForegroundColor Cyan
Write-Host "1. Automatic restart (recommended)" -ForegroundColor White
Write-Host "2. Manual restart instructions" -ForegroundColor White
Write-Host ""

$Choice = Read-Host "Select option (1 or 2)"

switch ($Choice) {
    "1" {
        Write-Host ""
        Write-Host "Restarting PowerShell session..." -ForegroundColor Green
        Write-Host "The script will automatically run after restart." -ForegroundColor Yellow
        
        $ScriptPath = Join-Path $PSScriptRoot "AzureSecurityReport-Modular.ps1"
        
        # Create a batch file to restart PowerShell and run the script
        $BatchContent = @"
@echo off
echo Restarting PowerShell session to resolve Graph module conflicts...
timeout /t 2 /nobreak >nul
pwsh.exe -ExecutionPolicy Bypass -File "$ScriptPath"
pause
"@
        
        $BatchFile = Join-Path $env:TEMP "RestartAzureSecurityReport.bat"
        $BatchContent | Out-File -FilePath $BatchFile -Encoding ASCII
        
        # Start the batch file and exit current session
        Start-Process -FilePath $BatchFile -WindowStyle Normal
        exit
    }
    "2" {
        Write-Host ""
        Write-Host "Manual restart instructions:" -ForegroundColor Cyan
        Write-Host "1. Close this PowerShell window" -ForegroundColor White
        Write-Host "2. Open a new PowerShell 7 window" -ForegroundColor White
        Write-Host "3. Navigate to: $PSScriptRoot" -ForegroundColor White
        Write-Host "4. Run: .\AzureSecurityReport-Modular.ps1" -ForegroundColor White
        Write-Host ""
        Write-Host "Press Enter to exit..." -ForegroundColor Gray
        Read-Host
        exit
    }
    default {
        Write-Host "Invalid selection. Please restart PowerShell manually." -ForegroundColor Red
        exit
    }
}

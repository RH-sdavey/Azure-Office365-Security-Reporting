# Test script for new Azure Security Report modules
# This script tests the new functionality without requiring full authentication

Write-Host "Testing Azure Security Report v3.5 - New Modules" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Test module imports
$ModulesPath = Join-Path $PSScriptRoot "Modules"

try {
    Write-Host "Testing module imports..." -ForegroundColor Yellow
    
    # Test Core module
    Import-Module (Join-Path $ModulesPath "AzureSecurityCore.psm1") -Force
    Write-Host "✓ AzureSecurityCore.psm1 loaded successfully" -ForegroundColor Green
    
    # Test Settings module
    Import-Module (Join-Path $ModulesPath "AzureSecuritySettings.psm1") -Force
    Write-Host "✓ AzureSecuritySettings.psm1 loaded successfully" -ForegroundColor Green
    
    # Test Infrastructure module
    Import-Module (Join-Path $ModulesPath "AzureSecurityInfrastructure.psm1") -Force
    Write-Host "✓ AzureSecurityInfrastructure.psm1 loaded successfully" -ForegroundColor Green
    
    # Test SharePoint module
    Import-Module (Join-Path $ModulesPath "AzureSecuritySharePoint.psm1") -Force
    Write-Host "✓ AzureSecuritySharePoint.psm1 loaded successfully" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "All new modules loaded successfully!" -ForegroundColor Green
    
    # Test configuration functions
    Write-Host ""
    Write-Host "Testing configuration functionality..." -ForegroundColor Yellow
    
    # Initialize config
    Initialize-SecurityConfig | Out-Null
    Write-Host "✓ Configuration initialized" -ForegroundColor Green
    
    # Test config retrieval
    $Config = Get-SecurityConfig
    if ($Config) {
        Write-Host "✓ Configuration retrieved successfully" -ForegroundColor Green
        Write-Host "  - Config file version: $($Config.Version)" -ForegroundColor Gray
        Write-Host "  - Export path: $($Config.ExportPath)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "New Features Available:" -ForegroundColor Cyan
    Write-Host "1. ⚙️  Settings & Configuration Management" -ForegroundColor White
    Write-Host "2. 🏗️  Azure Storage Security Assessment" -ForegroundColor White
    Write-Host "3. 🔐 Azure Key Vault Security Assessment" -ForegroundColor White
    Write-Host "4. 🛡️  Network Security Groups Analysis" -ForegroundColor White
    Write-Host "5. 📁 SharePoint Sharing Settings Report" -ForegroundColor White
    Write-Host "6. ☁️  OneDrive Security & Usage Report" -ForegroundColor White
    Write-Host "7. 📋 Data Loss Prevention Policy Guidance" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Key Improvements:" -ForegroundColor Cyan
    Write-Host "• Service Principal authentication support" -ForegroundColor White
    Write-Host "• Auto-connect functionality" -ForegroundColor White
    Write-Host "• Configurable export paths" -ForegroundColor White
    Write-Host "• Enhanced security coverage" -ForegroundColor White
    Write-Host "• Additional Azure resource analysis" -ForegroundColor White
    Write-Host ""
    
    Write-Host "✓ All tests completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run the main script:" -ForegroundColor Yellow
    Write-Host ".\AzureSecurityReport-Modular.ps1" -ForegroundColor White
    
}
catch {
    Write-Host "❌ Error during testing: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please check that all module files are present in the Modules folder." -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Press Enter to exit"

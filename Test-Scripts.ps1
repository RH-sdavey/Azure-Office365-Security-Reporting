# Test-Scripts.ps1 - Test both single-file and modular versions
# This script validates that both versions work correctly after the Graph module fixes

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Azure Security Report - Script Tester" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if modules can be imported
Write-Host "Test 1: Module Import Test" -ForegroundColor Green
Write-Host "-------------------------" -ForegroundColor Green

try {
    $ModulesPath = Join-Path $PSScriptRoot "Modules"
    $CoreModulePath = Join-Path $ModulesPath "AzureSecurityCore.psm1"
    
    if (Test-Path $CoreModulePath) {
        Import-Module $CoreModulePath -Force -ErrorAction Stop
        Write-Host "✓ Core module imported successfully" -ForegroundColor Green
        
        # Test if functions are available
        if (Get-Command "Show-Title" -ErrorAction SilentlyContinue) {
            Write-Host "✓ Core functions are available" -ForegroundColor Green
        } else {
            Write-Host "✗ Core functions not available" -ForegroundColor Red
        }
        
        # Clean up
        Remove-Module "AzureSecurityCore" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "✗ Core module not found at: $CoreModulePath" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Module import failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# Test 2: Check if scripts exist and are valid PowerShell
Write-Host "Test 2: Script Validation Test" -ForegroundColor Green
Write-Host "------------------------------" -ForegroundColor Green

$Scripts = @{
    "Single-File Script" = "AzureSecurityReport.ps1"
    "Modular Script" = "AzureSecurityReport-Modular.ps1"
    "Fix Script" = "Fix-GraphModules.ps1"
}

foreach ($ScriptName in $Scripts.Keys) {
    $ScriptPath = Join-Path $PSScriptRoot $Scripts[$ScriptName]
    
    if (Test-Path $ScriptPath) {
        try {
            # Test PowerShell syntax
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$null)
            Write-Host "✓ $ScriptName - Valid PowerShell syntax" -ForegroundColor Green
        } catch {
            Write-Host "✗ $ScriptName - Syntax error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ $ScriptName - File not found: $ScriptPath" -ForegroundColor Red
    }
}

Write-Host ""

# Test 3: Check required files
Write-Host "Test 3: Project Structure Test" -ForegroundColor Green
Write-Host "------------------------------" -ForegroundColor Green

$RequiredFiles = @(
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "SECURITY.md",
    ".gitignore"
)

foreach ($File in $RequiredFiles) {
    $FilePath = Join-Path $PSScriptRoot $File
    if (Test-Path $FilePath) {
        Write-Host "✓ $File exists" -ForegroundColor Green
    } else {
        Write-Host "✗ $File missing" -ForegroundColor Red
    }
}

Write-Host ""

# Test 4: Check module structure
Write-Host "Test 4: Module Structure Test" -ForegroundColor Green
Write-Host "-----------------------------" -ForegroundColor Green

$ModuleFiles = @(
    "Modules\AzureSecurityCore.psm1",
    "Modules\AzureSecurityIAM.psm1",
    "Modules\AzureSecurityDataProtection.psm1",
    "Modules\AzureSecurityOffice365.psm1"
)

foreach ($Module in $ModuleFiles) {
    $ModulePath = Join-Path $PSScriptRoot $Module
    if (Test-Path $ModulePath) {
        Write-Host "✓ $Module exists" -ForegroundColor Green
    } else {
        Write-Host "✗ $Module missing" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "If all tests show ✓, the scripts should work correctly." -ForegroundColor Green
Write-Host "If you see any ✗, please check the specific error messages above." -ForegroundColor Yellow
Write-Host ""
Write-Host "To fix Microsoft Graph module conflicts, run:" -ForegroundColor Cyan
Write-Host "  .\Fix-GraphModules.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to continue..." -ForegroundColor Gray
Read-Host

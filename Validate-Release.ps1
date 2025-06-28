# Azure Security Report v3.5 - Pre-Release Validation Script
# This script validates that all components are ready for release

$ErrorActionPreference = "Stop"

Write-Host "🔍 Azure Security Report v3.5 - Pre-Release Validation" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$ValidationResults = @()
$Passed = 0
$Failed = 0

# Function to add validation result
function Add-ValidationResult {
    param($Test, $Status, $Message)
    
    $script:ValidationResults += [PSCustomObject]@{
        Test = $Test
        Status = $Status
        Message = $Message
    }
    
    if ($Status -eq "PASS") {
        Write-Host "✅ $Test" -ForegroundColor Green
        $script:Passed++
    } else {
        Write-Host "❌ $Test - $Message" -ForegroundColor Red
        $script:Failed++
    }
}

# Test 1: Check if all required files exist
Write-Host "📁 Testing File Structure..." -ForegroundColor Yellow
$RequiredFiles = @(
    "AzureSecurityReport-Modular.ps1",
    "Start-AzureSecurityReport.ps1",
    "README.md",
    "RELEASE_NOTES_v3.5.md",
    "Modules\AzureSecurityCore.psm1",
    "Modules\AzureSecurityIAM.psm1",
    "Modules\AzureSecurityDataProtection.psm1",
    "Modules\AzureSecurityOffice365.psm1",
    "Modules\AzureSecuritySettings.psm1",
    "Modules\AzureSecurityInfrastructure.psm1",
    "Modules\AzureSecuritySharePoint.psm1"
)

foreach ($File in $RequiredFiles) {
    if (Test-Path $File) {
        Add-ValidationResult "File exists: $File" "PASS" ""
    } else {
        Add-ValidationResult "File exists: $File" "FAIL" "File not found"
    }
}

# Test 2: Check version numbers in files
Write-Host ""
Write-Host "🔢 Testing Version Numbers..." -ForegroundColor Yellow

# Check main script version
try {
    $MainScript = Get-Content "AzureSecurityReport-Modular.ps1" -Raw
    if ($MainScript -match "v3\.5") {
        Add-ValidationResult "Main script version" "PASS" ""
    } else {
        Add-ValidationResult "Main script version" "FAIL" "Version not updated to 3.5"
    }
} catch {
    Add-ValidationResult "Main script version" "FAIL" "Could not read main script"
}

# Check Settings module version
try {
    $SettingsModule = Get-Content "Modules\AzureSecuritySettings.psm1" -Raw
    if ($SettingsModule -match '"3\.5"') {
        Add-ValidationResult "Settings module version" "PASS" ""
    } else {
        Add-ValidationResult "Settings module version" "FAIL" "Version not updated to 3.5"
    }
} catch {
    Add-ValidationResult "Settings module version" "FAIL" "Could not read settings module"
}

# Check README version
try {
    $README = Get-Content "README.md" -Raw
    if ($README -match "Version-3\.5") {
        Add-ValidationResult "README version badge" "PASS" ""
    } else {
        Add-ValidationResult "README version badge" "FAIL" "Version badge not updated to 3.5"
    }
} catch {
    Add-ValidationResult "README version" "FAIL" "Could not read README"
}

# Test 3: Check module imports and exports
Write-Host ""
Write-Host "📦 Testing Module Structure..." -ForegroundColor Yellow

$ModulesToTest = @{
    "AzureSecuritySettings.psm1" = @("Show-SettingsMenu", "Get-SecurityConfig", "Set-SecurityConfig", "Connect-UsingConfig", "Initialize-SecurityConfig")
    "AzureSecurityInfrastructure.psm1" = @("Get-StorageSecurityReport", "Get-KeyVaultSecurityReport", "Get-NetworkSecurityReport")
    "AzureSecuritySharePoint.psm1" = @("Get-SharePointSharingReport", "Get-OneDriveSecurityReport", "Get-DLPPolicyReport")
}

foreach ($Module in $ModulesToTest.Keys) {
    $ModulePath = "Modules\$Module"
    try {
        $ModuleContent = Get-Content $ModulePath -Raw
        
        # Check if Export-ModuleMember exists
        if ($ModuleContent -match "Export-ModuleMember") {
            Add-ValidationResult "Module exports: $Module" "PASS" ""
        } else {
            Add-ValidationResult "Module exports: $Module" "FAIL" "No Export-ModuleMember found"
        }
        
        # Check if required functions exist
        $ExpectedFunctions = $ModulesToTest[$Module]
        foreach ($Function in $ExpectedFunctions) {
            if ($ModuleContent -match "function $Function") {
                Add-ValidationResult "Function exists: $Function" "PASS" ""
            } else {
                Add-ValidationResult "Function exists: $Function" "FAIL" "Function not found in $Module"
            }
        }
    } catch {
        Add-ValidationResult "Module structure: $Module" "FAIL" "Could not read module file"
    }
}

# Test 4: Check for syntax errors (basic)
Write-Host ""
Write-Host "🔍 Testing PowerShell Syntax..." -ForegroundColor Yellow

$ScriptsToTest = @(
    "AzureSecurityReport-Modular.ps1",
    "Test-NewFeatures.ps1"
)

foreach ($Script in $ScriptsToTest) {
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $Script -Raw), [ref]$null)
        Add-ValidationResult "Syntax check: $Script" "PASS" ""
    } catch {
        Add-ValidationResult "Syntax check: $Script" "FAIL" "Syntax error detected"
    }
}

# Test 5: Check README structure
Write-Host ""
Write-Host "📖 Testing README Structure..." -ForegroundColor Yellow

try {
    $README = Get-Content "README.md" -Raw
    
    $RequiredSections = @(
        "What's New in Version 3.5",
        "Azure Infrastructure Security",
        "SharePoint & OneDrive Security",
        "Settings & Configuration",
        "Required Modules",
        "Service Principal",
        "Storage Security",
        "Key Vault Security",
        "Network Security"
    )
    
    foreach ($Section in $RequiredSections) {
        if ($README -match $Section) {
            Add-ValidationResult "README section: $Section" "PASS" ""
        } else {
            Add-ValidationResult "README section: $Section" "FAIL" "Section not found or incomplete"
        }
    }
} catch {
    Add-ValidationResult "README structure" "FAIL" "Could not analyze README"
}

# Test 6: Check new menu structure in main script
Write-Host ""
Write-Host "🎯 Testing Menu Structure..." -ForegroundColor Yellow

try {
    $MainScript = Get-Content "AzureSecurityReport-Modular.ps1" -Raw
    
    $ExpectedMenuItems = @(
        "Azure Infrastructure Security Report",
        "SharePoint & OneDrive Security Report",
        "Settings & Configuration",
        "Show-InfrastructureSecurityMenu",
        "Show-SharePointMenu",
        "Show-SettingsMenu"
    )
    
    foreach ($Item in $ExpectedMenuItems) {
        if ($MainScript -match [regex]::Escape($Item)) {
            Add-ValidationResult "Menu item: $Item" "PASS" ""
        } else {
            Add-ValidationResult "Menu item: $Item" "FAIL" "Menu item not found"
        }
    }
} catch {
    Add-ValidationResult "Menu structure" "FAIL" "Could not analyze menu structure"
}

# Final Results
Write-Host ""
Write-Host "📋 Validation Summary" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Total Tests: $($ValidationResults.Count)"
Write-Host "Passed: $Passed" -ForegroundColor Green
Write-Host "Failed: $Failed" -ForegroundColor Red
Write-Host ""

if ($Failed -eq 0) {
    Write-Host "🎉 ALL TESTS PASSED! Azure Security Report v3.5 is ready for release!" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Release Checklist:" -ForegroundColor Yellow
    Write-Host "  • All files present and accounted for"
    Write-Host "  • Version numbers updated to 3.5"
    Write-Host "  • New modules properly structured"
    Write-Host "  • Menu system updated"
    Write-Host "  • README.md enhanced with new features"
    Write-Host "  • Release notes created"
    Write-Host ""
    Write-Host "🚀 Ready to deploy!" -ForegroundColor Green
} else {
    Write-Host "⚠️  VALIDATION FAILED! Please review and fix the following issues:" -ForegroundColor Red
    Write-Host ""
    $ValidationResults | Where-Object {$_.Status -eq "FAIL"} | ForEach-Object {
        Write-Host "❌ $($_.Test): $($_.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Please fix these issues before release." -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Press Enter to exit"

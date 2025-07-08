#Requires -Version 7.0
<#
.SYNOPSIS
    Azure Security Report - Modular Version
.DESCRIPTION
    Simplified main script that uses modular components for security auditing
.AUTHOR
    github.com/SteffMet
.VERSION
    3.5
.DATE
    June 28, 2025
#>

# Import modules
$ModulesPath = Join-Path $PSScriptRoot "Modules"

# Import Core module first and dot-source it to make functions available in current scope
$CoreModulePath = Join-Path $ModulesPath "AzureSecurityCore.psm1"
Import-Module $CoreModulePath -Force -Global

# Import other modules
Import-Module (Join-Path $ModulesPath "AzureSecurityIAM.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureSecurityDataProtection.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureSecurityOffice365.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureSecuritySettings.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureSecurityInfrastructure.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureSecuritySharePoint.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureComputeKQL.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "AzureEntraID.psm1") -Force -Global

# Teams submenu
function Show-TeamsMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Microsoft Teams Security Checks" -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "1. Check External Access Configuration"
        Write-Host "2. Report Teams with External Users or Guests"
        Write-Host "3. Return to Office 365 Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Get-TeamsExternalAccessReport; Read-Host "Press Enter to continue" }
            "2" { Get-TeamsWithExternalUsersReport; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Office 365 submenu
function Show-Office365Menu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Read-Only Office 365 Audit Menu" -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "1. License Usage Report"
        Write-Host "2. Inactive Accounts Report"
        Write-Host "3. Check Mailbox Forwarding Rules"
        Write-Host "4. Microsoft Teams"
        Write-Host "5. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Get-LicenseUsageReport; Read-Host "Press Enter to continue" }
            "2" { Get-InactiveAccountsReport; Read-Host "Press Enter to continue" }
            "3" { Get-MailboxForwardingReport; Read-Host "Press Enter to continue" }
            "4" { Show-TeamsMenu }
            "5" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# IAM submenu
function Show-IAMMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "IAM Security Checks" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "1. Check MFA Status"
        Write-Host "2. Check Guest User Access"
        Write-Host "3. Check Password Expiry Settings"
        Write-Host "4. Check Conditional Access Policies"
        Write-Host "5. App Registration Key Report"
        Write-Host "6. All SAM Account Names"
        Write-Host "7. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Test-MFAStatus; Read-Host "Press Enter to continue" }
            "2" { Test-GuestUserAccess; Read-Host "Press Enter to continue" }
            "3" { Test-PasswordExpirySettings; Read-Host "Press Enter to continue" }
            "4" { Test-ConditionalAccessPolicies; Read-Host "Press Enter to continue" }
            "5" { Get-AppRegistrationKeyReport; Read-Host "Press Enter to continue" }
            "6" { Get-AllSamls; Read-Host "Press Enter to continue" }
            "7" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Data Protection submenu
function Show-DataProtectionMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Data Protection Security Checks" -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "1. Check TLS Configuration on VMs"
        Write-Host "2. Check Virtual Machine Encryption"
        Write-Host "3. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Test-VMTLSConfiguration; Read-Host "Press Enter to continue" }
            "2" { Test-VMEncryption; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Azure Infrastructure Security submenu
function Show-InfrastructureSecurityMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure Infrastructure Security Checks" -ForegroundColor Cyan
        Write-Host "====================================" -ForegroundColor Cyan
        Write-Host "1. Azure Storage Security Report"
        Write-Host "2. Azure Key Vault Security Report"
        Write-Host "3. Network Security Groups Report"
        Write-Host "4. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-4)"
        
        switch ($Choice) {
            "1" { Get-StorageSecurityReport; Read-Host "Press Enter to continue" }
            "2" { Get-KeyVaultSecurityReport; Read-Host "Press Enter to continue" }
            "3" { Get-NetworkSecurityReport; Read-Host "Press Enter to continue" }
            "4" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# SharePoint & OneDrive Security submenu
function Show-SharePointMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "SharePoint & OneDrive Security Checks" -ForegroundColor Cyan
        Write-Host "=====================================" -ForegroundColor Cyan
        Write-Host "1. SharePoint Sharing Settings Report"
        Write-Host "2. OneDrive Security & Usage Report"
        Write-Host "3. Data Loss Prevention (DLP) Policy Report"
        Write-Host "4. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-4)"
        
        switch ($Choice) {
            "1" { Get-SharePointSharingReport; Read-Host "Press Enter to continue" }
            "2" { Get-OneDriveSecurityReport; Read-Host "Press Enter to continue" }
            "3" { Get-DLPPolicyReport; Read-Host "Press Enter to continue" }
            "4" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-AzureKQLQueriesMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure KQL Queries" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan
        Write-Host "1. Run Custom KQL Query"
        Write-Host "2. Compute Queries"
        Write-Host "2. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-2)"
        
        switch ($Choice) {
            "1" { Read-Host "Press Enter to continue" }
            "2" { Show-AzureComputeKQLQueriesMenu }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-AzureComputeKQLQueriesMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure Compute KQL Queries" -ForegroundColor Cyan
        Write-Host "===========================" -ForegroundColor Cyan
        Write-Host "1. Get VM DCR Associations"
        Write-Host "2. Return to KQL Queries Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-2)"
        
        switch ($Choice) {
            "1" { Get-AzureComputeDCRReport; Read-Host "Press Enter to continue" }
            "2" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Main menu
function Show-MainMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "1. Identity and Access Management Report (Entra ID)"
        Write-Host "2. Data Protection Report (Azure)"
        Write-Host "3. Azure Infrastructure Security Report"
        Write-Host "4. Office 365 Security Report"
        Write-Host "5. SharePoint & OneDrive Security Report"
        Write-Host "6. Azure KQL Queries"
        Write-Host "7. Settings & Configuration"
        Write-Host "Q. Exit"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-6, Q)"
        
        switch ($Choice) {
            "1" { Show-IAMMenu }
            "2" { Show-DataProtectionMenu }
            "3" { Show-InfrastructureSecurityMenu }
            "4" { Show-Office365Menu }
            "5" { Show-SharePointMenu }
            "6" { Show-AzureKQLQueriesMenu }
            "7" { Show-SettingsMenu }
            "Q" { 
                Write-ColorOutput "Thank you for using Azure & Office 365 Security Report!" "Green"
                Write-ColorOutput "Log file saved as: $script:LogFile" "Yellow"
                return 
            }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Main script execution
function Main {
    Show-Title
    Write-Log "Azure Security Report (Modular) v3.5 started" "INFO"
    
    # Initialize configuration
    Initialize-SecurityConfig | Out-Null
    $Config = Get-SecurityConfig
    
    # Required modules for this script
    $RequiredModules = @(
        "Az.Accounts", 
        "Az.Compute", 
        "Az.Security",
        "Az.ResourceGraph",
        "Az.KeyVault",
        "Az.Network",
        "Az.Storage",
        "Microsoft.Graph.Users", 
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Reports",
        "Microsoft.Graph.Sites",
        "ExchangeOnlineManagement",
        "MicrosoftTeams"
    )
    
    # Check required modules
    if (-not (Test-RequiredModules -RequiredModules $RequiredModules)) {
        Write-Log "Module check failed. Exiting." "ERROR"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Try auto-connect if configured
    $AutoConnected = $false
    if ($Config.AutoConnect -and $Config.UseServicePrincipal) {
        Write-ColorOutput "Attempting auto-connect using saved configuration..." "Yellow"
        $AutoConnected = Connect-UsingConfig
    }
    
    # Manual authentication if auto-connect failed or not configured
    if (-not $AutoConnected) {
        Write-ColorOutput "Using interactive authentication..." "Yellow"
        if (-not (Connect-AzureServices)) {
            Write-Log "Authentication failed. Exiting." "ERROR"
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
    
    Write-ColorOutput "Authentication successful. Starting security audit..." "Green"
    Start-Sleep 2
    
    # Show main menu
    Show-MainMenu
    
    Write-Log "Azure Security Report completed" "INFO"
}

# Start the script
Main

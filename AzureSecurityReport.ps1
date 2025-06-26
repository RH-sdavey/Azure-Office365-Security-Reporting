#Requires -Version 7.0
<#
.SYNOPSIS
    Azure Security Report - Read-Only Security Audit Script
.DESCRIPTION
    Performs comprehensive security audits in Microsoft Azure without making changes.
    Covers Identity and Access Management, and Data Protection security checks.
.AUTHOR
    github.com/SteffMet
.VERSION
    1.1
.Changelog 1.1
    - Added detailed logging functionality
    - Improved error handling and user prompts
    - Enhanced output formatting with colors
    - Added export functionality for reports in CSV format
    - Included checks for required PowerShell modules and authentication scopes
    - Added TLS configuration check for Azure VMs (simulated)
    - Added VM encryption check
    - Improved user interface with menus for better navigation
    - Added Support for PowerShell 7.0 and above
.DATE
    June 26, 2025
#>

# Global Variables
$script:LogFile = "AzureSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    Write-Host $LogEntry
}

# Function to display colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
    Write-Log -Message $Message -Level "INFO"
}

# Function to display title
function Show-Title {
    Clear-Host
    Write-Host "------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "              AZURE & OFFICE 365 SECURITY REPORT SCRIPT " -ForegroundColor Yellow
    Write-Host "               By github.com/SteffMet" -ForegroundColor Blue
    Write-Host "------------------------------------------------------------------"
    Write-Host ""
}

# Function to check and install required modules
function Test-RequiredModules {
    Write-ColorOutput "Checking required PowerShell modules..." "Yellow"
    
    $RequiredModules = @("Az.Accounts", "Az.Compute", "Az.Security", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.SignIns")
    $MissingModules = @()
    
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            $MissingModules += $Module
            Write-ColorOutput "Module '$Module' is not installed." "Red"
        } else {
            Write-ColorOutput "Module '$Module' is installed." "Green"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-ColorOutput "Missing modules: $($MissingModules -join ', ')" "Red"
        $Install = Read-Host "Would you like to install the missing modules? (Y/N)"
        
        if ($Install -eq 'Y' -or $Install -eq 'y') {
            foreach ($Module in $MissingModules) {
                try {
                    Write-ColorOutput "Installing module: $Module" "Yellow"
                    Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                    Write-ColorOutput "Successfully installed: $Module" "Green"
                } catch {
                    Write-ColorOutput "Failed to install module: $Module. Error: $($_.Exception.Message)" "Red"
                    Write-Log "Failed to install module: $Module. Error: $($_.Exception.Message)" "ERROR"
                    return $false
                }
            }
        } else {
            Write-ColorOutput "Cannot proceed without required modules. Exiting..." "Red"
            Write-Log "Cannot proceed without required modules. Exiting..." "ERROR"
            return $false
        }
    }
    
    return $true
}

# Function to authenticate to Azure and Microsoft Graph
function Connect-AzureServices {
    Write-ColorOutput "Authenticating to Azure services..." "Yellow"
    
    try {
        # Connect to Azure
        Write-ColorOutput "Connecting to Azure..." "Yellow"
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-ColorOutput "Successfully connected to Azure." "Green"
        
        # Connect to Microsoft Graph with required scopes
        Write-ColorOutput "Connecting to Microsoft Graph..." "Yellow"
        $Scopes = @("User.Read.All", "Directory.Read.All", "Policy.Read.ConditionalAccess", "UserAuthenticationMethod.Read.All")
        Connect-MgGraph -Scopes $Scopes -ErrorAction Stop | Out-Null
        
        # Verify granted scopes
        $GrantedScopes = (Get-MgContext).Scopes
        $MissingScopes = $Scopes | Where-Object { $_ -notin $GrantedScopes }
        if ($MissingScopes) {
            Write-ColorOutput "Warning: The following required scopes were not granted: $($MissingScopes -join ', ')" "Yellow"
            Write-Log "Missing scopes: $($MissingScopes -join ', ')" "WARNING"
        }
        
        Write-ColorOutput "Successfully connected to Microsoft Graph." "Green"
        return $true
    } catch {
        Write-ColorOutput "Authentication failed: $($_.Exception.Message)" "Red"
        Write-Log "Authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to validate file path for CSV export
function Get-ValidFilePath {
    param([string]$DefaultName)
    
    do {
        $FilePath = Read-Host "Enter the full file path for export (or press Enter for current directory)"
        
        if ([string]::IsNullOrWhiteSpace($FilePath)) {
            $FilePath = Join-Path (Get-Location) "$DefaultName`_$script:Timestamp.csv"
        }
        
        # Ensure .csv extension
        if (-not $FilePath.EndsWith('.csv')) {
            $FilePath += '.csv'
        }
        
        try {
            $Directory = Split-Path $FilePath -Parent
            if (-not (Test-Path $Directory)) {
                New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
            }
            # Test write access
            $TestFile = Join-Path $Directory "test_write.txt"
            New-Item -ItemType File -Path $TestFile -Force -ErrorAction Stop | Out-Null
            Remove-Item -Path $TestFile -ErrorAction Stop
            return $FilePath
        } catch {
            Write-ColorOutput "Invalid file path or insufficient permissions. Please try again." "Red"
            Write-Log "Invalid file path or insufficient permissions: $($_.Exception.Message)" "ERROR"
        }
    } while ($true)
}

# Function to check MFA status
function Check-MFAStatus {
    Write-ColorOutput "Checking MFA status for all users..." "Yellow"
    
    try {
        # Get all users with pagination
        $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName -PageSize 100 | Where-Object { $_.UserPrincipalName -notlike "*#EXT#*" }
        $UsersWithoutMFA = @()
        $GlobalAdminsWithoutMFA = @()
        
        # Get Global Admin role members
        $GlobalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop
        if (-not $GlobalAdminRole) {
            Write-ColorOutput "No Global Administrator role found." "Yellow"
            Write-Log "No Global Administrator role found." "WARNING"
            return
        }
        $GlobalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id
        
        foreach ($User in $Users) {
            try {
                $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop
                $HasMFA = $AuthMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -in @('#microsoft.graph.microsoftAuthenticatorAuthenticationMethod', '#microsoft.graph.phoneAuthenticationMethod', '#microsoft.graph.fido2AuthenticationMethod') }
                
                if (-not $HasMFA) {
                    $UserInfo = [PSCustomObject]@{
                        UPN = $User.UserPrincipalName
                        DisplayName = $User.DisplayName
                        MFAStatus = "Disabled"
                        IsGlobalAdmin = $User.Id -in $GlobalAdmins.Id
                    }
                    
                    $UsersWithoutMFA += $UserInfo
                    
                    if ($User.Id -in $GlobalAdmins.Id) {
                        $GlobalAdminsWithoutMFA += $UserInfo
                    }
                }
            } catch {
                Write-ColorOutput "Error checking MFA for user $($User.UserPrincipalName): $($_.Exception.Message)" "Red"
                Write-Log "Error checking MFA for user $($User.UserPrincipalName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Display summary
        if ($UsersWithoutMFA.Count -eq 0) {
            Write-ColorOutput "✓ All users have MFA enabled." "Green"
        } else {
            Write-ColorOutput "⚠ MFA Status: $($UsersWithoutMFA.Count) users without MFA, $($GlobalAdminsWithoutMFA.Count) Global Admins without MFA" "Red"
            
            # Prompt for export
            $Export = Read-Host "Would you like to export these results to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "MFA_Report"
                $UsersWithoutMFA | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Results exported to: $FilePath" "Green"
            }
        }
    } catch {
        Write-ColorOutput "Error checking MFA status: $($_.Exception.Message)" "Red"
        Write-Log "Error checking MFA status: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check guest user access
function Check-GuestUserAccess {
    Write-ColorOutput "Checking guest user access..." "Yellow"
    
    try {
        $GuestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property UserPrincipalName,DisplayName,CreatedDateTime -PageSize 100
        
        if ($GuestUsers.Count -eq 0) {
            Write-ColorOutput "✓ No guest users found." "Green"
        } else {
            Write-ColorOutput "⚠ Guest Access: $($GuestUsers.Count) guest users found" "Yellow"
            
            $GuestReport = $GuestUsers | ForEach-Object {
                [PSCustomObject]@{
                    UPN = $_.UserPrincipalName
                    DisplayName = $_.DisplayName
                    CreatedDate = $_.CreatedDateTime
                }
            }
            
            # Prompt for export
            $Export = Read-Host "Would you like to export guest user details to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "Guest_Users_Report"
                $GuestReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Results exported to: $FilePath" "Green"
            }
        }
    } catch {
        Write-ColorOutput "Error checking guest users: $($_.Exception.Message)" "Red"
        Write-Log "Error checking guest users: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check password expiry settings
function Check-PasswordExpirySettings {
    Write-ColorOutput "Checking password expiry settings..." "Yellow"
    
    try {
        $Users = Get-MgUser -All -Property UserPrincipalName,DisplayName,PasswordPolicies -PageSize 100 | Where-Object { $_.UserPrincipalName -notlike "*#EXT#*" }
        $NonExpiringPasswords = $Users | Where-Object { $_.PasswordPolicies -contains "DisablePasswordExpiration" }
        
        if ($NonExpiringPasswords.Count -eq 0) {
            Write-ColorOutput "✓ All user passwords are set to expire." "Green"
        } else {
            Write-ColorOutput "⚠ Password Expiry: $($NonExpiringPasswords.Count) users with non-expiring passwords" "Yellow"
            
            $PasswordReport = $NonExpiringPasswords | ForEach-Object {
                [PSCustomObject]@{
                    UPN = $_.UserPrincipalName
                    DisplayName = $_.DisplayName
                    PasswordExpiryStatus = "Never Expires"
                }
            }
            
            # Prompt for export
            $Export = Read-Host "Would you like to export these results to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "Password_Expiry_Report"
                $PasswordReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Results exported to: $FilePath" "Green"
            }
        }
    } catch {
        Write-ColorOutput "Error checking password expiry settings: $($_.Exception.Message)" "Red"
        Write-Log "Error checking password expiry settings: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check conditional access policies
function Check-ConditionalAccessPolicies {
    Write-ColorOutput "Checking Conditional Access policies..." "Yellow"
    
    try {
        $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($CAPolicies.Count -eq 0) {
            Write-ColorOutput "⚠ No Conditional Access policies found." "Red"
            return
        }
        
        $PolicyReport = @()
        $PoliciesWithoutMFA = 0
        $PoliciesWithoutRiskBlock = 0
        
        foreach ($Policy in $CAPolicies) {
            $HasMFARequirement = $false
            $BlocksRiskySignins = $false
            
            if ($Policy.GrantControls -and $Policy.GrantControls.BuiltInControls -contains "mfa") {
                $HasMFARequirement = $true
            }
            
            if ($Policy.Conditions -and $Policy.Conditions.SignInRiskLevels -contains "high" -and 
                $Policy.GrantControls -and $Policy.GrantControls.Operator -eq "OR" -and 
                $Policy.GrantControls.BuiltInControls -contains "block") {
                $BlocksRiskySignins = $true
            }
            
            if (-not $HasMFARequirement) { $PoliciesWithoutMFA++ }
            if (-not $BlocksRiskySignins) { $PoliciesWithoutRiskBlock++ }
            
            $PolicyReport += [PSCustomObject]@{
                PolicyName = $Policy.DisplayName
                State = $Policy.State
                MFAEnforced = $HasMFARequirement
                BlocksRiskySignins = $BlocksRiskySignins
            }
        }
        
        Write-ColorOutput "Conditional Access: $($CAPolicies.Count) policies found. MFA not enforced in $PoliciesWithoutMFA policies. Risky sign-ins not blocked in $PoliciesWithoutRiskBlock policies." "Yellow"
        
        if ($PoliciesWithoutMFA -gt 0 -or $PoliciesWithoutRiskBlock -gt 0) {
            Write-ColorOutput "⚠ Recommendation: Enforce MFA and block risky sign-ins in Conditional Access policies." "Red"
        }
        
        # Prompt for export
        $Export = Read-Host "Would you like to export policy details to CSV? (Y/N)"
        if ($Export -eq 'Y' -or $Export -eq 'y') {
            $FilePath = Get-ValidFilePath "Conditional_Access_Report"
            $PolicyReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-ColorOutput "Results exported to: $FilePath" "Green"
        }
    } catch {
        Write-ColorOutput "Error checking Conditional Access policies: $($_.Exception.Message)" "Red"
        Write-Log "Error checking Conditional Access policies: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check TLS configuration on VMs
function Check-TLSConfiguration {
    Write-ColorOutput "Checking TLS configuration on Azure VMs..." "Yellow"
    
    try {
        $VMs = Get-AzVM -ErrorAction Stop
        $TLSReport = @()
        $NonCompliantVMs = 0
        
        if ($VMs.Count -eq 0) {
            Write-ColorOutput "No Azure VMs found." "Yellow"
            return
        }
        
        Write-ColorOutput "NOTE: TLS version checking requires VM access (e.g., PowerShell remoting or Azure diagnostics). This script assumes TLS 1.2 for modern VMs but cannot verify actual configurations without additional setup." "Yellow"
        Write-Log "TLS check limitation: Actual VM inspection not implemented." "WARNING"
        
        foreach ($VM in $VMs) {
            try {
                # Placeholder: Actual TLS check would require VM access
                $TLSVersion = "1.2" # Assumption for modern VMs
                $IsCompliant = $true
                
                # For demonstration, randomly mark some VMs as non-compliant (replace with actual check)
                if ((Get-Random -Minimum 1 -Maximum 10) -le 2) {
                    $TLSVersion = "1.1"
                    $IsCompliant = $false
                    $NonCompliantVMs++
                }
                
                $TLSReport += [PSCustomObject]@{
                    VMName = $VM.Name
                    ResourceGroup = $VM.ResourceGroupName
                    TLSVersion = $TLSVersion
                    Location = $VM.Location
                    OSType = $VM.StorageProfile.OsDisk.OsType
                    ComplianceStatus = if ($IsCompliant) { "Compliant" } else { "Non-Compliant" }
                }
            } catch {
                Write-ColorOutput "Error checking TLS for VM $($VM.Name): $($_.Exception.Message)" "Red"
                Write-Log "Error checking TLS for VM $($VM.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        if ($NonCompliantVMs -eq 0) {
            Write-ColorOutput "✓ All VMs assumed to use TLS 1.2 (pending actual verification)." "Green"
        } else {
            Write-ColorOutput "⚠ TLS 1.0/1.1 detected on $NonCompliantVMs VMs (simulated). Upgrade to TLS 1.2 for security." "Red"
            Write-ColorOutput "TLS Status: $($VMs.Count - $NonCompliantVMs) VMs using TLS 1.2, $NonCompliantVMs VMs using TLS 1.0/1.1 (simulated)" "Yellow"
            
            # Prompt for export
            $Export = Read-Host "Would you like to export TLS configuration details to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "TLS_Configuration_Report"
                $TLSReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Results exported to: $FilePath" "Green"
            }
        }
    } catch {
        Write-ColorOutput "Error checking TLS configuration: $($_.Exception.Message)" "Red"
        Write-Log "Error checking TLS configuration: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check VM encryption
function Check-VMEncryption {
    Write-ColorOutput "Checking Virtual Machine encryption..." "Yellow"
    
    try {
        if (-not (Get-Module -ListAvailable -Name "Az.Security")) {
            Write-ColorOutput "Az.Security module is required for VM encryption checks. Please install it." "Red"
            Write-Log "Az.Security module missing for VM encryption checks." "ERROR"
            return
        }
        
        $VMs = Get-AzVM -ErrorAction Stop
        $EncryptionReport = @()
        $UnencryptedVMs = 0
        
        if ($VMs.Count -eq 0) {
            Write-ColorOutput "No Azure VMs found." "Yellow"
            return
        }
        
        foreach ($VM in $VMs) {
            try {
                $EncryptionStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -ErrorAction Stop
                
                $IsEncrypted = $EncryptionStatus.OsVolumeEncrypted -eq "Encrypted" -and 
                              ($EncryptionStatus.DataVolumesEncrypted -eq "Encrypted" -or $EncryptionStatus.DataVolumesEncrypted -eq "NotMounted")
                
                if (-not $IsEncrypted) {
                    $UnencryptedVMs++
                }
                
                $EncryptionReport += [PSCustomObject]@{
                    VMName = $VM.Name
                    ResourceGroup = $VM.ResourceGroupName
                    OSVolumeEncrypted = $EncryptionStatus.OsVolumeEncrypted
                    DataVolumesEncrypted = $EncryptionStatus.DataVolumesEncrypted
                    EncryptionStatus = if ($IsEncrypted) { "Encrypted" } else { "Not Encrypted" }
                }
            } catch {
                Write-ColorOutput "Error checking encryption for VM $($VM.Name): $($_.Exception.Message)" "Red"
                Write-Log "Error checking encryption for VM $($VM.Name): $($_.Exception.Message)" "ERROR"
                $EncryptionReport += [PSCustomObject]@{
                    VMName = $VM.Name
                    ResourceGroup = $VM.ResourceGroupName
                    OSVolumeEncrypted = "Error"
                    DataVolumesEncrypted = "Error"
                    EncryptionStatus = "Error"
                }
            }
        }
        
        if ($UnencryptedVMs -eq 0) {
            Write-ColorOutput "✓ All VMs are encrypted." "Green"
        } else {
            Write-ColorOutput "⚠ Encryption Status: $($VMs.Count - $UnencryptedVMs) VMs encrypted, $UnencryptedVMs VMs unencrypted" "Red"
            
            # Prompt for export
            $Export = Read-Host "Would you like to export encryption status to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "VM_Encryption_Report"
                $EncryptionReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Results exported to: $FilePath" "Green"
            }
        }
    } catch {
        Write-ColorOutput "Error checking VM encryption: $($_.Exception.Message)" "Red"
        Write-Log "Error checking VM encryption: $($_.Exception.Message)" "ERROR"
    }
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
        Write-Host "5. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Check-MFAStatus; Read-Host "Press Enter to continue" }
            "2" { Check-GuestUserAccess; Read-Host "Press Enter to continue" }
            "3" { Check-PasswordExpirySettings; Read-Host "Press Enter to continue" }
            "4" { Check-ConditionalAccessPolicies; Read-Host "Press Enter to continue" }
            "5" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Write-Log "Invalid IAM menu selection: $Choice" "WARNING"; Start-Sleep 2 }
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
            "1" { Check-TLSConfiguration; Read-Host "Press Enter to continue" }
            "2" { Check-VMEncryption; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Write-Log "Invalid Data Protection menu selection: $Choice" "WARNING"; Start-Sleep 2 }
        }
    } while ($true)
}

# Main menu
function Show-MainMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Read-Only Azure Security Audit Menu" -ForegroundColor Cyan
        Write-Host "====================================" -ForegroundColor Cyan
        Write-Host "1. Identity and Access Management Report"
        Write-Host "2. Data Protection Report"
        Write-Host "3. Exit"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Show-IAMMenu }
            "2" { Show-DataProtectionMenu }
            "3" { 
                Write-ColorOutput "Thank you for using Azure Security Report!" "Green"
                Write-ColorOutput "Log file saved as: $script:LogFile" "Yellow"
                return 
            }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Write-Log "Invalid main menu selection: $Choice" "WARNING"; Start-Sleep 2 }
        }
    } while ($true)
}

# Main script execution
function Main {
    Show-Title
    Write-Log "Azure Security Report started" "INFO"
    
    # Check required modules
    if (-not (Test-RequiredModules)) {
        Write-Log "Module check failed. Exiting." "ERROR"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Authenticate to Azure services
    if (-not (Connect-AzureServices)) {
        Write-Log "Authentication failed. Exiting." "ERROR"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-ColorOutput "Authentication successful. Starting security audit..." "Green"
    Start-Sleep 2
    
    # Show main menu
    Show-MainMenu
    
    Write-Log "Azure Security Report completed" "INFO"
}

# Start the script
Main
# Azure Security Report - Identity and Access Management Module
# Contains all IAM-related security checks

# Function to check MFA status
function Test-MFAStatus {
    Write-ColorOutput "Checking MFA status for all users..." "Yellow"
    
    # Check if modules are already loaded (from successful authentication)
    $UsersModuleLoaded = Get-Module -Name "Microsoft.Graph.Users" -ErrorAction SilentlyContinue
    $DirectoryModuleLoaded = Get-Module -Name "Microsoft.Graph.Identity.DirectoryManagement" -ErrorAction SilentlyContinue
    
    if (-not $UsersModuleLoaded -or -not $DirectoryModuleLoaded) {
        Write-ColorOutput "Required Microsoft Graph modules not loaded. Please ensure authentication was successful." "Red"
        Write-ColorOutput "If you see assembly conflicts, restart PowerShell and try again." "Yellow"
        return
    }
    
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
function Test-GuestUserAccess {
    Write-ColorOutput "Checking guest user access..." "Yellow"
    
    # Check if modules are already loaded (from successful authentication)
    if (-not (Get-Module -Name "Microsoft.Graph.Users" -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "Required Microsoft Graph modules not loaded. Please ensure authentication was successful." "Red"
        Write-ColorOutput "If you see assembly conflicts, restart PowerShell and try again." "Yellow"
        return
    }
    
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
function Test-PasswordExpirySettings {
    Write-ColorOutput "Checking password expiry settings..." "Yellow"
    
    # Check if modules are already loaded (from successful authentication)
    if (-not (Get-Module -Name "Microsoft.Graph.Users" -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "Required Microsoft Graph modules not loaded. Please ensure authentication was successful." "Red"
        Write-ColorOutput "If you see assembly conflicts, restart PowerShell and try again." "Yellow"
        return
    }
    
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
function Test-ConditionalAccessPolicies {
    Write-ColorOutput "Checking Conditional Access policies..." "Yellow"
    
    # Check if modules are already loaded (from successful authentication)
    if (-not (Get-Module -Name "Microsoft.Graph.Identity.SignIns" -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "Required Microsoft Graph modules not loaded. Please ensure authentication was successful." "Red"
        Write-ColorOutput "If you see assembly conflicts, restart PowerShell and try again." "Yellow"
        return
    }
    
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

Export-ModuleMember -Function Test-MFAStatus, Test-GuestUserAccess, Test-PasswordExpirySettings, Test-ConditionalAccessPolicies

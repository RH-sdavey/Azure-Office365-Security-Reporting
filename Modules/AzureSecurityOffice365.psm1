# Azure Security Report - Office 365 Module
# Contains all Office 365-related security checks

# Function to check Office 365 license usage
function Get-LicenseUsageReport {
    Write-ColorOutput "Retrieving Office 365 license usage..." "Yellow"
    
    # Check if modules are already loaded (from successful authentication)
    if (-not (Get-Module -Name "Microsoft.Graph.Identity.DirectoryManagement" -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "Required Microsoft Graph modules not loaded. Please ensure authentication was successful." "Red"
        Write-ColorOutput "If you see assembly conflicts, restart PowerShell and try again." "Yellow"
        return
    }
    
    try {
        # Get all SKUs (license types) in the tenant
        $SubscribedSkus = Get-MgSubscribedSku -All -ErrorAction Stop
        
        if ($SubscribedSkus.Count -eq 0) {
            Write-ColorOutput "No Office 365 licenses found in the tenant." "Yellow"
            return
        }
        
        $LicenseReport = @()
        $TotalUnassignedLicenses = 0
        $TotalWastedCost = 0
        
        foreach ($Sku in $SubscribedSkus) {
            $UnassignedCount = $Sku.PrepaidUnits.Enabled - $Sku.ConsumedUnits
            if ($UnassignedCount -lt 0) { $UnassignedCount = 0 }
            
            $TotalUnassignedLicenses += $UnassignedCount
            
            # Estimate cost impact (simplified calculation)
            $EstimatedMonthlyCostPerLicense = switch -Wildcard ($Sku.SkuPartNumber) {
                "*E5*" { 57 }
                "*E3*" { 36 }
                "*E1*" { 12 }
                "*BUSINESS_PREMIUM*" { 22 }
                "*BUSINESS_BASIC*" { 6 }
                "*EXCHANGESTANDARD*" { 4 }
                "*EXCHANGEONLINE*" { 8 }
                default { 15 }
            }
            
            $WastedCost = $UnassignedCount * $EstimatedMonthlyCostPerLicense
            $TotalWastedCost += $WastedCost
            
            $LicenseInfo = [PSCustomObject]@{
                SkuPartNumber = $Sku.SkuPartNumber
                SkuDisplayName = if ($Sku.ServicePlans) { ($Sku.ServicePlans | Select-Object -First 1).ServicePlanName } else { $Sku.SkuPartNumber }
                TotalLicenses = $Sku.PrepaidUnits.Enabled
                AssignedLicenses = $Sku.ConsumedUnits
                UnassignedLicenses = $UnassignedCount
                UtilizationPercentage = [math]::Round(($Sku.ConsumedUnits / $Sku.PrepaidUnits.Enabled) * 100, 2)
                EstimatedMonthlyCostPerLicense = $EstimatedMonthlyCostPerLicense
                PotentialMonthlySavings = $WastedCost
            }
            
            $LicenseReport += $LicenseInfo
            
            # Display individual license info
            if ($UnassignedCount -gt 0) {
                Write-ColorOutput "⚠ $($Sku.SkuPartNumber): $($Sku.ConsumedUnits) assigned, $UnassignedCount unassigned (Potential savings: `$$WastedCost/month)" "Yellow"
            } else {
                Write-ColorOutput "✓ $($Sku.SkuPartNumber): $($Sku.ConsumedUnits) assigned, 0 unassigned" "Green"
            }
        }
        
        # Display summary
        Write-Host ""
        Write-ColorOutput "=== LICENSE USAGE SUMMARY ===" "Cyan"
        Write-ColorOutput "Total SKUs: $($SubscribedSkus.Count)" "White"
        Write-ColorOutput "Total unassigned licenses: $TotalUnassignedLicenses" $(if ($TotalUnassignedLicenses -gt 0) { "Yellow" } else { "Green" })
        Write-ColorOutput "Estimated monthly savings if optimized: `$$TotalWastedCost" $(if ($TotalWastedCost -gt 0) { "Red" } else { "Green" })
        
        if ($TotalUnassignedLicenses -gt 0) {
            Write-ColorOutput "⚠ Recommendation: Review and remove unused licenses to optimize costs." "Red"
        }
        
        # Prompt for export
        $Export = Read-Host "Would you like to export license details to CSV? (Y/N)"
        if ($Export -eq 'Y' -or $Export -eq 'y') {
            $FilePath = Get-ValidFilePath "License_Usage_Report"
            $LicenseReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-ColorOutput "License report exported to: $FilePath" "Green"
        }
        
    } catch {
        Write-ColorOutput "Error retrieving license usage: $($_.Exception.Message)" "Red"
        Write-Log "Error retrieving license usage: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check inactive accounts
function Get-InactiveAccountsReport {
    Write-ColorOutput "Checking for inactive user accounts (90+ days)..." "Yellow"
    
    try {
        # Calculate date 90 days ago
        $InactiveThreshold = (Get-Date).AddDays(-90)
        Write-ColorOutput "Checking for accounts inactive since: $($InactiveThreshold.ToString('yyyy-MM-dd'))" "Cyan"
        
        # Get all users with sign-in activity
        $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,AssignedLicenses,SignInActivity -PageSize 100 | 
                 Where-Object { $_.UserPrincipalName -notlike "*#EXT#*" -and $_.AccountEnabled -eq $true }
        
        $InactiveUsers = @()
        $InactiveUsersWithLicenses = @()
        
        foreach ($User in $Users) {
            try {
                $LastSignIn = $null
                $IsInactive = $false
                
                # Check sign-in activity
                if ($User.SignInActivity -and $User.SignInActivity.LastSignInDateTime) {
                    $LastSignIn = [DateTime]$User.SignInActivity.LastSignInDateTime
                    $IsInactive = $LastSignIn -lt $InactiveThreshold
                } else {
                    # No sign-in data available - consider as inactive
                    $IsInactive = $true
                }
                
                if ($IsInactive) {
                    $HasLicenses = $User.AssignedLicenses -and $User.AssignedLicenses.Count -gt 0
                    
                    $UserInfo = [PSCustomObject]@{
                        UPN = $User.UserPrincipalName
                        DisplayName = $User.DisplayName
                        LastSignInDate = if ($LastSignIn) { $LastSignIn.ToString('yyyy-MM-dd') } else { "Never" }
                        DaysInactive = if ($LastSignIn) { ([DateTime]::Now - $LastSignIn).Days } else { "Unknown" }
                        HasAssignedLicenses = $HasLicenses
                        LicenseCount = if ($User.AssignedLicenses) { $User.AssignedLicenses.Count } else { 0 }
                        AccountEnabled = $User.AccountEnabled
                    }
                    
                    $InactiveUsers += $UserInfo
                    
                    if ($HasLicenses) {
                        $InactiveUsersWithLicenses += $UserInfo
                    }
                }
            } catch {
                Write-Log "Error checking sign-in for user $($User.UserPrincipalName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Display summary
        Write-Host ""
        Write-ColorOutput "=== INACTIVE ACCOUNTS SUMMARY ===" "Cyan"
        
        if ($InactiveUsers.Count -eq 0) {
            Write-ColorOutput "✓ No inactive accounts found (all users active within 90 days)." "Green"
        } else {
            Write-ColorOutput "⚠ Inactive Accounts: $($InactiveUsers.Count) users have not signed in for 90+ days" "Yellow"
            
            if ($InactiveUsersWithLicenses.Count -gt 0) {
                Write-ColorOutput "🚨 Critical: $($InactiveUsersWithLicenses.Count) inactive accounts have active licenses assigned!" "Red"
                
                # Calculate potential license cost savings
                $TotalLicenses = ($InactiveUsersWithLicenses | Measure-Object -Property LicenseCount -Sum).Sum
                $EstimatedMonthlySavings = $TotalLicenses * 25  # Estimated average license cost
                Write-ColorOutput "💰 Potential monthly savings: `$$EstimatedMonthlySavings (estimated)" "Red"
            }
            
            # Prompt for export
            $Export = Read-Host "Would you like to export inactive accounts to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "Inactive_Accounts_Report"
                $InactiveUsers | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Inactive accounts report exported to: $FilePath" "Green"
            }
        }
        
    } catch {
        Write-ColorOutput "Error checking inactive accounts: $($_.Exception.Message)" "Red"
        Write-Log "Error checking inactive accounts: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check mailbox forwarding rules
function Get-MailboxForwardingReport {
    Write-ColorOutput "Checking mailbox forwarding rules..." "Yellow"
    
    try {
        # Check if Exchange Online module is available
        if (-not (Get-Module -ListAvailable -Name "ExchangeOnlineManagement")) {
            Write-ColorOutput "ExchangeOnlineManagement module is required for mailbox checks. Please install it with: Install-Module ExchangeOnlineManagement" "Red"
            return
        }
        
        # Connect to Exchange Online if not already connected
        try {
            Get-OrganizationConfig -ErrorAction Stop | Out-Null
        } catch {
            Write-ColorOutput "Connecting to Exchange Online..." "Yellow"
            Connect-ExchangeOnline -ShowProgress $false -ErrorAction Stop
        }
        
        # Get all mailboxes with forwarding configured
        $Mailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object { 
            $_.ForwardingAddress -or $_.ForwardingSmtpAddress -or $_.DeliverToMailboxAndForward 
        }
        
        $ForwardingReport = @()
        $ExternalForwarding = @()
        
        foreach ($Mailbox in $Mailboxes) {
            $ForwardingType = "None"
            $ForwardingDestination = ""
            $IsExternal = $false
            
            if ($Mailbox.ForwardingAddress) {
                $ForwardingType = "Internal"
                $ForwardingDestination = $Mailbox.ForwardingAddress
            } elseif ($Mailbox.ForwardingSmtpAddress) {
                $ForwardingType = "SMTP"
                $ForwardingDestination = $Mailbox.ForwardingSmtpAddress
                # Check if external domain
                $Domain = ($Mailbox.ForwardingSmtpAddress -split "@")[1]
                $AcceptedDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
                $IsExternal = $Domain -notin $AcceptedDomains
            }
            
            $ForwardingInfo = [PSCustomObject]@{
                Mailbox = $Mailbox.UserPrincipalName
                DisplayName = $Mailbox.DisplayName
                ForwardingType = $ForwardingType
                ForwardingDestination = $ForwardingDestination
                DeliverToMailboxAndForward = $Mailbox.DeliverToMailboxAndForward
                IsExternalForwarding = $IsExternal
                MailboxType = $Mailbox.RecipientTypeDetails
            }
            
            $ForwardingReport += $ForwardingInfo
            
            if ($IsExternal) {
                $ExternalForwarding += $ForwardingInfo
            }
        }
        
        # Display summary
        Write-Host ""
        Write-ColorOutput "=== MAILBOX FORWARDING SUMMARY ===" "Cyan"
        
        if ($ForwardingReport.Count -eq 0) {
            Write-ColorOutput "✓ No mailbox forwarding rules found." "Green"
        } else {
            Write-ColorOutput "📧 Total mailboxes with forwarding: $($ForwardingReport.Count)" "Yellow"
            Write-ColorOutput "🌐 External forwarding rules: $($ExternalForwarding.Count)" $(if ($ExternalForwarding.Count -gt 0) { "Red" } else { "Green" })
            
            if ($ExternalForwarding.Count -gt 0) {
                Write-ColorOutput "🚨 Warning: External email forwarding detected! This could be a security risk." "Red"
                Write-ColorOutput "⚠ Recommendation: Review and validate all external forwarding rules." "Red"
            }
            
            # Prompt for export
            $Export = Read-Host "Would you like to export forwarding rules to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "Mailbox_Forwarding_Report"
                $ForwardingReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Mailbox forwarding report exported to: $FilePath" "Green"
            }
        }
        
    } catch {
        Write-ColorOutput "Error checking mailbox forwarding: $($_.Exception.Message)" "Red"
        Write-Log "Error checking mailbox forwarding: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check Teams external access settings
function Get-TeamsExternalAccessReport {
    Write-ColorOutput "Checking Microsoft Teams external access settings..." "Yellow"
    
    try {
        # Check if Teams module is available
        if (-not (Get-Module -ListAvailable -Name "MicrosoftTeams")) {
            Write-ColorOutput "MicrosoftTeams module is required for Teams checks. Please install it with: Install-Module MicrosoftTeams" "Red"
            return
        }
        
        # Connect to Teams if not already connected
        try {
            Get-CsTenant -ErrorAction Stop | Out-Null
        } catch {
            Write-ColorOutput "Connecting to Microsoft Teams..." "Yellow"
            Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
        }
        
        # Get external access configuration
        $ExternalAccessConfig = Get-CsTenantFederationConfiguration
        $GuestAccessConfig = Get-CsTeamsGuestCallingConfiguration
        $ClientConfig = Get-CsTeamsClientConfiguration
        
        Write-Host ""
        Write-ColorOutput "=== TEAMS EXTERNAL ACCESS CONFIGURATION ===" "Cyan"
        
        # Check federation settings
        if ($ExternalAccessConfig.AllowFederatedUsers) {
            Write-ColorOutput "🌐 External Access (Federation): ENABLED" "Yellow"
            Write-ColorOutput "   - Public Cloud Federation: $($ExternalAccessConfig.AllowPublicUsers)" "White"
            Write-ColorOutput "   - Skype Consumer: $($ExternalAccessConfig.AllowTeamsConsumer)" "White"
        } else {
            Write-ColorOutput "✓ External Access (Federation): DISABLED" "Green"
        }
        
        # Check guest access
        if ($GuestAccessConfig.AllowPrivateCalling) {
            Write-ColorOutput "👥 Guest Calling: ENABLED" "Yellow"
        } else {
            Write-ColorOutput "✓ Guest Calling: DISABLED" "Green"
        }
        
        # Check external app access
        if ($ClientConfig.AllowExternalApps) {
            Write-ColorOutput "📱 External Apps: ENABLED" "Yellow"
        } else {
            Write-ColorOutput "✓ External Apps: DISABLED" "Green"
        }
        
        # Create report object
        $AccessReport = [PSCustomObject]@{
            FederationEnabled = $ExternalAccessConfig.AllowFederatedUsers
            PublicCloudFederation = $ExternalAccessConfig.AllowPublicUsers
            SkypeConsumerEnabled = $ExternalAccessConfig.AllowTeamsConsumer
            GuestCallingEnabled = $GuestAccessConfig.AllowPrivateCalling
            ExternalAppsEnabled = $ClientConfig.AllowExternalApps
            LastChecked = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        }
        
        # Security assessment
        $SecurityScore = 0
        if (-not $ExternalAccessConfig.AllowFederatedUsers) { $SecurityScore += 20 }
        if (-not $ExternalAccessConfig.AllowPublicUsers) { $SecurityScore += 20 }
        if (-not $ExternalAccessConfig.AllowTeamsConsumer) { $SecurityScore += 20 }
        if (-not $GuestAccessConfig.AllowPrivateCalling) { $SecurityScore += 20 }
        if (-not $ClientConfig.AllowExternalApps) { $SecurityScore += 20 }
        
        Write-Host ""
        Write-ColorOutput "🛡️ Security Score: $SecurityScore/100" $(if ($SecurityScore -ge 80) { "Green" } elseif ($SecurityScore -ge 60) { "Yellow" } else { "Red" })
        
        if ($SecurityScore -lt 80) {
            Write-ColorOutput "⚠ Recommendation: Consider restricting external access to improve security posture." "Yellow"
        }
        
        # Prompt for export
        $Export = Read-Host "Would you like to export Teams access configuration to CSV? (Y/N)"
        if ($Export -eq 'Y' -or $Export -eq 'y') {
            $FilePath = Get-ValidFilePath "Teams_External_Access_Report"
            $AccessReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-ColorOutput "Teams external access report exported to: $FilePath" "Green"
        }
        
    } catch {
        Write-ColorOutput "Error checking Teams external access: $($_.Exception.Message)" "Red"
        Write-Log "Error checking Teams external access: $($_.Exception.Message)" "ERROR"
    }
}

# Function to get Teams with external users
function Get-TeamsWithExternalUsersReport {
    Write-ColorOutput "Checking Teams with external users and guests..." "Yellow"
    
    try {
        # Check if Teams module is available
        if (-not (Get-Module -ListAvailable -Name "MicrosoftTeams")) {
            Write-ColorOutput "MicrosoftTeams module is required for Teams checks. Please install it with: Install-Module MicrosoftTeams" "Red"
            return
        }
        
        # Connect to Teams if not already connected
        try {
            Get-CsTenant -ErrorAction Stop | Out-Null
        } catch {
            Write-ColorOutput "Connecting to Microsoft Teams..." "Yellow"
            Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
        }
        
        # Get all teams
        $Teams = Get-Team
        $TeamsWithExternalUsers = @()
        $TotalExternalUsers = 0
        
        Write-ColorOutput "Scanning $($Teams.Count) teams for external users..." "Yellow"
        
        foreach ($Team in $Teams) {
            try {
                # Get team members
                $TeamUsers = Get-TeamUser -GroupId $Team.GroupId
                $ExternalUsers = $TeamUsers | Where-Object { $_.User -like "*#EXT#*" -or $_.Role -eq "Guest" }
                
                if ($ExternalUsers.Count -gt 0) {
                    $TotalExternalUsers += $ExternalUsers.Count
                    
                    $TeamInfo = [PSCustomObject]@{
                        TeamName = $Team.DisplayName
                        TeamId = $Team.GroupId
                        Visibility = $Team.Visibility
                        TotalMembers = $TeamUsers.Count
                        ExternalUsers = $ExternalUsers.Count
                        ExternalUsersList = ($ExternalUsers | ForEach-Object { $_.User }) -join "; "
                        LastChecked = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    }
                    
                    $TeamsWithExternalUsers += $TeamInfo
                }
            } catch {
                Write-Log "Error checking team $($Team.DisplayName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Display summary
        Write-Host ""
        Write-ColorOutput "=== TEAMS EXTERNAL USERS SUMMARY ===" "Cyan"
        
        if ($TeamsWithExternalUsers.Count -eq 0) {
            Write-ColorOutput "✓ No teams with external users found." "Green"
        } else {
            Write-ColorOutput "👥 Teams with external users: $($TeamsWithExternalUsers.Count)" "Yellow"
            Write-ColorOutput "🌐 Total external users across all teams: $TotalExternalUsers" "Yellow"
            
            # Show top teams with most external users
            $TopTeams = $TeamsWithExternalUsers | Sort-Object ExternalUsers -Descending | Select-Object -First 5
            Write-Host ""
            Write-ColorOutput "Top teams with external users:" "Cyan"
            foreach ($Team in $TopTeams) {
                Write-ColorOutput "  • $($Team.TeamName): $($Team.ExternalUsers) external users" "White"
            }
            
            Write-Host ""
            Write-ColorOutput "⚠ Recommendation: Review external user access and ensure appropriate governance." "Yellow"
            
            # Prompt for export
            $Export = Read-Host "Would you like to export teams with external users to CSV? (Y/N)"
            if ($Export -eq 'Y' -or $Export -eq 'y') {
                $FilePath = Get-ValidFilePath "Teams_External_Users_Report"
                $TeamsWithExternalUsers | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
                Write-ColorOutput "Teams external users report exported to: $FilePath" "Green"
            }
        }
        
    } catch {
        Write-ColorOutput "Error checking Teams external users: $($_.Exception.Message)" "Red"
        Write-Log "Error checking Teams external users: $($_.Exception.Message)" "ERROR"
    }
}

Export-ModuleMember -Function Get-LicenseUsageReport, Get-InactiveAccountsReport, Get-MailboxForwardingReport, Get-TeamsExternalAccessReport, Get-TeamsWithExternalUsersReport

# Azure Security Report - SharePoint & OneDrive Security Module
# Contains SharePoint Online and OneDrive security assessment functions

# Function to check SharePoint sharing settings
function Get-SharePointSharingReport {
    Write-ColorOutput "Analyzing SharePoint Online Sharing Settings..." "Yellow"
    Write-Log "Starting SharePoint Sharing Analysis" "INFO"
    
    try {
        # Connect to SharePoint Admin if not already connected
        try {
            $AdminUrl = (Get-MgOrganization).DisplayName
            if (-not $AdminUrl) {
                throw "Unable to determine tenant admin URL"
            }
        }
        catch {
            Write-ColorOutput "Unable to connect to SharePoint Admin. Please ensure you have SharePoint Administrator permissions." "Red"
            return
        }
        
        # Get sharing settings using Microsoft Graph
        $SharePointSettings = @()
        $Sites = @()
        
        try {
            # Get all SharePoint sites
            $Sites = Get-MgSite -All -Property "Id,Name,WebUrl,CreatedDateTime,LastModifiedDateTime"
            Write-ColorOutput "Found $($Sites.Count) SharePoint sites" "Green"
        }
        catch {
            Write-ColorOutput "Error retrieving SharePoint sites: $($_.Exception.Message)" "Red"
            Write-Log "Error retrieving SharePoint sites: $($_.Exception.Message)" "ERROR"
        }
        
        $SecurityFindings = @()
        $Counter = 0
        
        Write-Host ""
        Write-Host "=== SHAREPOINT SHARING SECURITY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        # Analyze tenant-level settings first
        Write-Host "Analyzing tenant-level sharing settings..." -ForegroundColor Yellow
        
        # Get organization settings
        try {
            $OrgSettings = Get-MgOrganization -Property "Id,DisplayName"
            
            # Create tenant-level finding
            $TenantFinding = [PSCustomObject]@{
                SiteName = "TENANT LEVEL"
                SiteUrl = "N/A"
                SiteType = "Tenant"
                CreatedDate = "N/A"
                LastModified = "N/A"
                ExternalSharingEnabled = "Unknown - Requires SharePoint Admin Module"
                GuestAccessEnabled = "Unknown - Requires SharePoint Admin Module"
                AnonymousLinksEnabled = "Unknown - Requires SharePoint Admin Module"
                RiskLevel = "Medium"
                Issues = "Manual review required for tenant-level settings"
                Recommendations = "Review SharePoint Admin Center for external sharing settings"
            }
            
            $SecurityFindings += $TenantFinding
            Write-Host "[MANUAL REVIEW] Tenant Level - Check SharePoint Admin Center" -ForegroundColor Yellow
        }
        catch {
            Write-Log "Could not retrieve tenant settings: $($_.Exception.Message)" "WARNING"
        }
        
        # Analyze individual sites (sample of first 50 sites for performance)
        $SitesToAnalyze = $Sites | Select-Object -First 50
        $TotalSites = $SitesToAnalyze.Count
        
        foreach ($Site in $SitesToAnalyze) {
            $Counter++
            Write-Progress -Activity "Analyzing SharePoint Sites" -Status "Processing $($Site.Name)" -PercentComplete (($Counter / $TotalSites) * 100)
            
            try {
                # Basic site information
                $SiteName = $Site.Name
                $SiteUrl = $Site.WebUrl
                $CreatedDate = $Site.CreatedDateTime
                $LastModified = $Site.LastModifiedDateTime
                
                # For demonstration, we'll analyze what we can through Graph API
                # Real sharing settings would require SharePoint CSOM or PnP PowerShell
                
                $RiskLevel = "Low"
                $Issues = @()
                $Recommendations = @()
                
                # Check if site is recently created (might need attention)
                if ($CreatedDate -and $CreatedDate -gt (Get-Date).AddDays(-30)) {
                    $Issues += "Recently created site (within 30 days)"
                    $Recommendations += "Review sharing settings for new site"
                }
                
                # Check site URL for potential issues
                if ($SiteUrl -like "*personal*") {
                    $RiskLevel = "Medium"
                    $Issues += "OneDrive personal site detected"
                    $Recommendations += "Review OneDrive sharing policies"
                }
                
                # Create finding
                $Finding = [PSCustomObject]@{
                    SiteName = $SiteName
                    SiteUrl = $SiteUrl
                    SiteType = if ($SiteUrl -like "*personal*") { "OneDrive" } else { "SharePoint" }
                    CreatedDate = if ($CreatedDate) { $CreatedDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                    LastModified = if ($LastModified) { $LastModified.ToString("yyyy-MM-dd") } else { "Unknown" }
                    ExternalSharingEnabled = "Requires SharePoint Admin Module"
                    GuestAccessEnabled = "Requires SharePoint Admin Module"
                    AnonymousLinksEnabled = "Requires SharePoint Admin Module"
                    RiskLevel = $RiskLevel
                    Issues = ($Issues -join '; ')
                    Recommendations = ($Recommendations -join '; ')
                }
                
                $SecurityFindings += $Finding
                
            }
            catch {
                Write-Log "Error analyzing site $($Site.Name): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-Progress -Activity "Analyzing SharePoint Sites" -Completed
        
        # Summary
        Write-Host ""
        Write-Host "=== SHAREPOINT SHARING SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total Sites Analyzed: $($SecurityFindings.Count)"
        Write-Host "SharePoint Sites: $($SecurityFindings | Where-Object {$_.SiteType -eq 'SharePoint'} | Measure-Object | Select-Object -ExpandProperty Count)"
        Write-Host "OneDrive Sites: $($SecurityFindings | Where-Object {$_.SiteType -eq 'OneDrive'} | Measure-Object | Select-Object -ExpandProperty Count)"
        Write-Host ""
        Write-Host "⚠️  IMPORTANT NOTE:" -ForegroundColor Yellow
        Write-Host "   Full SharePoint sharing analysis requires additional modules:" -ForegroundColor Yellow
        Write-Host "   - PnP.PowerShell" -ForegroundColor Yellow
        Write-Host "   - SharePoint Online Management Shell" -ForegroundColor Yellow
        Write-Host "   This report provides basic site enumeration only." -ForegroundColor Yellow
        
        # Export to CSV
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "SharePoint_Sharing_Report_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $SecurityFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "Report exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export report: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "SharePoint Sharing Analysis completed" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during SharePoint Sharing Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during SharePoint Sharing Analysis: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check OneDrive usage and security
function Get-OneDriveSecurityReport {
    Write-ColorOutput "Analyzing OneDrive Security and Usage..." "Yellow"
    Write-Log "Starting OneDrive Security Analysis" "INFO"
    
    try {
        # Get OneDrive usage report
        $OneDriveUsage = @()
        
        try {
            # Get OneDrive usage using Microsoft Graph Reports
            $UsageReport = Get-MgReportOneDriveUsageAccountDetail -Period D30
            
            if ($UsageReport) {
                $OneDriveUsage = $UsageReport | ConvertFrom-Csv
                Write-ColorOutput "Retrieved OneDrive usage data for $($OneDriveUsage.Count) users" "Green"
            } else {
                Write-ColorOutput "No OneDrive usage data available" "Yellow"
            }
        }
        catch {
            Write-ColorOutput "Error retrieving OneDrive usage data: $($_.Exception.Message)" "Yellow"
            Write-Log "Error retrieving OneDrive usage data: $($_.Exception.Message)" "WARNING"
        }
        
        $SecurityFindings = @()
        $Counter = 0
        $TotalUsers = $OneDriveUsage.Count
        
        Write-Host ""
        Write-Host "=== ONEDRIVE SECURITY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        if ($OneDriveUsage.Count -eq 0) {
            Write-ColorOutput "No OneDrive usage data to analyze. This may require SharePoint Administrator permissions." "Yellow"
            
            # Try to get basic user information instead
            try {
                $Users = Get-MgUser -Select "Id,DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity" -Top 100
                
                foreach ($User in $Users) {
                    $Finding = [PSCustomObject]@{
                        UserPrincipalName = $User.UserPrincipalName
                        DisplayName = $User.DisplayName
                        OneDriveUrl = "Unknown - Requires SharePoint Admin"
                        StorageUsed = "Unknown"
                        StorageQuota = "Unknown"
                        FileCount = "Unknown"
                        LastActivityDate = "Unknown"
                        SharingCapability = "Unknown"
                        RiskLevel = "Unknown"
                        Issues = "Requires SharePoint Administrator permissions for detailed analysis"
                        Recommendations = "Enable SharePoint reporting permissions"
                    }
                    $SecurityFindings += $Finding
                }
            }
            catch {
                Write-ColorOutput "Unable to retrieve user data: $($_.Exception.Message)" "Red"
            }
        } else {
            foreach ($Usage in $OneDriveUsage) {
                $Counter++
                Write-Progress -Activity "Analyzing OneDrive Users" -Status "Processing $($Usage.'Owner Display Name')" -PercentComplete (($Counter / $TotalUsers) * 100)
                
                try {
                    # Parse usage data
                    $StorageUsed = if ($Usage.'Storage Used (Byte)') { [long]$Usage.'Storage Used (Byte)' } else { 0 }
                    $StorageQuota = if ($Usage.'Storage Allocated (Byte)') { [long]$Usage.'Storage Allocated (Byte)' } else { 0 }
                    $FileCount = if ($Usage.'File Count') { [int]$Usage.'File Count' } else { 0 }
                    $LastActivityDate = $Usage.'Last Activity Date'
                    
                    # Calculate storage usage percentage
                    $StoragePercentage = if ($StorageQuota -gt 0) { ($StorageUsed / $StorageQuota) * 100 } else { 0 }
                    
                    # Determine risk level
                    $RiskLevel = "Low"
                    $Issues = @()
                    $Recommendations = @()
                    
                    # Check for high storage usage
                    if ($StoragePercentage -gt 90) {
                        $RiskLevel = "High"
                        $Issues += "Storage usage above 90%"
                        $Recommendations += "Monitor storage usage and consider increasing quota"
                    } elseif ($StoragePercentage -gt 75) {
                        $RiskLevel = "Medium"
                        $Issues += "Storage usage above 75%"
                        $Recommendations += "Monitor storage usage"
                    }
                    
                    # Check for inactive OneDrive
                    if ($LastActivityDate) {
                        $LastActivity = [DateTime]::Parse($LastActivityDate)
                        if ($LastActivity -lt (Get-Date).AddDays(-90)) {
                            if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                            $Issues += "No activity in 90+ days"
                            $Recommendations += "Review if OneDrive is still needed"
                        }
                    }
                    
                    # Check for large number of files
                    if ($FileCount -gt 10000) {
                        if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                        $Issues += "Large number of files ($FileCount)"
                        $Recommendations += "Consider organizing files into folders"
                    }
                    
                    $Finding = [PSCustomObject]@{
                        UserPrincipalName = $Usage.'Owner Principal Name'
                        DisplayName = $Usage.'Owner Display Name'
                        OneDriveUrl = $Usage.'Site URL'
                        StorageUsed = "$([math]::Round($StorageUsed / 1GB, 2)) GB"
                        StorageQuota = "$([math]::Round($StorageQuota / 1GB, 2)) GB"
                        StoragePercentage = "$([math]::Round($StoragePercentage, 1))%"
                        FileCount = $FileCount
                        LastActivityDate = $LastActivityDate
                        SharingCapability = "Requires SharePoint Admin Module"
                        RiskLevel = $RiskLevel
                        Issues = ($Issues -join '; ')
                        Recommendations = ($Recommendations -join '; ')
                    }
                    
                    $SecurityFindings += $Finding
                    
                }
                catch {
                    Write-Log "Error analyzing OneDrive for $($Usage.'Owner Display Name'): $($_.Exception.Message)" "WARNING"
                }
            }
        }
        
        Write-Progress -Activity "Analyzing OneDrive Users" -Completed
        
        # Summary
        Write-Host ""
        Write-Host "=== ONEDRIVE SECURITY SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total OneDrive Accounts: $($SecurityFindings.Count)"
        
        if ($OneDriveUsage.Count -gt 0) {
            Write-Host "High Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'High'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
            Write-Host "Medium Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Medium'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
            Write-Host "Low Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Low'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
            
            # Calculate totals
            $TotalStorageUsed = ($SecurityFindings | ForEach-Object { 
                if ($_.'StorageUsed' -match '(\d+\.?\d*) GB') { [double]$Matches[1] } else { 0 }
            } | Measure-Object -Sum).Sum
            
            Write-Host ""
            Write-Host "Storage Statistics:" -ForegroundColor Yellow
            Write-Host "  Total Storage Used: $([math]::Round($TotalStorageUsed, 2)) GB"
            Write-Host "  Average per User: $([math]::Round($TotalStorageUsed / $SecurityFindings.Count, 2)) GB"
        }
        
        # Export to CSV
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "OneDrive_Security_Report_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $SecurityFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "Report exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export report: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "OneDrive Security Analysis completed" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during OneDrive Security Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during OneDrive Security Analysis: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check data loss prevention policies
function Get-DLPPolicyReport {
    Write-ColorOutput "Analyzing Data Loss Prevention Policies..." "Yellow"
    Write-Log "Starting DLP Policy Analysis" "INFO"
    
    try {
        Write-Host ""
        Write-Host "=== DATA LOSS PREVENTION ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        # Note: Full DLP analysis requires Security & Compliance PowerShell
        Write-Host "⚠️  DLP Policy Analysis Limitation:" -ForegroundColor Yellow
        Write-Host "   Full DLP analysis requires Security & Compliance Center PowerShell module" -ForegroundColor Yellow
        Write-Host "   This module is not included in the current implementation" -ForegroundColor Yellow
        Write-Host ""
        
        # Provide basic recommendations
        $DLPFindings = @(
            [PSCustomObject]@{
                PolicyName = "Manual Review Required"
                PolicyType = "Security & Compliance Center"
                Status = "Unknown"
                Locations = "SharePoint, OneDrive, Exchange, Teams"
                SensitiveInfoTypes = "Requires Security & Compliance PowerShell"
                RiskLevel = "Medium"
                Issues = "Manual review of DLP policies required"
                Recommendations = "Connect to Security & Compliance Center PowerShell and review DLP policies"
            }
        )
        
        Write-Host "DLP Policy Recommendations:" -ForegroundColor Cyan
        Write-Host "1. Review existing DLP policies in Security & Compliance Center"
        Write-Host "2. Ensure policies cover SharePoint, OneDrive, Exchange, and Teams"
        Write-Host "3. Test DLP policies with sample sensitive data"
        Write-Host "4. Monitor DLP policy matches and false positives"
        Write-Host "5. Configure appropriate user notifications and policy tips"
        
        # Export basic DLP guidance
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "DLP_Policy_Guidance_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $DLPFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "DLP guidance exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export DLP guidance: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "DLP Policy Analysis completed (manual review required)" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during DLP Policy Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during DLP Policy Analysis: $($_.Exception.Message)" "ERROR"
    }
}

Export-ModuleMember -Function Get-SharePointSharingReport, Get-OneDriveSecurityReport, Get-DLPPolicyReport

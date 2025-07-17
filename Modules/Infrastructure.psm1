# Azure Security Report - Azure Storage Security Module
# Contains storage security assessment functions

# Function to check Azure Storage Account security configuration
function Get-StorageSecurityReport {
    Write-ColorOutput "Analyzing Azure Storage Account Security..." "Yellow"
    Write-Log "Starting Storage Security Analysis" "INFO"
    
    try {
        # Get all storage accounts
        $StorageAccounts = Get-AzStorageAccount
        
        if (-not $StorageAccounts) {
            Write-ColorOutput "No storage accounts found in the current subscription." "Yellow"
            return
        }
        
        $SecurityFindings = @()
        $TotalAccounts = $StorageAccounts.Count
        $Counter = 0
        
        Write-Host ""
        Write-Host "=== AZURE STORAGE SECURITY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($StorageAccount in $StorageAccounts) {
            $Counter++
            Write-Progress -Activity "Analyzing Storage Accounts" -Status "Processing $($StorageAccount.StorageAccountName)" -PercentComplete (($Counter / $TotalAccounts) * 100)
            
            # Get storage account context
            $StorageContext = $StorageAccount.Context
            
            # Check public access
            $PublicAccess = "Unknown"
            try {
                $PublicAccess = $StorageAccount.AllowBlobPublicAccess
            } catch {
                Write-Log "Could not determine public access for $($StorageAccount.StorageAccountName)" "WARNING"
            }
            
            # Check encryption
            $EncryptionStatus = if ($StorageAccount.Encryption) { "Enabled" } else { "Disabled" }
            
            # Check HTTPS only
            $HttpsOnly = if ($StorageAccount.EnableHttpsTrafficOnly) { "Enabled" } else { "Disabled" }
            
            # Check network access
            $NetworkAccess = $StorageAccount.NetworkRuleSet.DefaultAction
            
            # Check for public blob containers
            $PublicContainers = @()
            try {
                $Containers = Get-AzStorageContainer -Context $StorageContext -ErrorAction SilentlyContinue
                foreach ($Container in $Containers) {
                    if ($Container.PublicAccess -ne "Off") {
                        $PublicContainers += $Container.Name
                    }
                }
            } catch {
                Write-Log "Could not check containers for $($StorageAccount.StorageAccountName): $($_.Exception.Message)" "WARNING"
            }
            
            # Determine risk level
            $RiskLevel = "Low"
            $Issues = @()
            
            if ($PublicAccess -eq $true) {
                $RiskLevel = "High"
                $Issues += "Public blob access allowed"
            }
            
            if ($HttpsOnly -eq "Disabled") {
                $RiskLevel = "High"
                $Issues += "HTTPS not enforced"
            }
            
            if ($PublicContainers.Count -gt 0) {
                $RiskLevel = "Critical"
                $Issues += "Public containers detected: $($PublicContainers -join ', ')"
            }
            
            if ($NetworkAccess -eq "Allow") {
                if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                $Issues += "Network access allows all"
            }
            
            # Add to findings
            $Finding = [PSCustomObject]@{
                StorageAccountName = $StorageAccount.StorageAccountName
                ResourceGroup = $StorageAccount.ResourceGroupName
                Location = $StorageAccount.Location
                PublicBlobAccess = $PublicAccess
                HttpsOnly = $HttpsOnly
                Encryption = $EncryptionStatus
                NetworkAccess = $NetworkAccess
                PublicContainers = ($PublicContainers -join '; ')
                PublicContainerCount = $PublicContainers.Count
                RiskLevel = $RiskLevel
                Issues = ($Issues -join '; ')
                LastModified = $StorageAccount.LastGeoFailoverTime
            }
            
            $SecurityFindings += $Finding
            
            # Display finding
            $RiskColor = switch ($RiskLevel) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            
            Write-Host "[$RiskLevel] " -ForegroundColor $RiskColor -NoNewline
            Write-Host "$($StorageAccount.StorageAccountName) " -NoNewline
            if ($Issues.Count -gt 0) {
                Write-Host "- Issues: $($Issues -join ', ')" -ForegroundColor $RiskColor
            } else {
                Write-Host "- No security issues detected" -ForegroundColor Green
            }
        }
        
        Write-Progress -Activity "Analyzing Storage Accounts" -Completed
        
        # Summary
        Write-Host ""
        Write-Host "=== STORAGE SECURITY SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total Storage Accounts: $TotalAccounts"
        Write-Host "Critical Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Critical'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "High Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'High'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "Medium Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Medium'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
        Write-Host "Low Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Low'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
        
        # Export to CSV
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "Storage_Security_Report_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $SecurityFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "Report exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export report: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "Storage Security Analysis completed" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during Storage Security Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during Storage Security Analysis: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check Azure Key Vault security configuration
function Get-KeyVaultSecurityReport {
    Write-ColorOutput "Analyzing Azure Key Vault Security..." "Yellow"
    Write-Log "Starting Key Vault Security Analysis" "INFO"
    
    try {
        # Get all key vaults
        $KeyVaults = Get-AzKeyVault
        
        if (-not $KeyVaults) {
            Write-ColorOutput "No Key Vaults found in the current subscription." "Yellow"
            return
        }
        
        $SecurityFindings = @()
        $TotalVaults = $KeyVaults.Count
        $Counter = 0
        
        Write-Host ""
        Write-Host "=== AZURE KEY VAULT SECURITY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($Vault in $KeyVaults) {
            $Counter++
            Write-Progress -Activity "Analyzing Key Vaults" -Status "Processing $($Vault.VaultName)" -PercentComplete (($Counter / $TotalVaults) * 100)
            
            # Get detailed vault information
            $VaultDetails = Get-AzKeyVault -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName
            
            # Check network access
            $NetworkAccess = if ($VaultDetails.NetworkAcls) { 
                $VaultDetails.NetworkAcls.DefaultAction 
            } else { 
                "Allow" 
            }
            
            # Check soft delete
            $SoftDeleteEnabled = $VaultDetails.EnableSoftDelete
            
            # Check purge protection
            $PurgeProtectionEnabled = $VaultDetails.EnablePurgeProtection
            
            # Check RBAC authorization
            $RbacAuthorizationEnabled = $VaultDetails.EnableRbacAuthorization
            
            # Check certificates nearing expiration
            $ExpiringCerts = @()
            try {
                $Certificates = Get-AzKeyVaultCertificate -VaultName $Vault.VaultName
                $ThirtyDaysFromNow = (Get-Date).AddDays(30)
                
                foreach ($Cert in $Certificates) {
                    $CertDetails = Get-AzKeyVaultCertificate -VaultName $Vault.VaultName -Name $Cert.Name
                    if ($CertDetails.Expires -and $CertDetails.Expires -le $ThirtyDaysFromNow) {
                        $ExpiringCerts += "$($Cert.Name) (Expires: $($CertDetails.Expires.ToString('yyyy-MM-dd')))"
                    }
                }
            } catch {
                Write-Log "Could not check certificates for $($Vault.VaultName): $($_.Exception.Message)" "WARNING"
            }
            
            # Check access policies
            $AccessPolicyCount = if ($VaultDetails.AccessPolicies) { $VaultDetails.AccessPolicies.Count } else { 0 }
            
            # Determine risk level
            $RiskLevel = "Low"
            $Issues = @()
            
            if ($NetworkAccess -eq "Allow") {
                $RiskLevel = "Medium"
                $Issues += "Network access allows all IPs"
            }
            
            if (-not $SoftDeleteEnabled) {
                $RiskLevel = "High"
                $Issues += "Soft delete not enabled"
            }
            
            if (-not $PurgeProtectionEnabled) {
                if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                $Issues += "Purge protection not enabled"
            }
            
            if ($ExpiringCerts.Count -gt 0) {
                $RiskLevel = "High"
                $Issues += "Certificates expiring within 30 days: $($ExpiringCerts.Count)"
            }
            
            if ($AccessPolicyCount -gt 10) {
                if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                $Issues += "High number of access policies ($AccessPolicyCount)"
            }
            
            # Add to findings
            $Finding = [PSCustomObject]@{
                VaultName = $Vault.VaultName
                ResourceGroup = $Vault.ResourceGroupName
                Location = $Vault.Location
                NetworkAccess = $NetworkAccess
                SoftDeleteEnabled = $SoftDeleteEnabled
                PurgeProtectionEnabled = $PurgeProtectionEnabled
                RbacAuthorizationEnabled = $RbacAuthorizationEnabled
                AccessPolicyCount = $AccessPolicyCount
                ExpiringCertificates = ($ExpiringCerts -join '; ')
                ExpiringCertCount = $ExpiringCerts.Count
                RiskLevel = $RiskLevel
                Issues = ($Issues -join '; ')
            }
            
            $SecurityFindings += $Finding
            
            # Display finding
            $RiskColor = switch ($RiskLevel) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            
            Write-Host "[$RiskLevel] " -ForegroundColor $RiskColor -NoNewline
            Write-Host "$($Vault.VaultName) " -NoNewline
            if ($Issues.Count -gt 0) {
                Write-Host "- Issues: $($Issues -join ', ')" -ForegroundColor $RiskColor
            } else {
                Write-Host "- No security issues detected" -ForegroundColor Green
            }
        }
        
        Write-Progress -Activity "Analyzing Key Vaults" -Completed
        
        # Summary
        Write-Host ""
        Write-Host "=== KEY VAULT SECURITY SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total Key Vaults: $TotalVaults"
        Write-Host "Critical Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Critical'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "High Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'High'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "Medium Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Medium'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
        Write-Host "Low Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Low'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
        
        # Export to CSV
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "KeyVault_Security_Report_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $SecurityFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "Report exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export report: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "Key Vault Security Analysis completed" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during Key Vault Security Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during Key Vault Security Analysis: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check Azure Network Security Groups
function Get-NetworkSecurityReport {
    Write-ColorOutput "Analyzing Azure Network Security Groups..." "Yellow"
    Write-Log "Starting Network Security Analysis" "INFO"
    
    try {
        # Get all NSGs
        $NSGs = Get-AzNetworkSecurityGroup
        
        if (-not $NSGs) {
            Write-ColorOutput "No Network Security Groups found in the current subscription." "Yellow"
            return
        }
        
        $SecurityFindings = @()
        $TotalNSGs = $NSGs.Count
        $Counter = 0
        
        Write-Host ""
        Write-Host "=== AZURE NETWORK SECURITY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($NSG in $NSGs) {
            $Counter++
            Write-Progress -Activity "Analyzing Network Security Groups" -Status "Processing $($NSG.Name)" -PercentComplete (($Counter / $TotalNSGs) * 100)
            
            $DangerousRules = @()
            $OpenPorts = @()
            
            # Check security rules
            foreach ($Rule in $NSG.SecurityRules) {
                # Check for dangerous rules
                if ($Rule.Access -eq "Allow" -and $Rule.Direction -eq "Inbound") {
                    # Check for any source (*) with common dangerous ports
                    if ($Rule.SourceAddressPrefix -eq "*" -or $Rule.SourceAddressPrefix -eq "Internet") {
                        $DangerousPorts = @("22", "3389", "1433", "3306", "5432", "1521", "27017")
                        
                        foreach ($Port in $DangerousPorts) {
                            if ($Rule.DestinationPortRange -eq $Port -or 
                                $Rule.DestinationPortRange -eq "*" -or
                                ($Rule.DestinationPortRange -like "*-*" -and $Port -ge ($Rule.DestinationPortRange.Split('-')[0]) -and $Port -le ($Rule.DestinationPortRange.Split('-')[1]))) {
                                $DangerousRules += "$($Rule.Name): Port $Port open to Internet"
                                $OpenPorts += $Port
                            }
                        }
                        
                        # Check for wildcard ports
                        if ($Rule.DestinationPortRange -eq "*") {
                            $DangerousRules += "$($Rule.Name): All ports open to Internet"
                        }
                    }
                }
            }
            
            # Determine risk level
            $RiskLevel = "Low"
            $Issues = @()
            
            if ($DangerousRules.Count -gt 0) {
                $RiskLevel = "Critical"
                $Issues += "Dangerous inbound rules detected"
            }
            
            if ($OpenPorts -contains "22" -or $OpenPorts -contains "3389") {
                $RiskLevel = "Critical"
                $Issues += "SSH/RDP open to Internet"
            }
            
            if ($OpenPorts -contains "1433" -or $OpenPorts -contains "3306" -or $OpenPorts -contains "5432") {
                $RiskLevel = "Critical"
                $Issues += "Database ports open to Internet"
            }
            
            # Add to findings
            $Finding = [PSCustomObject]@{
                NSGName = $NSG.Name
                ResourceGroup = $NSG.ResourceGroupName
                Location = $NSG.Location
                SecurityRulesCount = $NSG.SecurityRules.Count
                DangerousRules = ($DangerousRules -join '; ')
                DangerousRulesCount = $DangerousRules.Count
                OpenPorts = ($OpenPorts | Sort-Object -Unique) -join ', '
                AssociatedSubnets = ($NSG.Subnets | ForEach-Object { $_.Id.Split('/')[-1] }) -join ', '
                AssociatedNICs = ($NSG.NetworkInterfaces | ForEach-Object { $_.Id.Split('/')[-1] }) -join ', '
                RiskLevel = $RiskLevel
                Issues = ($Issues -join '; ')
            }
            
            $SecurityFindings += $Finding
            
            # Display finding
            $RiskColor = switch ($RiskLevel) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            
            Write-Host "[$RiskLevel] " -ForegroundColor $RiskColor -NoNewline
            Write-Host "$($NSG.Name) " -NoNewline
            if ($Issues.Count -gt 0) {
                Write-Host "- Issues: $($Issues -join ', ')" -ForegroundColor $RiskColor
            } else {
                Write-Host "- No security issues detected" -ForegroundColor Green
            }
        }
        
        Write-Progress -Activity "Analyzing Network Security Groups" -Completed
        
        # Summary
        Write-Host ""
        Write-Host "=== NETWORK SECURITY SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Total NSGs: $TotalNSGs"
        Write-Host "Critical Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Critical'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "High Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'High'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
        Write-Host "Medium Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Medium'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
        Write-Host "Low Risk: $($SecurityFindings | Where-Object {$_.RiskLevel -eq 'Low'} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
        
        # Export to CSV
        $Config = Get-SecurityConfig
        $ExportPath = $Config.ExportPath
        $FileName = "Network_Security_Report_$script:Timestamp.csv"
        $FilePath = Join-Path $ExportPath $FileName
        
        try {
            $SecurityFindings | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "Report exported to: $FilePath" "Green"
        }
        catch {
            Write-ColorOutput "Failed to export report: $($_.Exception.Message)" "Red"
        }
        
        Write-Log "Network Security Analysis completed" "INFO"
        
    }
    catch {
        Write-ColorOutput "Error during Network Security Analysis: $($_.Exception.Message)" "Red"
        Write-Log "Error during Network Security Analysis: $($_.Exception.Message)" "ERROR"
    }
}

function Get-AzureResourceInventoryReport {
    Write-ColorOutput "Generating Azure Resource Inventory Report..." "Yellow"
    Write-Log "Starting Azure Resource Inventory Report" "INFO"
    try {
        $ScriptPath = Join-Path $PSScriptRoot "ARI" "AzureResourceInventory.ps1"
        write-Log "Executing script: $ScriptPath" "INFO"
        if (Test-Path $ScriptPath) {
            . $ScriptPath -Online
        } else {
            Write-ColorOutput "Azure Resource Inventory Report script not found." "Red"
            Write-Log "Azure Resource Inventory Report script not found." "ERROR"
        }
    } catch {
        Write-ColorOutput "Error generating Azure Resource Inventory Report: $($_.Exception.Message)" "Red"
        Write-Log "Error generating Azure Resource Inventory Report: $($_.Exception.Message)" "ERROR"
    }
}


Export-ModuleMember -Function Get-StorageSecurityReport, Get-KeyVaultSecurityReport, Get-NetworkSecurityReport, Get-AzureResourceInventoryReport

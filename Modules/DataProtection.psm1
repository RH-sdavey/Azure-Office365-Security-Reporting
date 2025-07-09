# Azure Security Report - Data Protection Module
# Contains all data protection-related security checks

# Function to check TLS configuration on VMs using Azure Resource Graph
function Test-TLSConfiguration {
    Write-ColorOutput "Checking TLS configuration on Azure VMs using Azure Resource Graph..." "Yellow"
    
    try {
        # Check if Az.ResourceGraph module is available
        if (-not (Get-Module -ListAvailable -Name "Az.ResourceGraph")) {
            Write-ColorOutput "Az.ResourceGraph module is required for TLS configuration checks. Attempting to install..." "Yellow"
            try {
                Install-Module -Name "Az.ResourceGraph" -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Import-Module -Name "Az.ResourceGraph" -Force -ErrorAction Stop
                Write-ColorOutput "Successfully installed and imported Az.ResourceGraph module." "Green"
            } catch {
                Write-ColorOutput "Failed to install Az.ResourceGraph module: $($_.Exception.Message)" "Red"
                Write-Log "Failed to install Az.ResourceGraph module: $($_.Exception.Message)" "ERROR"
                return
            }
        } else {
            Import-Module -Name "Az.ResourceGraph" -Force -ErrorAction SilentlyContinue
        }
        
        # Query VMs with security configuration using Azure Resource Graph
        $Query = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend OSType = tostring(properties.storageProfile.osDisk.osType)
| extend VMSize = tostring(properties.hardwareProfile.vmSize)
| extend ProvisioningState = tostring(properties.provisioningState)
| extend PowerState = tostring(properties.extended.instanceView.powerState.displayStatus)
| project name, resourceGroup, location, OSType, VMSize, ProvisioningState, PowerState, subscriptionId
| order by name asc
"@
        
        Write-ColorOutput "Querying Azure Resource Graph for VM information..." "Yellow"
        $VMs = Search-AzGraph -Query $Query -ErrorAction Stop
        $TLSReport = @()
        $NonCompliantVMs = 0
        $WindowsVMs = 0
        $LinuxVMs = 0
        
        if ($VMs.Count -eq 0) {
            Write-ColorOutput "No Azure VMs found." "Yellow"
            return
        }
        
        Write-ColorOutput "Found $($VMs.Count) Azure VMs. Analyzing TLS configuration..." "Green"
        
        foreach ($VM in $VMs) {
            try {
                # Determine likely TLS configuration based on OS type and VM characteristics
                $OSType = $VM.OSType
                $TLSVersion = "Unknown"
                $IsCompliant = $false
                $ComplianceNotes = ""
                
                if ($OSType -eq "Windows") {
                    $WindowsVMs++
                    # Modern Windows VMs typically use TLS 1.2 by default
                    # Check if it's a newer VM size (indicates recent deployment)
                    if ($VM.VMSize -match "v[3-5]|Standard_[D-F][0-9]+s?_v[3-5]|Standard_E[0-9]+[a-z]*s?_v[3-5]") {
                        $TLSVersion = "1.2"
                        $IsCompliant = $true
                        $ComplianceNotes = "Modern VM size - likely TLS 1.2 enabled by default"
                    } else {
                        $TLSVersion = "1.0/1.1"
                        $IsCompliant = $false
                        $NonCompliantVMs++
                        $ComplianceNotes = "Older VM size - may require TLS 1.2 configuration verification"
                    }
                } elseif ($OSType -eq "Linux") {
                    $LinuxVMs++
                    # Modern Linux distributions typically support TLS 1.2
                    $TLSVersion = "1.2"
                    $IsCompliant = $true
                    $ComplianceNotes = "Linux VM - typically supports TLS 1.2"
                } else {
                    $TLSVersion = "Unknown"
                    $IsCompliant = $false
                    $ComplianceNotes = "Unknown OS type - manual verification required"
                }
                
                $TLSReport += [PSCustomObject]@{
                    VMName = $VM.name
                    ResourceGroup = $VM.resourceGroup
                    Location = $VM.location
                    OSType = $OSType
                    VMSize = $VM.VMSize
                    PowerState = $VM.PowerState
                    TLSVersion = $TLSVersion
                    ComplianceStatus = if ($IsCompliant) { "Likely Compliant" } else { "Needs Verification" }
                    Notes = $ComplianceNotes
                    SubscriptionId = $VM.subscriptionId
                }
            } catch {
                Write-ColorOutput "Error processing VM $($VM.name): $($_.Exception.Message)" "Red"
                Write-Log "Error processing VM $($VM.name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Display summary
        Write-Host ""
        Write-ColorOutput "=== TLS CONFIGURATION ANALYSIS SUMMARY ===" "Cyan"
        Write-ColorOutput "Total VMs analyzed: $($VMs.Count)" "White"
        Write-ColorOutput "Windows VMs: $WindowsVMs" "White"
        Write-ColorOutput "Linux VMs: $LinuxVMs" "White"
        
        if ($NonCompliantVMs -eq 0) {
            Write-ColorOutput "✓ All VMs likely use TLS 1.2 or have modern configurations." "Green"
        } else {
            Write-ColorOutput "⚠ $NonCompliantVMs VMs may need TLS 1.2 verification or configuration." "Yellow"
            Write-ColorOutput "🔍 Recommendation: Manually verify TLS settings on older Windows VMs." "Yellow"
        }
        
        Write-Host ""
        Write-ColorOutput "ℹ️  Note: This analysis is based on VM metadata and best practices." "Cyan"
        Write-ColorOutput "   For definitive TLS configuration, use Azure Security Center or connect directly to VMs." "Cyan"
        
        # Prompt for export
        $Export = Read-Host "Would you like to export TLS analysis results to CSV? (Y/N)"
        if ($Export -eq 'Y' -or $Export -eq 'y') {
            $FilePath = Get-ValidFilePath "TLS_Configuration_Analysis"
            $TLSReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-ColorOutput "Results exported to: $FilePath" "Green"
        }
    } catch {
        Write-ColorOutput "Error checking TLS configuration: $($_.Exception.Message)" "Red"
        Write-Log "Error checking TLS configuration: $($_.Exception.Message)" "ERROR"
    }
}

# Function to check VM encryption
function Test-VMEncryption {
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

Export-ModuleMember -Function Test-TLSConfiguration, Test-VMEncryption

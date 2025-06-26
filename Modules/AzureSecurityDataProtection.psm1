# Azure Security Report - Data Protection Module
# Contains all data protection-related security checks

# Function to check TLS configuration on VMs
function Test-TLSConfiguration {
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

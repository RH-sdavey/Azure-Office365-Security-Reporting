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
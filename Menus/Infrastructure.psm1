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
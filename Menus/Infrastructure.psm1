function Show-InfrastructureMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure Infrastructure" -ForegroundColor Cyan
        Write-Host "====================================" -ForegroundColor Cyan
        Write-Host "1. Azure Resource Inventory Report (can take 10-15 minutes)"
        Write-Host "2. Azure Storage Security Report"
        Write-Host "3. Azure Key Vault Security Report"
        Write-Host "4. Network Security Groups Report"
        Write-Host "5. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-4)"
        
        switch ($Choice) {
            "1" { Get-AzureResourceInventoryReport ; Read-Host "Press Enter to continue" }
            "2" { Get-StorageSecurityReport; Read-Host "Press Enter to continue" }
            "3" { Get-KeyVaultSecurityReport; Read-Host "Press Enter to continue" }
            "4" { Get-NetworkSecurityReport; Read-Host "Press Enter to continue" }
            "5" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}
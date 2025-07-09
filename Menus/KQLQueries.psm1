function Show-AzureKQLQueriesMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure KQL Queries" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan
        Write-Host "1. Run Custom KQL Query"
        Write-Host "2. Compute Queries"
        Write-Host "2. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-2)"
        
        switch ($Choice) {
            "1" { Read-Host "Press Enter to continue" }
            "2" { Show-AzureComputeKQLQueriesMenu }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-AzureComputeKQLQueriesMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Azure Compute KQL Queries" -ForegroundColor Cyan
        Write-Host "===========================" -ForegroundColor Cyan
        Write-Host "1. Get VM DCR Associations"
        Write-Host "2. Return to KQL Queries Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-2)"
        
        switch ($Choice) {
            "1" { Get-AzureComputeDCRReport; Read-Host "Press Enter to continue" }
            "2" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

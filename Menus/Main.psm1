function Show-MainMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "1. Identity and Access Management"
        Write-Host "2. Data Protection"
        Write-Host "3. Azure Infrastructure"
        Write-Host "4. Office 365"
        Write-Host "5. Azure KQL Queries"
        Write-Host "7. Settings & Configuration"
        Write-Host "8. Tools & Utilities"
        Write-Host "Q. Exit"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-6, Q)"
        
        switch ($Choice) {
            "1" { Show-IAMMenu }
            "2" { Show-DataProtectionMenu }
            "3" { Show-InfrastructureSecurityMenu }
            "4" { Show-Office365Menu }
            "5" { Show-AzureKQLQueriesMenu }
            "7" { Show-SettingsMenu }
            "8" { Show-ToolsMenu }
            "Q" { 
                Write-ColorOutput "Thank you for using Azure & Office 365 Security Report!" "Green"
                Write-ColorOutput "Log file saved as: $script:LogFile" "Yellow"
                return 
            }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}
function Show-ToolsMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Tools & Utilities" -ForegroundColor Cyan
        Write-Host "=================" -ForegroundColor Cyan
        Write-Host "1. Name to Object ID"
        Write-Host "2. Convert Object ID to Name"
        Write-Host "3. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Convert-NameToObjectID; Read-Host "Press Enter to continue" }
            "2" { Convert-ObjectIDToName; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}
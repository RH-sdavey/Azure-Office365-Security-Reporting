function Show-IAMMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "IAM Security Checks" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "1. Check MFA Status"
        Write-Host "2. Check Guest User Access"
        Write-Host "3. Check Password Expiry Settings"
        Write-Host "4. Check Conditional Access Policies"
        Write-Host "5. App Registration Key Report"
        Write-Host "6. All SAM Account Names"
        Write-Host "7. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Test-MFAStatus; Read-Host "Press Enter to continue" }
            "2" { Test-GuestUserAccess; Read-Host "Press Enter to continue" }
            "3" { Test-PasswordExpirySettings; Read-Host "Press Enter to continue" }
            "4" { Test-ConditionalAccessPolicies; Read-Host "Press Enter to continue" }
            "5" { Get-AppRegistrationKeyReport; Read-Host "Press Enter to continue" }
            "6" { Get-AllSamls; Read-Host "Press Enter to continue" }
            "7" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-IAMMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Entra ID and IAM" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "1. EntraID Audit Report (cant take 2-3hrs to complete)"
        Write-Host "2. MFA Menu"
        Write-Host "3. Guest User Menu"
        Write-Host "4. Check Password Expiry Settings"
        Write-Host "5. Conditional Access Policies Menu"
        Write-Host "6. App Registration Key Report"
        Write-Host "7. All SAM Account Names"
        Write-Host "8. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Get-EntraIDAuditReport; Read-Host "Press Enter to continue" }
            "2" { Show-MFAMenu }
            "3" { Show-GuestUserMenu }
            "4" { Test-PasswordExpirySettings; Read-Host "Press Enter to continue" }
            "5" { Show-ConditionalAccessPoliciesMenu }
            "6" { Get-AppRegistrationKeyReport; Read-Host "Press Enter to continue" }
            "7" { Get-AllSamls; Read-Host "Press Enter to continue" }
            "8" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-MFAMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "MFA Security Checks" -ForegroundColor Cyan
        Write-Host "====================" -ForegroundColor Cyan
        Write-Host "1. Check MFA Status"
        Write-Host "2. Check MFA Registration"
        Write-Host "3. Return to IAM Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Test-MFAStatus; Read-Host "Press Enter to continue" }
            "2" { Read-Host "Not Implemented -Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}


function Show-GuestUserMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Guest User Security Checks" -ForegroundColor Cyan
        Write-Host "===========================" -ForegroundColor Cyan
        Write-Host "1. List Guest Users"
        Write-Host "2. Check Guest User Access"
        Write-Host "3. Return to IAM Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Read-Host "Not Implemented: Press Enter to continue" }
            "2" { Test-GuestUserAccess; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-ConditionalAccessPoliciesMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Conditional Access Policies" -ForegroundColor Cyan
        Write-Host "============================" -ForegroundColor Cyan
        Write-Host "1. List Conditional Access Policies"
        Write-Host "2. Check Policy Impact"
        Write-Host "3. Return to IAM Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Test-ConditionalAccessPolicies; Read-Host "Press Enter to continue" }
            "2" { Read-Host "Not Implemented: Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}
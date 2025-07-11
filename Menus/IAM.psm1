function Show-IAMMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "IAM Security Checks" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "1. MFA Menu"
        Write-Host "2. Guest User Menu"
        Write-Host "3. Check Password Expiry Settings"
        Write-Host "4. Conditional Access Policies Menu"
        Write-Host "5. App Registration Key Report"
        Write-Host "6. All SAM Account Names"
        Write-Host "7. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-5)"
        
        switch ($Choice) {
            "1" { Show-MFAMenu }
            "2" { Show-GuestUserMenu }
            "3" { Test-PasswordExpirySettings; Read-Host "Press Enter to continue" }
            "4" { Show-ConditionalAccessPoliciesMenu }
            "5" { Get-AppRegistrationKeyReport; Read-Host "Press Enter to continue" }
            "6" { Get-AllSamls; Read-Host "Press Enter to continue" }
            "7" { return }
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
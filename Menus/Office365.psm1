function Show-Office365Menu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Office 365 Audit Menu" -ForegroundColor Cyan
        Write-Host "=========================" -ForegroundColor Cyan
        Write-Host "1. License Usage Report"
        Write-Host "2. Inactive Accounts Report"
        
        Write-Host "3.5 Outlook"
        Write-Host "4. Microsoft Teams"
        Write-Host "5. SharePoint & OneDrive"
        Write-Host "6. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-6)"
        
        switch ($Choice) {
            "1" { Get-LicenseUsageReport; Read-Host "Press Enter to continue" }
            "2" { Get-InactiveAccountsReport; Read-Host "Press Enter to continue" }
            "3" { Show-OutlookMenu; Read-Host "Press Enter to continue" }
            "4" { Show-TeamsMenu; Read-Host "Press Enter to continue" }
            "5" { Show-SharePointMenu; Read-Host "Press Enter to continue" }
            "6" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

function Show-OutlookMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Outlook Security Checks" -ForegroundColor Cyan
        Write-Host "========================" -ForegroundColor Cyan
        Write-Host "1. Check Outlook Rules"
        Write-Host "2. Check Outlook Signatures"
        Write-Host "3. Check Mailbox Forwarding Rules"
        Write-Host "4. Return to Office 365 Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Get-OutlookRulesReport; Read-Host "Press Enter to continue" }
            "2" { Get-OutlookSignaturesReport; Read-Host "Press Enter to continue" }
            "3" { Get-MailboxForwardingReport; Read-Host "Press Enter to continue" }
            "4" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}


function Show-TeamsMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Microsoft Teams Security Checks" -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "1. Check External Access Configuration"
        Write-Host "2. Report Teams with External Users or Guests"
        Write-Host "3. Check Mailbox Forwarding Rules"
        Write-Host "3. Return to Office 365 Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-3)"
        
        switch ($Choice) {
            "1" { Get-TeamsExternalAccessReport; Read-Host "Press Enter to continue" }
            "2" { Get-TeamsWithExternalUsersReport; Read-Host "Press Enter to continue" }
            "3" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}


function Show-SharePointMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "SharePoint & OneDrive Security Checks" -ForegroundColor Cyan
        Write-Host "=====================================" -ForegroundColor Cyan
        Write-Host "1. SharePoint Sharing Settings Report"
        Write-Host "2. OneDrive Security & Usage Report"
        Write-Host "3. Data Loss Prevention (DLP) Policy Report"
        Write-Host "4. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-4)"
        
        switch ($Choice) {
            "1" { Get-SharePointSharingReport; Read-Host "Press Enter to continue" }
            "2" { Get-OneDriveSecurityReport; Read-Host "Press Enter to continue" }
            "3" { Get-DLPPolicyReport; Read-Host "Press Enter to continue" }
            "4" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}
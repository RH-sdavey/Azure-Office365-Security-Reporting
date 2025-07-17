function Get-AppRegistrationKeyReport {
    $appRegistrationDisplayName = read-host "Provide the display name of the app registration"
    if (-not $appRegistrationDisplayName) {
        Write-Error "Please provide the display name of the app registration."
    }

    $sp = Get-AzADServicePrincipal -DisplayName $appRegistrationDisplayName

    $keys  = Get-AzADAppCredential -ApplicationId $sp.AppId
    Write-Host "App Registration Key Details for $appRegistrationDisplayName"

    $keys | Format-Table
}


function Get-AllSamls {
    $userData = @()

    $users = Get-MgUser -Filter "onPremisesSyncEnabled eq true" -All -Property "userPrincipalName, onPremisesSamAccountName"
    $filteredUsers = $users | Where-Object { $null -ne $_.onPremisesSamAccountName }

    foreach ($azuser in $filteredUsers) {
        $userData += [pscustomobject]@{
            "Work Email"    = $azuser.UserPrincipalName
            "SAM Account Name" = $azuser.OnPremisesSamAccountName
        }
    }

    if ($userData.Count -eq 0) {
        Write-ColorOutput "No users with on-premises SAM account names found." "Yellow"
    } else {
        $userData | Format-Table -AutoSize
    }


}


function Get-EntraIDAuditReport {
    Write-ColorOutput "Generating Azure Resource Inventory Report..." "Yellow"
    Write-Log "Starting Azure Resource Inventory Report" "INFO"
    try {
        $ScriptPath = Join-Path $PSScriptRoot "EntraFalcon" "run_EntraFalcon.ps1"
        write-Log "Executing script: $ScriptPath" "INFO"
        if (Test-Path $ScriptPath) {
            . $ScriptPath -IncludeMsApps -AuthMethod "DeviceCode"
        } else {
            Write-ColorOutput "Entra ID Inventory script not found." "Red"
            Write-Log "Entra ID Inventory script not found." "ERROR"
        }
    } catch {
        Write-ColorOutput "Error generating Entra ID Inventory Report: $($_.Exception.Message)" "Red"
        Write-Log "Error generating Entra ID Inventory Report: $($_.Exception.Message)" "ERROR"
    }
}
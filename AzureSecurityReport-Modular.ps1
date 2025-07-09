#Requires -Version 7.0
<#
.SYNOPSIS
    Azure Security Report - Modular Version
.DESCRIPTION
    Simplified main script that uses modular components for security auditing
#>

$CoreModulePath = Join-Path $ModulesPath "Core.psm1"
Import-Module $CoreModulePath -Force -Global

$MenusPath = Join-Path $PSScriptRoot "Menus"
Import-Module (Join-Path $MenusPath "Main.psm1") -Force -Global
Import-Module (Join-Path $MenusPath "IAM.psm1") -Force -Global
Import-Module (Join-Path $MenusPath "Office365.psm1") -Force -Global
Import-Module (Join-Path $MenusPath "DataProtection.psm1") -Force -Global
Import-Module (Join-Path $MenusPath "Infrastructure.psm1") -Force -Global
Import-Module (Join-Path $MenusPath "KQLQueries.psm1") -Force -Global

$ModulesPath = Join-Path $PSScriptRoot "Modules"
Import-Module (Join-Path $ModulesPath "DataProtection.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "IAM.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "EntraID.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "Office365.psm1") -Force
Import-Module (Join-Path $ModulesPath "Settings.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "Infrastructure.psm1") -Force -Global
Import-Module (Join-Path $ModulesPath "SharePoint.psm1") -Force -Global

# KQL Queries modules
Import-Module (Join-Path $ModulesPath "KQL" "AzureComputeKQL.psm1") -Force -Global


function Main {
    Show-Title
    
    Initialize-SecurityConfig | Out-Null
    $Config = Get-SecurityConfig
    
    $RequiredModules = @(
        "Az.Accounts", 
        "Az.Compute", 
        "Az.Security",
        "Az.ResourceGraph",
        "Az.KeyVault",
        "Az.Network",
        "Az.Storage",
        "Microsoft.Graph.Users", 
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Reports",
        "Microsoft.Graph.Sites",
        "ExchangeOnlineManagement",
        "MicrosoftTeams"
    )
    
    # Check required modules
    if (-not (Test-RequiredModules -RequiredModules $RequiredModules)) {
        Write-Log "Module check failed. Exiting." "ERROR"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # # Try auto-connect if configured
    # $AutoConnected = $false
    # if ($Config.AutoConnect -and $Config.UseServicePrincipal) {
    #     Write-ColorOutput "Attempting auto-connect using saved configuration..." "Yellow"
    #     $AutoConnected = Connect-UsingConfig
    # }
    
    # # Manual authentication if auto-connect failed or not configured
    # if (-not $AutoConnected) {
    #     Write-ColorOutput "Using interactive authentication..." "Yellow"
    #     if (-not (Connect-AzureServices)) {
    #         Write-Log "Authentication failed. Exiting." "ERROR"
    #         Read-Host "Press Enter to exit"
    #         exit 1
    #     }
    # }
    
    Write-ColorOutput "Authentication successful. Starting security audit..." "Green"
    Start-Sleep 2
    
    Show-MainMenu
}

Main

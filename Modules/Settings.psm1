# Azure Security Report - Settings Module
# Contains configuration management and credential storage

$script:ConfigFile = Join-Path $PSScriptRoot "..\AzureSecurityConfig.json"

# Function to initialize default configuration
function Initialize-SecurityConfig {
    $DefaultConfig = @{
        TenantId = ""
        ApplicationId = ""
        CertificateThumbprint = ""
        UseServicePrincipal = $false
        AutoConnect = $false
        ExportPath = ".\Reports"
        LogLevel = "INFO"
        LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Version = "3.5"
    }
    
    if (-not (Test-Path $script:ConfigFile)) {
        $DefaultConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $script:ConfigFile -Encoding UTF8
        Write-ColorOutput "Configuration file created at: $script:ConfigFile" "Green"
    }
    
    return $DefaultConfig
}

# Function to load configuration
function Get-SecurityConfig {
    try {
        if (Test-Path $script:ConfigFile) {
            $Config = Get-Content -Path $script:ConfigFile -Raw | ConvertFrom-Json
            return $Config
        } else {
            return Initialize-SecurityConfig
        }
    }
    catch {
        Write-ColorOutput "Error loading configuration: $($_.Exception.Message)" "Red"
        return Initialize-SecurityConfig
    }
}

# Function to save configuration
function Set-SecurityConfig {
    param(
        $Config
    )
    
    try {
        # Convert to hashtable if it's a PSCustomObject
        if ($Config -is [PSCustomObject]) {
            $ConfigHash = @{}
            $Config.PSObject.Properties | ForEach-Object {
                $ConfigHash[$_.Name] = $_.Value
            }
            $Config = $ConfigHash
        }
        
        $Config.LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $Config | ConvertTo-Json -Depth 3 | Set-Content -Path $script:ConfigFile -Encoding UTF8
        Write-ColorOutput "Configuration saved successfully." "Green"
        return $true
    }
    catch {
        Write-ColorOutput "Error saving configuration: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to manage settings menu
function Show-SettingsMenu {
    do {
        Clear-Host
        Show-Title
        Write-Host "Settings & Configuration" -ForegroundColor Cyan
        Write-Host "=======================" -ForegroundColor Cyan
        
        $Config = Get-SecurityConfig
        
        Write-Host ""
        Write-Host "Current Configuration:" -ForegroundColor Yellow
        Write-Host "  Tenant ID: $(if($Config.TenantId) { $Config.TenantId } else { 'Not Set' })"
        Write-Host "  Application ID: $(if($Config.ApplicationId) { $Config.ApplicationId } else { 'Not Set' })"
        Write-Host "  Service Principal: $(if($Config.UseServicePrincipal) { 'Enabled' } else { 'Disabled' })"
        Write-Host "  Auto Connect: $(if($Config.AutoConnect) { 'Enabled' } else { 'Disabled' })"
        Write-Host "  Export Path: $($Config.ExportPath)"
        Write-Host ""
        
        Write-Host "1. Configure Azure Service Principal"
        Write-Host "2. Set Export Path"
        Write-Host "3. Toggle Auto-Connect"
        Write-Host "4. View Current Configuration"
        Write-Host "5. Reset Configuration"
        Write-Host "6. Return to Main Menu"
        Write-Host ""
        
        $Choice = Read-Host "Please select an option (1-6)"
        
        switch ($Choice) {
            "1" { Set-ServicePrincipalConfig; Read-Host "Press Enter to continue" }
            "2" { Set-ExportPathConfig; Read-Host "Press Enter to continue" }
            "3" { Toggle-AutoConnect; Read-Host "Press Enter to continue" }
            "4" { Show-CurrentConfig; Read-Host "Press Enter to continue" }
            "5" { Reset-Configuration; Read-Host "Press Enter to continue" }
            "6" { return }
            default { Write-ColorOutput "Invalid selection. Please try again." "Red"; Start-Sleep 2 }
        }
    } while ($true)
}

# Function to configure service principal
function Set-ServicePrincipalConfig {
    Write-Host ""
    Write-Host "Configure Azure Service Principal Authentication" -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host ""
    
    $Config = Get-SecurityConfig
    
    $TenantId = Read-Host "Enter Tenant ID (Current: $($Config.TenantId))"
    if ($TenantId) { $Config.TenantId = $TenantId }
    
    $AppId = Read-Host "Enter Application (Client) ID (Current: $($Config.ApplicationId))"
    if ($AppId) { $Config.ApplicationId = $AppId }
    
    $CertThumbprint = Read-Host "Enter Certificate Thumbprint (Optional, Current: $($Config.CertificateThumbprint))"
    if ($CertThumbprint) { $Config.CertificateThumbprint = $CertThumbprint }
    
    $UseSP = Read-Host "Use Service Principal for authentication? (y/n) [Current: $(if($Config.UseServicePrincipal) {'y'} else {'n'})]"
    if ($UseSP -eq 'y' -or $UseSP -eq 'Y') {
        $Config.UseServicePrincipal = $true
    } elseif ($UseSP -eq 'n' -or $UseSP -eq 'N') {
        $Config.UseServicePrincipal = $false
    }
    
    Set-SecurityConfig -Config $Config
}

# Function to set export path
function Set-ExportPathConfig {
    $Config = Get-SecurityConfig
    
    Write-Host ""
    Write-Host "Current Export Path: $($Config.ExportPath)" -ForegroundColor Yellow
    $NewPath = Read-Host "Enter new export path (or press Enter to keep current)"
    
    if ($NewPath) {
        if (-not (Test-Path $NewPath)) {
            try {
                New-Item -Path $NewPath -ItemType Directory -Force | Out-Null
                Write-ColorOutput "Created directory: $NewPath" "Green"
            }
            catch {
                Write-ColorOutput "Error creating directory: $($_.Exception.Message)" "Red"
                return
            }
        }
        $Config.ExportPath = $NewPath
        Set-SecurityConfig -Config $Config
    }
}

# Function to toggle auto-connect
function Toggle-AutoConnect {
    $Config = Get-SecurityConfig
    $Config.AutoConnect = -not $Config.AutoConnect
    Set-SecurityConfig -Config $Config
    Write-ColorOutput "Auto-Connect is now: $(if($Config.AutoConnect) {'Enabled'} else {'Disabled'})" "Green"
}

# Function to show current configuration
function Show-CurrentConfig {
    $Config = Get-SecurityConfig
    
    Write-Host ""
    Write-Host "Current Configuration Details" -ForegroundColor Yellow
    Write-Host "============================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Tenant ID: $($Config.TenantId)"
    Write-Host "Application ID: $($Config.ApplicationId)"
    Write-Host "Certificate Thumbprint: $($Config.CertificateThumbprint)"
    Write-Host "Use Service Principal: $($Config.UseServicePrincipal)"
    Write-Host "Auto Connect: $($Config.AutoConnect)"
    Write-Host "Export Path: $($Config.ExportPath)"
    Write-Host "Log Level: $($Config.LogLevel)"
    Write-Host "Last Updated: $($Config.LastUpdated)"
    Write-Host "Configuration Version: $($Config.Version)"
    Write-Host ""
}

# Function to reset configuration
function Reset-Configuration {
    $Confirm = Read-Host "Are you sure you want to reset all configuration? (y/n)"
    if ($Confirm -eq 'y' -or $Confirm -eq 'Y') {
        try {
            Remove-Item -Path $script:ConfigFile -Force -ErrorAction Stop
            Initialize-SecurityConfig | Out-Null
            Write-ColorOutput "Configuration reset successfully." "Green"
        }
        catch {
            Write-ColorOutput "Error resetting configuration: $($_.Exception.Message)" "Red"
        }
    }
}

# Function to connect using saved configuration
function Connect-UsingConfig {
    $Config = Get-SecurityConfig
    
    if ($Config.UseServicePrincipal -and $Config.TenantId -and $Config.ApplicationId) {
        try {
            Write-ColorOutput "Connecting using saved Service Principal configuration..." "Yellow"
            
            if ($Config.CertificateThumbprint) {
                # Certificate-based authentication
                Connect-AzAccount -ServicePrincipal -TenantId $Config.TenantId -ApplicationId $Config.ApplicationId -CertificateThumbprint $Config.CertificateThumbprint
                Connect-MgGraph -TenantId $Config.TenantId -ClientId $Config.ApplicationId -CertificateThumbprint $Config.CertificateThumbprint
            } else {
                Write-ColorOutput "Certificate thumbprint not configured. Please use interactive authentication." "Yellow"
                return $false
            }
            
            Write-ColorOutput "Successfully connected using saved configuration." "Green"
            return $true
        }
        catch {
            Write-ColorOutput "Failed to connect using saved configuration: $($_.Exception.Message)" "Red"
            return $false
        }
    } else {
        Write-ColorOutput "Service Principal not configured or incomplete. Please configure in Settings." "Yellow"
        return $false
    }
}

Export-ModuleMember -Function Show-SettingsMenu, Get-SecurityConfig, Set-SecurityConfig, Connect-UsingConfig, Initialize-SecurityConfig

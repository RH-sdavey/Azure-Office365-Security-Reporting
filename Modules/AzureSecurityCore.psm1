# Azure Security Report - Core Module
# Contains shared utilities and common functions

# Global Variables
$script:LogFile = "AzureSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    Write-Host $LogEntry
}

# Function to display colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
    Write-Log -Message $Message -Level "INFO"
}

# Function to display title
function Show-Title {
    Clear-Host
    Write-Host "------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "              AZURE & OFFICE 365 SECURITY REPORT SCRIPT " -ForegroundColor Yellow
    Write-Host "               By github.com/SteffMet" -ForegroundColor Blue
    Write-Host "------------------------------------------------------------------"
    Write-Host ""
}

# Function to validate file path for CSV export
function Get-ValidFilePath {
    param([string]$DefaultName)
    
    do {
        $FilePath = Read-Host "Enter the full file path for export (or press Enter for current directory)"
        
        if ([string]::IsNullOrWhiteSpace($FilePath)) {
            $FilePath = Join-Path (Get-Location) "$DefaultName`_$script:Timestamp.csv"
        }
        
        # Ensure .csv extension
        if (-not $FilePath.EndsWith('.csv')) {
            $FilePath += '.csv'
        }
        
        try {
            $Directory = Split-Path $FilePath -Parent
            if (-not (Test-Path $Directory)) {
                New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
            }
            # Test write access
            $TestFile = Join-Path $Directory "test_write.txt"
            New-Item -ItemType File -Path $TestFile -Force -ErrorAction Stop | Out-Null
            Remove-Item -Path $TestFile -ErrorAction Stop
            return $FilePath
        } catch {
            Write-ColorOutput "Invalid file path or insufficient permissions. Please try again." "Red"
            Write-Log "Invalid file path or insufficient permissions: $($_.Exception.Message)" "ERROR"
        }
    } while ($true)
}

# Function to check and install required modules
function Test-RequiredModules {
    param([string[]]$RequiredModules)
    
    Write-ColorOutput "Checking required PowerShell modules..." "Yellow"
    $MissingModules = @()
    
    foreach ($Module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $Module)) {
            $MissingModules += $Module
            Write-ColorOutput "Module '$Module' is not installed." "Red"
        } else {
            Write-ColorOutput "Module '$Module' is installed." "Green"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-ColorOutput "Missing modules: $($MissingModules -join ', ')" "Red"
        $Install = Read-Host "Would you like to install the missing modules? (Y/N)"
        
        if ($Install -eq 'Y' -or $Install -eq 'y') {
            foreach ($Module in $MissingModules) {
                try {
                    Write-ColorOutput "Installing module: $Module" "Yellow"
                    Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                    Write-ColorOutput "Successfully installed: $Module" "Green"
                } catch {
                    Write-ColorOutput "Failed to install module: $Module. Error: $($_.Exception.Message)" "Red"
                    Write-Log "Failed to install module: $Module. Error: $($_.Exception.Message)" "ERROR"
                    return $false
                }
            }
        } else {
            Write-ColorOutput "Cannot proceed without required modules. Exiting..." "Red"
            Write-Log "Cannot proceed without required modules. Exiting..." "ERROR"
            return $false
        }
    }
    
    return $true
}

# Function to authenticate to Azure and Microsoft Graph
function Connect-AzureServices {
    Write-ColorOutput "Authenticating to Azure services..." "Yellow"
    
    try {
        # Connect to Azure
        Write-ColorOutput "Connecting to Azure..." "Yellow"
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-ColorOutput "Successfully connected to Azure." "Green"
        
        # Connect to Microsoft Graph with required scopes
        Write-ColorOutput "Connecting to Microsoft Graph..." "Yellow"
        $Scopes = @(
            "User.Read.All", 
            "Directory.Read.All", 
            "Policy.Read.ConditionalAccess", 
            "UserAuthenticationMethod.Read.All",
            "Organization.Read.All",
            "Reports.Read.All",
            "AuditLog.Read.All"
        )
        Connect-MgGraph -Scopes $Scopes -ErrorAction Stop | Out-Null
        
        # Verify granted scopes
        $GrantedScopes = (Get-MgContext).Scopes
        $MissingScopes = $Scopes | Where-Object { $_ -notin $GrantedScopes }
        if ($MissingScopes) {
            Write-ColorOutput "Warning: The following required scopes were not granted: $($MissingScopes -join ', ')" "Yellow"
            Write-Log "Missing scopes: $($MissingScopes -join ', ')" "WARNING"
        }
        
        Write-ColorOutput "Successfully connected to Microsoft Graph." "Green"
        return $true
    } catch {
        Write-ColorOutput "Authentication failed: $($_.Exception.Message)" "Red"
        Write-Log "Authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

Export-ModuleMember -Function Write-Log, Write-ColorOutput, Show-Title, Get-ValidFilePath, Test-RequiredModules, Connect-AzureServices -Variable LogFile, Timestamp

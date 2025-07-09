# Azure Security Report - Core Module
# Contains shared utilities and common functions

# Function to safely import Microsoft Graph modules
function Import-GraphModuleSafely {
    param(
        [string]$ModuleName
    )
    
    try {
        # First, try to remove any existing loaded modules to avoid conflicts
        $LoadedModule = Get-Module -Name $ModuleName -ErrorAction SilentlyContinue
        if ($LoadedModule) {
            Write-Log "Removing existing module: $ModuleName" "INFO"
            Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue
        }
        
        # Clear any cached assemblies (PowerShell 7+ feature)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        # Import the module with force and specific error handling
        Write-Log "Importing module: $ModuleName" "INFO"
        Import-Module -Name $ModuleName -Force -Scope Global -ErrorAction Stop
        
        Write-Log "Successfully imported: $ModuleName" "INFO"
        return $true
    }
    catch {
        Write-ColorOutput "Failed to import module $ModuleName`: $($_.Exception.Message)" "Red"
        Write-Log "Failed to import module $ModuleName`: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to reset PowerShell session for Graph modules
function Reset-GraphSession {
    Write-Log "Resetting Microsoft Graph session to resolve assembly conflicts..." "INFO"
    
    try {
        # Disconnect from Microsoft Graph
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        } catch {
            # Ignore disconnect errors
        }
        
        # Remove all Microsoft Graph modules
        $GraphModules = Get-Module -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue
        foreach ($Module in $GraphModules) {
            Write-Log "Removing Graph module: $($Module.Name)" "INFO"
            Remove-Module -Name $Module.Name -Force -ErrorAction SilentlyContinue
        }
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-Log "Graph session reset complete" "INFO"
        return $true
    }
    catch {
        Write-Log "Error during Graph session reset: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

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
        [string]$Color = "White",
        [bool]$Log = $true
    )
    Write-Host $Message -ForegroundColor $Color
    if ($Log) {
        Write-Log -Message $Message -Level "INFO"
    }
}

# Function to display title
function Show-Title {
    Clear-Host
    Write-ColorOutput "------------------------------------------------------------------" "Cyan" $false
    Write-ColorOutput "      AZURE & OFFICE 365 SECURITY AND REPORTING TOOLBOX      " "Yellow" $false
    Write-ColorOutput "------------------------------------------------------------------" "Cyan" $false
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
        # Check if we've already had assembly conflicts in this session
        if ($global:GraphAssemblyConflictDetected) {
            Write-ColorOutput "Assembly conflicts detected in this session. PowerShell restart recommended." "Yellow"
            $RestartScript = Join-Path $PSScriptRoot "..\Restart-PowerShellSession.ps1"
            if (Test-Path $RestartScript) {
                & $RestartScript
                return $false
            }
        }
        
        # Reset Graph session first to avoid assembly conflicts
        Reset-GraphSession
        
        # Import required Graph modules safely
        $GraphModules = @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Users", 
            "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Identity.DirectoryManagement",
            "Microsoft.Graph.Reports"
        )
        
        $ModuleImportFailed = $false
        foreach ($Module in $GraphModules) {
            if (-not (Import-GraphModuleSafely -ModuleName $Module)) {
                Write-ColorOutput "Failed to import required Graph module: $Module" "Red"
                $ModuleImportFailed = $true
                
                # Check if it's an assembly conflict
                if ((Get-Error | Select-Object -Last 1).Exception.Message -like "*Assembly with same name is already loaded*") {
                    $global:GraphAssemblyConflictDetected = $true
                    Write-ColorOutput "Assembly conflict detected. PowerShell session restart required." "Yellow"
                    
                    $RestartScript = Join-Path $PSScriptRoot "..\Restart-PowerShellSession.ps1"
                    if (Test-Path $RestartScript) {
                        Write-ColorOutput "Starting restart helper..." "Yellow"
                        & $RestartScript
                        return $false
                    } else {
                        Write-ColorOutput "Please exit PowerShell and start a fresh session, then run the script again." "Yellow"
                        return $false
                    }
                }
            }
        }
        
        if ($ModuleImportFailed) {
            return $false
        }
        
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
        
        # If authentication fails due to assembly conflicts, suggest restart
        if ($_.Exception.Message -like "*Assembly with same name is already loaded*") {
            $global:GraphAssemblyConflictDetected = $true
            Write-ColorOutput "Assembly conflict detected. PowerShell session restart required." "Yellow"
            Write-Log "Assembly conflict detected. Restart recommended." "WARNING"
            
            $RestartScript = Join-Path $PSScriptRoot "..\Restart-PowerShellSession.ps1"
            if (Test-Path $RestartScript) {
                Write-ColorOutput "Starting restart helper..." "Yellow"
                & $RestartScript
                return $false
            }
        }
        return $false
    }
}

Export-ModuleMember -Function Write-Log, Write-ColorOutput, Show-Title, Get-ValidFilePath, Test-RequiredModules, Connect-AzureServices, Import-GraphModuleSafely, Reset-GraphSession -Variable LogFile, Timestamp

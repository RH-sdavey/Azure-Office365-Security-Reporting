# Fix-GraphModules.ps1 - Utility script to resolve Microsoft Graph assembly conflicts
# Run this if you encounter assembly conflicts with Microsoft Graph modules

Write-Host "Fixing Microsoft Graph module assembly conflicts..." -ForegroundColor Yellow

try {
    # Disconnect from Microsoft Graph
    Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Green
    } catch {
        Write-Host "No active Graph session to disconnect." -ForegroundColor Gray
    }
    
    # Remove all Microsoft Graph modules
    Write-Host "Removing all Microsoft Graph modules..." -ForegroundColor Yellow
    $GraphModules = Get-Module -Name "Microsoft.Graph*" -ErrorAction SilentlyContinue
    
    if ($GraphModules.Count -eq 0) {
        Write-Host "No Microsoft Graph modules currently loaded." -ForegroundColor Gray
    } else {
        foreach ($Module in $GraphModules) {
            Write-Host "Removing: $($Module.Name)" -ForegroundColor Gray
            Remove-Module -Name $Module.Name -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Removed $($GraphModules.Count) Microsoft Graph modules." -ForegroundColor Green
    }
    
    # Force garbage collection
    Write-Host "Clearing memory cache..." -ForegroundColor Yellow
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    Write-Host "Memory cache cleared." -ForegroundColor Green
    
    Write-Host "`nMicrosoft Graph modules have been reset." -ForegroundColor Green
    Write-Host "You can now run your Azure Security Report script." -ForegroundColor Green
    
} catch {
    Write-Host "Error during Graph module reset: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You may need to restart PowerShell completely." -ForegroundColor Yellow
}

Write-Host "`nPress Enter to continue..." -ForegroundColor Cyan
Read-Host

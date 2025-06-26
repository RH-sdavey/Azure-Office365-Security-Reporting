# Build script to combine modules into single deployable file
param(
    [string]$OutputPath = "AzureSecurityReport-Compiled.ps1"
)

Write-Host "Building single-file deployment..." -ForegroundColor Yellow

$ModulesPath = Join-Path $PSScriptRoot "Modules"
$MainScript = Join-Path $PSScriptRoot "AzureSecurityReport-Modular.ps1"

# Combine all module content
$CombinedContent = @"
#Requires -Version 7.0
<#
.SYNOPSIS
    Azure Security Report - Compiled Single File
.DESCRIPTION
    Auto-generated from modular components
.AUTHOR
    github.com/SteffMet
.VERSION
    2.0-Compiled
.DATE
    $(Get-Date -Format "yyyy-MM-dd")
#>

"@

# Add each module content (without Import-Module statements)
Get-ChildItem -Path $ModulesPath -Filter "*.psm1" | ForEach-Object {
    $Content = Get-Content $_.FullName -Raw
    # Remove Import-Module lines and Export-ModuleMember lines
    $CleanContent = $Content -replace "Import-Module.*", "" -replace "Export-ModuleMember.*", ""
    $CombinedContent += "`n# === $($_.BaseName) Module ===`n"
    $CombinedContent += $CleanContent
    $CombinedContent += "`n"
}

# Add main script content (without Import-Module statements)
$MainContent = Get-Content $MainScript -Raw
$CleanMainContent = $MainContent -replace "Import-Module.*", ""
$CombinedContent += "`n# === Main Script ===`n"
$CombinedContent += $CleanMainContent

# Write to output file
$CombinedContent | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Compiled script created: $OutputPath" -ForegroundColor Green
Write-Host "File size: $([math]::Round((Get-Item $OutputPath).Length / 1KB, 2)) KB" -ForegroundColor Cyan

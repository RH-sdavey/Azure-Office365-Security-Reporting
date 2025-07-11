function Get-AzureComputeDCRReport {
    <#
    .SYNOPSIS
        Retrieves Data Collection Rule (DCR) associations for Azure Virtual Machines.
    .DESCRIPTION
        This function queries Azure Monitor to find all Data Collection Rules associated with Virtual Machines.
    .EXAMPLE
        Get-AzureComputeDCRReport
    #>
    $query = @"
securityresources
| where type == "microsoft.security/assessments"
| extend description = tostring(properties.metadata.description)
| extend displayName = tostring(properties.displayName)
| extend severity = tostring(properties.metadata.severity)
| extend remediationDescription = tostring(properties.metadata.remediationDescription)
| extend policyDefinitionId = tostring(properties.metadata.policyDefinitionId)
| extend implementationEffort = tostring(properties.metadata.implementationEffort)
| extend userImpact = tostring(properties.metadata.userImpact)
| distinct name, description, displayName, severity, remediationDescription, policyDefinitionId, implementationEffort, userImpact
"@
    
    Write-ColorOutput "Retrieving Data Collection Rule associations for Azure Virtual Machines..." "Cyan"
    
    try {
        $results = Search-AzGraph -Query $query -ErrorAction Stop
        if ($results.Count -eq 0) {
            Write-ColorOutput "No Data Collection Rules found for any Virtual Machines." "Yellow"
        } else {
            $results | Format-Table -AutoSize
        }
    } catch {
        Write-ColorOutput "Error retrieving DCR report: $_" "Red"
    }
}
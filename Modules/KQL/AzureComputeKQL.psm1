$query = @"
insightsresources
| where type == 'microsoft.insights/datacollectionruleassociations'
    | where id contains 'microsoft.compute/virtualmachines/'
| project id = trim_start('/', tolower(id)), properties
| extend idComponents = split(id, '/')
| extend subscription = tolower(tostring(idComponents[1])), resourceGroup = tolower(tostring(idComponents[3])), vmName = tolower(tostring(idComponents[7]))
| extend dcrId = properties['dataCollectionRuleId']
| where isnotnull(dcrId)
| extend dcrId = tostring(dcrId)
| summarize dcrList = make_list(dcrId), dcrCount = count() by subscription, resourceGroup, vmName
| sort by dcrCount desc
"@


function Get-AzureComputeDCRReport {
    <#
    .SYNOPSIS
        Retrieves Data Collection Rule (DCR) associations for Azure Virtual Machines.
    .DESCRIPTION
        This function queries Azure Monitor to find all Data Collection Rules associated with Virtual Machines.
    .EXAMPLE
        Get-AzureComputeDCRReport
    #>
    
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
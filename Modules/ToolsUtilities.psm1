function Convert-NameToObjectID {
    $Name = read-host "Enter a users name to convert to Object ID: "

    if (-not $Name) {
        Write-ColorOutput "Name cannot be empty." "Red"
        return
    }

    try {
        $User = get-mgUser -Filter "DisplayName eq '$Name'" -ErrorAction Stop
        if ($User) {
            Write-ColorOutput "Object ID for '$Name': $($User.ObjectId)" "Green"
        } else {
            Write-ColorOutput "No user found with the name '$Name'." "Red"
        }
    } catch {
        Write-ColorOutput "Error retrieving user: $_" "Red"
    }
}

function Convert-ObjectIDToName {
    $ObjectID = read-host "Enter an Object ID to convert to Name: "

    if (-not $ObjectID) {
        Write-ColorOutput "Object ID cannot be empty." "Red"
        return
    }

    try {
        $User = Get-MGUser -UserId $ObjectID -ErrorAction Stop
        if ($User) {
            Write-ColorOutput "Name for Object ID '$ObjectID': $($User.DisplayName)" "Green"
        } else {            Write-ColorOutput "No user found with the Object ID '$ObjectID'." "Red"
        }
    } catch {
        Write-ColorOutput "Error retrieving user: $_" "Red"
    }

}
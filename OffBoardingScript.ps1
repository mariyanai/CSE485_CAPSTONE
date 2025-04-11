#TODO:
# 1. work out how to format output
# 2. connect to apis
# 3. clear-host ????
# 4. automatic

$output = ""

Write-Host "Choose mode:"
Write-Host "1. Interactive"
Write-Host "2. Automatic"

$mode = Read-Host "Enter a number (1-2)"

switch ($mode){
    # Interactive (manual) mode
    "1" {
        $username = Read-Host "Please enter a username."
        try{
            $user = Get-ADUser -properties * $username
        }
        catch{
            Write-Host "Invalid username."
        }

        do {
            
            #Print menu and prompt user to choose a task
            Write-Host "Now editing: $username"
            Write-Host "Select a task to run:"
            Write-Host "1. Set AD account expiration date."
            Write-Host "2. Reset account password."
            Write-Host "3. Update user description field in AD with off-boarding reason."
            Write-Host "4. Suspend Okta access."
            Write-Host "5. Sign out user from all Office 365 sessions."
            Write-Host "6. Disable Exchange ActiveSync"
            Write-Host "7. Select new user."
            Write-Host "8. Exit."

            $choice = Read-Host "Enter a number 1-8"

            switch ($choice) {
                #1: Set AD account expiration date
                "1" {
                    $dateInput = Read-Host "Enter an expiration date and time: MM/DD/YYYY HH:MM"
                    try{
                        $expirationDate = [DateTime]::Parse($dateInput)

                        $user.AccountExpirationDate = $expirationDate
                        Write-Host $user.AccountExpirationDate

                        #Get-ADUser -Filter * -SearchBase "OU=_Users,DC=acctcom,DC=mesa" -Properties Name, SamAccountName | Select-Object Name, SamAccountName
                    }
                    catch{
                        Write-Host "Please enter a valid date and time."
                    }  
                }
                #2: Reset account password
                "2" {  
                }
                #3: Update user description field in AD with offboarding reason
                "3" {
                    $reason = Read-Host "Enter offboarding reason."
                    $user.Description += " - Offboarding Reason: "
                    $user.Description += $($reason)
                    Write-Host $user.Description
                }
                #4: Suspend user Okta access
                "4" {    
                }
                #5: Sign out user from all O365 sessions
                "5" {   
                }
                #6: Disable Exchange ActiveSync
                "6" {     
                }
                #7: Enter a new user to edit
                "7" {  
                    $username = Read-Host "Please enter a new username."
                    try{
                        $user = Get-ADUser -properties * $username
                    }
                    catch{
                        Write-Host "Invalid username."
                    }   
                }
                #8: Exit program
                "8" {
                    Write-Host "yo mama fat chungus"
                    exit     
                }
            }
        }
        while($choice -ne "8")   
    }
    "2" {
    }
    Default {
        Write-Host "Please enter a valid number."
    }
}



 #TODO:
# 1. work out how to format output file
# 2. connect to APIs
# 3. clear-host ????
# 4. do automatic mode

#Set Paramter for CSV file for Automatic Mode
param (
    [Parameter(Mandatory = $false)]
    [string]$CsvFilePath
)

#Check for CSV file parameter
if ($CsvFilePath) {
    if (-Not (Test-Path $CsvFilePath)) {
        Write-Host "The file '$CsvFilePath' does not exist."
        exit
    } 
    $mode = 2

} else {
  
  $mode = 1
}

$CurrentDate = Get-Date
$output = "Date of Execution: $CurrentDate`n"


function setExpDate() {
    param (
        [datetime]$dateInput,
        [string]$username
    )
    try{
        $expirationDate = [DateTime]::Parse($dateInput)
        #TO-DO: Change to Set-ADUser using service account creds
        $user.AccountExpirationDate = $expirationDate
        Write-Host $user.AccountExpirationDate

        #Get-ADUser -Filter * -SearchBase "OU=_Users,DC=acctcom,DC=mesa" -Properties Name, SamAccountName | Select-Object Name, SamAccountName
        }
        catch{
            Write-Host "Please enter a valid date and time."
        } 
}

function Verify-Usernames { #this function is intended to verify if the users exist, if they do not exist
    param (
        [string]$filePath
    )

    # Read each line of the CSV file (usernames)
    $usernames = Get-Content -Path $filePath
    $allUsernames = Get-ADUser -Filter * -Properties SamAccountName #there is probably an optimization for this
    $validUsernames = @() #init array

    # Iterate through each username
    foreach ($username in $usernames) {
        #check if the user exists within Mesa
        if($allUsernames.SamAccountName -contains $username) {
            Write-Host "Valid user: $username"
            $validUsernames += $username
        }
        else{
            Write-Host "Invalid user: $username"
            $output += "This username is invalid and no operations will be done on it: $username`n"
        }    
    }
    return $validUsernames
}

function resetAccPass() {
    param (
  
    )
}

function updateUserDescr() {
    param (
        [string]$reason = "No offboarding reason provided",
        [string]$username
    )
    #TO-DO: Change to Set-ADUser using service account creds
    $user.Description += " - Offboarding Reason: "
    $output += "$username's description changed to: $reason \n" #need to test to see if this works
    user.Description += $($reason)
    Write-Host $user.Description
}

function susOkta() {
    param (

    )
}

function signOutO365() {
    param (
    [string] $username
    )
    $userObj = Get-AzureADUser -ObjectId $user #gets user based object using azure, but im not sure if we have access

    $uri = "https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions" #swap userID for appropriate field


    $headers = @{
    "Authorization" = "Bearer {access_token}" #we need an access token if going the Microsoft Graph path
    "Content-Type"  = "application/json"
    }

    #Invoke-RestMethod -Uri $uri -Method POST -Headers $headers  #actually call it 

}

function disableActiveSync() {
    param (

    )
}
if ($CsvFilePath) {
    if (-Not (Test-Path $CsvFilePath)) {
        Write-Host "The file '$CsvFilePath' does not exist."
        exit
    } 
    $mode = 2

} else {
    $mode = 1
}


#Write-Host "Choose mode:"
#Write-Host "1. Interactive"
#Write-Host "2. Automatic"

#$mode = Read-Host "Enter a number (1-2)"

switch ($mode){
    # Interactive (manual) mode
    "1" {
        $username = Read-Host "Please enter a username"
        try{
            $user = Get-ADUser -properties * $username
        }
        catch{
            Write-Host "Invalid username."
        }
        #if user is invalid, do not continue normally
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
                    setExpDate($dateInput, $user)  
                }
                #2: Reset account password
                "2" {  
                }
                #3: Update user description field in AD with offboarding reason
                "3" {
                    $reason = Read-Host "Enter offboarding reason."
                    updateUserDescr($reason, $user)
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
                    Write-Host "Exit"
                    exit     
                }
            }
        }
        while($choice -ne "8")   
    }

    #Automatic Mode (Using CSV file) we should probably make this an if else
    "2" {
        $data = Import-Csv -Path $CsvFilePath
        Write-Host "Entered Automatic Mode"
        $verifiedUsers = Verify-Usernames($CsvFilePath) #zz not sure if we need to parse other input for when passwords expire and what not
        Write-Host "List of valid usernames:" $verifiedUsers #this works!
        $output += "List of valid usernames: " + ($verifiedUsers -join ", ")
        Write-Host $output

        #we should probably perform the neccessary operations in order
        foreach ($username in $verifiedUsers) {
            updateUserDescr -username $username #3
        }
        

        Set-Content -Path "C:\Users\mivanov\OffBoardingScript\output.txt" -Value $output
    }
}


 

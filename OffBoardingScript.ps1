 #TODO:
# 1. work out how to format output file
# 2. connect to APIs
# 3. clear-host ????
# 4. do automatic mode
# 5. Do Start-Sleep when writing new AD properties to log file so server can update in time

#Testing User:
#U: duser

#-----------------------------------------------------------------------------------------------------------#

#Set Paramter for CSV file for Automatic Mode
param (
    [Parameter(Mandatory = $false)]
    [string]$CsvFilePath
)

#Imports:
Import-Module ExchangeOnlineManagement

#Create output log file
$global:output = ""

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


#Set credentials for service account
$Credentials = New-Object System.Management.Automation.PSCredential `
    -ArgumentList 'udeprosa', (ConvertTo-SecureString 'WM2G!ghGRY=d*2BYg7s#bY3t' -AsPlainText -Force)

function Verify-Usernames { #this function is intended to verify if the users exist
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
            $global:output += "This username is invalid and no operations will be done on it: $username`n" #output doesnt work this way
        }    
    }
    return $validUsernames
}


function setExpDate {
    param (
        [datetime]$dateInput,
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )
    try{
        Write-Host "Enter setExpDate"
        Set-ADUser -Identity $username -AccountExpirationDate $dateInput -Credential $Credentials

        }
        catch{
            Write-Host "Please enter a valid date and time."
        } 
}

function resetAccPass {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )

    function GenerateRanPassword {
        param (
            [int]$length = 12
        )

        Add-Type -AssemblyName System.Web
        [System.Web.Security.Membership]::GeneratePassword($length, 0)

    }

    $newPassword = GenerateRanPassword
    Set-ADAccountPassword -Identity $username `
                          -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) `
                          -Reset `
                          -Credential $Credentials
    Unlock-ADAccount -Identity $username -Credential $Credentials
    Set-ADUser -Identity $username -ChangePasswordAtLogon $true -Credential $Credentials
    Write-Host "Password has been reset to: $newPassword, forced password change on next login."
}

function updateUserDescr() {
    param (
        [string]$reason,
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )

    $reason = " - Offboarding Reason: " + $reason
    $Description = (Get-ADUser -Identity $username -Properties Description).Description
    $Description += $reason
    Set-ADUser -Identity $username -Description $Description -Credential $Credentials
    Write-Host (Get-ADUser -Identity $username -Properties Description).Description

}

function resetUserDescr {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )
    Set-ADUser -Identity $username -Description "DoIT - Automation test account" -Credential $Credentials
}

function getOktaId { #helper, we need the UUID to disable account
    param (
        [string]$userToGetID
    )

    $email = (Get-ADUser -Identity $userToGetID -Properties mail).mail
    #adding to output for testing 
    $global:output += "Using email $($email)"
    Write-Host "Current output content: $output"

    if (-not $email) {
        Write-Error "Email address for user $userToGetID is not found in Active Directory."
        return
    }

    $oktaDomain = "https://mesaaz.okta.com"  # Okta Domain could be wrong
    $apiToken = "someToken IS this okay to put in the code?" 

    $headers = @{
        "Authorization" = "SSWS $apiToken"
        "Content-Type"  = "application/json"
    }

    $url = "$oktaDomain/api/v1/users?q=$email"  # Use email to search in Okta API

    try {
        # Get the user details from Okta API
        $user = Invoke-RestMethod -Uri $url -Method Get -Headers $headers

        # Extract the userId from the response
        $userId = $user.id

        # Output the userId
        Write-Output "The userId for $email is: $userId"
        return $userId
    } catch {
        Write-Error "An error occurred while retrieving the user: $_" #returning 401 which is fine for now
        $output += "An error occurred while retrieving the user: $_"
    }
}


function susOkta {
    param (
        [string] $userID

    )

    #Install-Module -Name Okta 
    #hesitant to do this wanted to be sure

    $oktaDomain = "https://cityOfMesa.okta.com" #url is probably something like this 
    $API_token = "i think this will be given to us!" 

    $headers = @{
    "Authorization" = "SSWS $apiToken"
    "Content-Type"  = "application/json"
     }

     $body = @{
         "status" = "LOCKED_OUT"
      } | ConvertTo-Json

     $url = "$oktaDomain/api/v1/users/$userID/lifecycle"

     try {
        $reponse = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body #send the actual request
        Write-Host "Response from Okta API:"
        Write-Host $response
        $global:output += $response + "`n"

     } catch {
         Write-Host $global:output
         Write-Host "An error occurred: $_"
         $global:output += "An error occurred: $_" + "`n"

     }




}

function signOutO365 {
    param (

    )
}

function disableActiveSync {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )

    Connect-ExchangeOnline -UserPrincipalName "udeprosa@mesaaz.gov" -Device
    Write-Host Get-CASMailbox -Identity $username | Select Name, ActiveSyncEnabled
    Disconnect-ExchangeOnline -Confirm:$false

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


switch ($mode){
    # Interactive (manual) mode
    "1" {
        $inputUsername = Read-Host "Please enter a username"
        try{
            $user = Get-ADUser -Identity $inputUsername -properties *
        }
        catch{
            Write-Host "Invalid username."
        }
        #if user is invalid, do not continue normally
        do {
            
            #Print menu and prompt user to choose a task
            Write-Host "Now editing: $inputUsername"
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
                    $dateInput = $dateInput.Trim()
                    
                    #$dateInput = [DateTime]::Parse($dateInput)
                    $dateInput = [datetime]::ParseExact($dateInput, 'MM/dd/yyyy HH:mm', $null)
                    Write-Host "Parsed date: $dateInput"
                    Write-Host "Type of dateInput: $($dateInput.GetType().FullName)"
                    setExpDate $dateInput $user  
             
                }
                #2: Reset account password
                "2" {  
                    resetAccPass $user
                    Write-Host "Password has been reset, force password change at next login."
                }
                #3: Update user description field in AD with offboarding reason
                "3" {
                    $reason = Read-Host "Enter offboarding reason"
                    #updateUserDescr $reason $user
                    resetUserDescr $user 
                    (Get-ADUser -Identity duser -properties Description).Description
                }
                #4: Suspend user Okta access
                "4" {
                Write-Host $user    
                    $userID = getOktaId $inputUsername
                    Write-Host $userID
                }
                #5: Sign out user from all O365 sessions
                "5" {   
                }
                #6: Disable Exchange ActiveSync
                "6" {
                    disableActiveSync $user     
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
                    $global:output += "Exiting `n"  #output seems to be broken 
                    Set-Content -Path "C:\Users\mivanov\OffBoardingScript\output.txt" -Value $output
                    exit     
                }
            }
        }
        while($choice -ne "8")   
    }

    #Automatic Mode (Using CSV file)
    "2" {
        $data = Import-Csv -Path $CsvFilePath
        Write-Host "Entered Automatic Mode"

        $verifiedUsers = Verify-Usernames($CsvFilePath) #zz not sure if we need to parse other input for when passwords expire and what not
        Write-Host "List of valid usernames:" $verifiedUsers #this works!
        $global:output += "List of valid usernames: " + ($verifiedUsers -join ", ")
        Write-Host $global:output

        #we should probably perform the neccessary operations in order
        foreach ($username in $verifiedUsers) {
            #updateUserDescr -username $username #3

        }
        
        Set-Content -Path "C:\Users\mivanov\OffBoardingScript\output.txt" -Value $global:output
    }
}


 

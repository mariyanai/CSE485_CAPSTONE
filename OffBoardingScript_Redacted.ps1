#NOTE: API keys, credentials, etc. have been REDACTED for security.
#All instances have been replaced for GitHub purposes, but actual values remain in use for City Of Mesa.

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

$mode = 0

if ($CsvFilePath) {
    if (-Not (Test-Path $CsvFilePath)) {
        Write-Host "The file '$CsvFilePath' does not exist."
        exit
    } 
    $mode = 2

} else {
    $mode = 1
}


# Set credentials for service account
$Credentials = New-Object System.Management.Automation.PSCredential `
    -ArgumentList 'meow', (ConvertTo-SecureString 'meow' -AsPlainText -Force)

# This function is intended to verify if the users exist
function Verify-Usernames {
    param (
        [string]$filePath
    )

    # Fetch all database usernames
    $allUsernames = Get-ADUser -Filter * -Properties SamAccountName

    # Arrays to store valid user info
    $validUsernames = @()
    $invalidUsernames = @()
    $expirationDateTimes = @()
    $times = @()
    $offboardReasons = @()

    # Import CSV
    $csvData = Import-Csv -Path $filePath

    # Iterate through each username
    foreach ($entry in $csvData) {
        $username = $entry.username.Trim()
        $date = $entry.'expiration date'.Trim()
        $time = $entry.time.Trim()
        $reason = $entry.'offboard reason'.Trim()
        
        # Check if the user exists within Mesa & store user info
        if($allUsernames.SamAccountName -contains $username) {
            # Validate user in AD
            #Write-Host "Valid user: $username"
            $validUsernames += $username

            # Combine date + time into full datetime string
            $dateTimeString = "$date $time"
            $expirationDT = [datetime]::Parse($dateTimeString)
            $expirationDateTimes += $expirationDT

            # Add offboarding reason
            $offboardReasons += $reason
        }
        else{
            #Write-Host "Invalid user: $username"
            $invalidUsernames += $username
        }    
    }

    # Return all arrays in hash table for easy access
    return [PSCustomObject]@{ 
        ValidUsernames = $validUsernames
        InvalidUsernames = $invalidUsernames 
        ExpirationDateTimes = $expirationDateTimes
        OffboardReasons = $offboardReasons
    }
}

function setExpDate {
    param (
        [datetime]$dateInput,
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )
    try{
        Set-ADUser -Identity $username -AccountExpirationDate $dateInput -Credential $Credentials

        }
        catch{
            Write-Error "Please enter a valid date and time."
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
    #Write-Host (Get-ADUser -Identity $username -Properties Description).Description
}

# Helper Function for Dummie Account
function resetUserDescr {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )
    Set-ADUser -Identity $username -Description "DoIT - Automation test account" -Credential $Credentials
}

# Helper function, UUID is needed to disable account
function getOktaId {
    param (
        [string]$userToGetID
    )

    $email = (Get-ADUser -Identity $userToGetID -Properties mail).mail
    #adding to output for testing 
    #$global:output += "Using email $($email)"
    #Write-Host "Current output content: $output"

    if (-not $email) {
        Write-Error "Email address for user $userToGetID is not found in Active Directory."
        return
    }

    $oktaDomain = "https://mesaaz.okta.com"
    $apiToken = "meow" 

    $headers = @{
        "Authorization" = "SSWS $apiToken"
        "Content-Type"  = "application/json"
    }
     # Use email to search in Okta API
    $url = "$oktaDomain/api/v1/users?q=$email"

    try {
        # Get the user details from Okta API
        $user = Invoke-RestMethod -Uri $url -Method Get -Headers $headers

        # Extract the userId from the response
        $userId = $user.id

        # Output the userId
        #Write-Output "The userId for $email is: $userId"
        return $userId
    } catch {
        Write-Error "An error occurred while retrieving the user: $_"
        $output += "An error occurred while retrieving the user: $_"
    }
}

function susOkta {
    param (
        [string] $userID

    )

    #Install-Module -Name Okta 

    $oktaDomain = "https://mesaaz.okta.com"
    $API_token = "meow" 

    $headers = @{
    "Authorization" = "SSWS $apiToken"
    "Content-Type"  = "application/json"
     }

     $body = @{
         "status" = "LOCKED_OUT"
      } | ConvertTo-Json

     $url = "$oktaDomain/api/v1/users/$userID/lifecycle"

     try {
        $reponse = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
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
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )

    # App registration info
    $clientId = "meow" #Application identifier
    $tenantId = "meow" #Azure directory location
    $clientSecret = "meow" #App password

    # Token endpoint: requests a token
    $tokenUrl = "meow"

    $body = @{
        client_id = $clientId
        scope  = "https://graph.microsoft.com/.default" #Access Microsoft Graph API
        client_secret = $clientSecret
        grant_type = "client_credentials"
    }

    # Request token
    $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
    $accessToken = $response.access_token

    # For checking contents of token
    #$accessToken | Out-File -FilePath "token.txt"

    # API endpoint
    $urlUser = $username.UserPrincipalName
    $graphUrl = "meow" #Endpont for signing out user
    #$graphUrl = "meow"

    # Set headers
    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    #Send request to sign out user
    $result = Invoke-RestMethod -Method POST -Uri $graphUrl -Headers $headers
}

function disableActiveSync {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$username
    )

    # Find and open credential file for certificate password
    $credFile = "C:\COM\Cred.txt"
    $cred = Get-Content $credFile | ConvertTo-SecureString -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    # Connect to Exchange Online using certificate
    Connect-ExchangeOnline -AppId "meow" `
        -CertificateFilePath "meow" `
        -CertificateThumbPrint "meow" `
        -Organization "mesaarizona.onmicrosoft.com"

    # NOTE: Using Get command rather than Set for testing
    Get-CASMailbox -Identity "ttrent@mesaaz.gov" | Select Name, ActiveSyncEnabled
    #Set-CASMailbox -Identity $username.UserPrincipalName -ActiveSyncEnabled $false
    Disconnect-ExchangeOnline -Confirm:$false
}

function Send-Mail{	param($subject,$attachment)    $body = "Hi Team, `nPlease find the attached output file from the offboarding script.`n`nThanks."    #TO-DO: Change to desire output file location    #$attachment = "C:\Users\mivanov\OffBoardingScript\output.txt"	$smtp = new-object system.net.mail.smtpClient("mailhost.acctcom.mesa")	$mail = new-object System.Net.Mail.MailMessage	$mail.from = "DoNotReply@mesaaz.gov"	$mail.to.add($to)	$mail.subject = $subject	$mail.body = $body	$mail.IsBodyHtml = $false		$mail.Attachments.Add($attachment)	$smtp.send($mail)}

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
                    updateUserDescr $reason $user
                    #resetUserDescr $user 
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
                    signOutO365 $user   
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
        Write-Host "Automatic Mode Enabled. Processing users from CSV without prompts...`n"

        # Parse valid usernames, returns hash table of info
        $result = Verify-Usernames($CsvFilePath)

        # Check if all usernames entered are invalid
        if ($result.ValidUsernames.Count -eq 0) {
            Write-Host "No usernames in CSV file are valid.`n"
            Exit
        }

        $now = Get-Date
        $global:output += "Date/Time of Execution: $now`n"
        $global:output += "List of Valid Usernames Entered: " + ($result.ValidUsernames -join ", ") + "`n"

        # Perform function calls for every valid username entered
        for ($i = 0; $i -lt $result.ValidUsernames.Count; $i++) {

            $userObj = Get-ADUser -Identity $result.ValidUsernames[$i] -Properties *

            # #1: Set Expiration Date
            try {
                setExpDate $result.ExpirationDateTimes[$i] $userObj
                $global:output += "    $($result.ValidUsernames[$i]): Expiration date/time set to $($result.ExpirationDateTimes[$i])`n"
            } catch {
                Write-Host "Error setting expiration date for: $($result.ValidUsernames[$i])"
            }

            # #2: Reset Account Password
            try {
                resetAccPass $userObj
                $global:output += "    $($result.ValidUsernames[$i]): Password reset and forced change at next login`n"
            } catch {
                Write-Host "ERROR resetting password for: $($result.ValidUsernames[$i])"
            }

            # #3: Add Offboarding Reason to AD
            try {
                if (-not [string]::IsNullOrWhiteSpace($result.OffboardReasons[$i])) {
                    #updateUserDescr $result.OffboardReasons[$i] $userObj
                    resetUserDescr $userObj
                    $global:output += "    $($result.ValidUsernames[$i]): Offboard reason added to AD`n"
                }
            } catch {
                Write-Host "ERROR adding offboard reason to AD for: $($result.ValidUsernames[$i])"
            }

            # #4: Suspend OKTA acess
            # NOTE: not functional for testing/safety purposes
            try {
                $oktaID = getOktaID $result.ValidUsernames[$i]
                #susOkta $oktaID
                $global:output += "    $($result.ValidUsernames[$i]): OKTA access suspended`n"
            } catch {
                Write-Host "ERROR suspending OKTA access for: $($result.ValidUsernames[$i])"
            }

            # #5: Sign Out User From O365 Sessions
            try {
                signOutO365 $userObj
                $global:output += "    $($result.ValidUsernames[$i]): Signed out from all O365 sessions`n"
            } catch {
                Write-Host "ERROR signing out of O365 sessions for: $($result.ValidUsernames[$i])"
            }

            # #6: Disable Exchange ActiveSync
            # TO-DO: Permission issues with using certificate method/UserDepro
            try {
                #disableActiveSync $userObj
                $global:output += "    $($result.ValidUsernames[$i]): Exchange ActiveSync Disabled`n"
            } catch {
                Write-Host "ERROR disabling ActiveSync for: $($result.ValidUsernames[$i])"
            }

            $global:output += "`n"

        }

        # Notify User of invalid Usernames
        $global:output += "The following usernames entered are invalid and no actions were performed: "
        for ($i = 0; $i -lt $result.InvalidUsernames.Count; $i++) {
            $global:output += "$($result.InvalidUsernames[$i] -join ", ") "
        }

        $global:output += "`n"
        
        Write-Host $global:output
        Set-Content -Path "C:\Users\mivanov\OffBoardingScript\output.txt" -Value $global:output

        Send-Mail
    }
}


 
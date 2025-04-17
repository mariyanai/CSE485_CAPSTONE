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

#Create output log file
$output = ""

#Set credentials for service account
$Credentials = New-Object System.Management.Automation.PSCredential `
    -ArgumentList 'udeprosa', (ConvertTo-SecureString 'WM2G!ghGRY=d*2BYg7s#bY3t' -AsPlainText -Force)

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

function susOkta {
    param (

    )
}

function signOutO365 {
    param (

    )
}

function disableActiveSync {
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

$output = ""

switch ($mode){
    # Interactive (manual) mode
    "1" {
        $username = Read-Host "Please enter a username"
        try{
            $user = Get-ADUser -Identity $username -properties *
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

    #Automatic Mode (Using CSV file)
    "2" {
        $data = Import-Csv -Path $CsvFilePath
        Write-Host "Entered Automatic Mode"
    }
}



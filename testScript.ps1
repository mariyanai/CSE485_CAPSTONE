#Automatic Password Expiration Email Reminder Script

function Send-Mail{
	param($from,$to,$subject,$body,$expiryDate,$fullName,$days)

$body = @"
<!DOCTYPE html>
<html>
<head>
    <title>Password Expiry Reminder</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        .container {
            max-width: 600px;
            margin: auto;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 10px;
            background-color: #f9f9f9;
        }
        h2 {
            color: #d9534f;
        }
        ul {
            padding-left: 20px;
        }
        .note {
            font-style: italic;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>$fullName,</h2>
        <p><strong>Reminder:</strong> Your Windows password will expire in less than <strong>$days day(s)</strong>.</p>
        
        <p><strong>IMPORTANT:</strong> If you do not change your Windows password before it expires, your account may become locked out and you will not be able to access City resources.</p>
        
        <p>To change your Windows domain password:</p>
        <ul>
            <li>Browse to <a href="https://mesaaz.okta.com" target="_blank">https://mesaaz.okta.com</a>.</li>
            <li>Click the drop-down menu to the right of your name near the upper right corner of the screen and select <strong>Settings</strong>.</li>
            <li>Click the <strong>Edit Profile</strong> button and enter your <strong>CURRENT</strong> password when prompted.</li>
            <li>Scroll down to the <strong>Change Windows Password</strong> section.</li>
            <li>Enter your current password, new password, and verify the new password.</li>
            <li>Click the <strong>Change Password</strong> button.</li>
        </ul>
        
        <p class="note"><strong>NOTE:</strong> If your password has <strong>EXPIRED</strong>, you will need to answer your Forgotten Password Question AND enter a mobile phone number to receive a password reset code. Alternatively, you can contact the DoIT Help Desk for assistance.</p>
        
        <p>Once you have changed your password, please remember to:</p>
        <ul>
            <li>Close Outlook (and any other open Office applications) and reopen. You may be prompted to enter your Office 365 credentials, as well as your new password. Your Office 365 username is <em>username@mesaaz.gov</em> (e.g., <em>jdoe@mesaaz.gov</em>).</li>
            <li>Close Teams by right-clicking on the Teams icon in the system tray and selecting <strong>Quit</strong>. Reopen Teams when ready.</li>
        </ul>
        
        <p>Please remember to change your password on the mobile device(s) you use to connect to City resources, especially WiFi SSIDs such as <strong>“empwifi”</strong>. Failure to do so may cause your account to get locked out.</p>
        
        <p>For further assistance, please contact the DoIT Help Desk.</p>
        
        <p>Thank You,</p>
        <p><strong>Department of Innovation and Technology</strong></p>
    </div>
</body>
</html>
"@

	$smtp = new-object system.net.mail.smtpClient("mailhost.acctcom.mesa")
	$mail = new-object System.Net.Mail.MailMessage

	$mail.from = "DoNotReply.ExpiringPasswords@mesaaz.gov"
	$mail.to.add($to)
	$mail.subject = $subject
	$mail.body = $body
	$mail.IsBodyHtml = $true	
	#$mail.Attachments.Add($image)
	$smtp.send($mail)
}

$CurrentDate = Get-Date
$FutureDate = $CurrentDate.AddDays(7)

#Fetch all users whose expiration date is within next 7 days or less
$ExpiringUsers = Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} `
    -SearchBase "OU=_Users,DC=acctcom,DC=mesa" `
    -Properties Name, SamAccountName, msDS-UserPasswordExpiryTimeComputed |
    Select-Object -Property Name, SamAccountName,@{Name="ExpirationDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} |
    Where-Object { $_.ExpirationDate -le $FutureDate -and $_.ExpirationDate -ge $CurrentDate } |
    Sort-Object "ExpirationDate"

$output = "Date of Execution: $CurrentDate`nThe following accounts were sent password expiry reminders:`n`n"

#Iterate through list of users/expiration dates and print
foreach ($User in $ExpiringUsers) {
    #Write-Host "User: $($User.SamAccountName) - Expiration Date: $($User.ExpirationDate)"
    $output += "User: $($User.SamAccountName) - Expiration Date: $($User.ExpirationDate)`n"
    $fullName = $User.Name
    $expiryDate = $User.ExpirationDate
    $days = ($expiryDate - $CurrentDate).Days
    $subject = "Your Password is Expiring Soon!"
    #Change -to address to $User.SamAccountName
    Send-Mail -from "DoNotReply.ExpiringPasswords@mesaaz.gov" -to treytrent128@gmail.com -subject $subject -body $body -expiryDate $expiryDate -fullName $fullName -days $days
}

Set-Content -Path "C:\Users\ttrent\EmailAutomationScript\output\logs.txt" -Value $output

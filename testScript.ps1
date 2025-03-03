#Automatic Password Expiration Email Reminder Script

Function Send-EmailNotification {
    param([string]$username, [datetime]$expiryDate)

    $recipient = "$username@gmail.com"
    $subject = "Your Password is Expiring Soon!"
    $body = @"
<html>
    <body>
        <p>Dear $username,`</p>
        <p>Your password will expire on `<strong>$($expiryDate.ToString('yyyy-MM-dd'))</strong>. Please reset it as soon as possible to avoid account lockout.</p>
        <p>Click the link below to reset your password:</p>
        <p><a href='$RESET_PASSWORD_URL'>$RESET_PASSWORD_URL</a></p>
        <p>Thank you,`<br> Your IT Support Team</p>
    </body>
</html>
"@

    try {
        Send-MailMessage -To $recipient -From $EMAIL_SENDER -Subject $subject -Body $body `
            -SmtpServer $SMTP_SERVER -Port $SMTPPORT -UseSsl -BodyAsHtml 
            -Credential (New-Object System.Management.Automation.PSCredential($SMTP_USER, (ConvertTo-SecureString $SMTP_PASSWORD -AsPlainText -Force)))
        Write-Host "Email sent to $recipient"
    } catch {
        Write-Host "Failed to send email to $recipient : $_"
    }
}

$CurrentDate = Get-Date
$FutureDate = $CurrentDate.AddDays(7)

#Fetch all users whose expiration date is within next 7 days or less
$ExpiringUsers = Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} `
    -SearchBase "OU=_Users,DC=acctcom,DC=mesa" `
    -Properties SamAccountName, msDS-UserPasswordExpiryTimeComputed |
    Select-Object -Property SamAccountName,@{Name="ExpirationDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} |
    Where-Object { $_.ExpirationDate -le $FutureDate -and $_.ExpirationDate -ge $CurrentDate } |
    Sort-Object "ExpirationDate"

#Iterate through list of users/expiration dates and print
foreach ($User in $ExpiringUsers) {
    Write-Host "User: $($User.SamAccountName) - Expiration Date: $($User.ExpirationDate)"
    #TO-DO: Send e-mail to User using Mesa server/IT email, awaiting further info
}

$RESET_PASSWORD_URL = "https://mesaaz.okta.com/"
$EMAIL_SENDER = "treytrent54@gmail.com" #Change to IT E-mail


#TESTING SEND EMAIL (gmail server)

#$SMTP_SERVER = "smtp.gmail.com"
#$SMTPPORT = 587
#$SMTP_PASSWORD = "fuov vhvf qjmu iozm"
#$SMTP_USER = "treytrent54@gmail.com"
#$expiryDate = Get-Date
#Send-EmailNotification -username "treytrent54" -expiryDate $expiryDate #Change to get date from OU

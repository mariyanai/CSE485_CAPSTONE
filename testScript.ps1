#testing Script for Password Reset

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
        Send-MailMessage -To $recipient -From $EMAIL_SENDER -Subject $subject -Body $body -SmtpServer $SMTP_SERVER -Port $SMTPPORT -UseSsl -BodyAsHtml -Credential (New-Object System.Management.Automation.PSCredential($SMTP_USER, (ConvertTo-SecureString $SMTP_PASSWORD -AsPlainText -Force)))
        Write-Host "Email sent to $recipient"
    } catch {
        Write-Host "Failed to send email to $recipient : $_"
    }
}



$RESET_PASSWORD_URL = "https://mesaaz.okta.com/"
$EMAIL_SENDER = "treytrent54@gmail.com" #Change to IT E-mail
$SMTP_SERVER = "smtp.gmail.com"
$SMTPPORT = 587
$SMTP_PASSWORD = "fuov vhvf qjmu iozm"
$SMTP_USER = "treytrent54@gmail.com"
$expiryDate = Get-Date
Send-EmailNotification -username "treytrent54" -expiryDate $expiryDate #Change to get date from OU
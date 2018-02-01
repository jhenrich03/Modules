$Today = Get-Date
# Change this value to change how far out you want to notify the user
$Days = 5
$Days2 = $Days - 1
$midnight = $Today.Date.AddDays($Days)
$midnight2 = $Today.Date.AddDays($Days2)

$Users = Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} -Properties msDS-UserPasswordExpiryTimeComputed,GivenName,userprincipalname | 
Select-Object UserPrincipalName,GivenName,Name,@{n='ExpiryDate';e={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} |
Where-Object {$_.expirydate -ge $midnight2 -and $_.expirydate -le $midnight}

foreach ($U in $Users) {

$subject = "Password Expiration Notice"
$from = "helpdesk@mastersoncompany.com"
$to = "$($U.userprincipalname)"
$server = "ex2.mastersoncompany.com"
$link = "<a href='http://helpdesk'>here.</a>"
$body = "
<font face=""Arial"">
 $($U.givenname),<br><br>
 Your password is set to expire in <b>$Days</b> days on <b>$($midnight2.ToShortDateString()).</b></b><br><br>

 <b>**Password Requirements**</b><br><br>

  - Must be at least <b>7</b> characters long<br>
  - Cannot contain a part of your name or username<br>
  - Must contain characters from <u><b>three</b></u> of the following categories:<br><br>
    1. Uppercase letters<br>
    2. Lowercase letters<br>
    3. A number<br>
    4. Non-alphanumeric characters (!,$,&,*)<br><br>


 We recommend you choose a password that is difficult to guess, but easy for you to remember. Please do not share your password with anyone or have it written down somewhere near your desk.<br><br>
 This is a message from the Masterson IT Department. If you have any questions, please reply to this email or submit a ticket $link
</font>"

Send-MailMessage -From $from -To $to -Bcc josh.henrich@mastersoncompany.com -Body $body -BodyAsHtml -Subject $subject -SmtpServer $server

}
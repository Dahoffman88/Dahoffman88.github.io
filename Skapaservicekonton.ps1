# Läs in xmlen till en variabel

[xml]$Settings = Get-Content .\Settings.xml

# Lista services

$Settings.Services.Service


# Plocka ut Biztalk kontonen

$BizTalkSettings = $Settings.Services.Service | Where-Object Name -eq BizTalk


#Lista alla konton under BizTalk
foreach ($acc in $BizTalkSettings.Accounts.Account ) {
	Write-Output  $acc  

}


# Sätt unika lösenord på alla konton
$SettingsFile = "C:\Temp\Settings.xml"
Add-Type -AssemblyName System.web
foreach ($AccountName in $BizTalkSettings.Accounts.Account) {
	# GeneratePassword( int length,     int numberOfNonAlphanumericCharacters)
	$NewPW = [System.Web.Security.Membership]::GeneratePassword(20, 6)
	$AccountName.PW = $NewPW
	$Settings.Save($SettingsFile)

}

# Läs in xmlen igen
[xml]$Settings = Get-Content C:\Temp\Settings.xml


$BizTalkSettings = $Settings.Services.Service | Where-Object Name -eq BizTalk


# Skapa AD-konton, typ nåt sånt här...
foreach ($Account in $BizTalkSettings.Accounts.Account) {

	$SecurePassword = ConvertTo-SecureString -String $Account.PW -AsPlainText -Force

	New-ADUser `

		-Description $($Account.Description) `

		-DisplayName $($Account.Name) `

		-GivenName $($Account.Name) `

		-Name $($Account.Name) `

		-Path $($Account.OU) `

		-SamAccountName $($Account.Name) `

		-CannotChangePassword $false `

		-PasswordNeverExpires $true `

		-ChangePasswordAtLogon $False


    $NewAccount = Get-ADUser $($Account.Name)
    Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword
    #Set-ADAccountControl $NewAccount -CannotChangePassword $false -PasswordNeverExpires $true
    #Set-ADUser $NewAccount -ChangePasswordAtLogon $False 
    Enable-ADAccount $NewAccount

}

# Verifiera att kontonen skapats
foreach ($Account in $BizTalkSettings.Accounts.Account) {

    Get-ADUser -Identity $Account.name  

}
foreach ($Group in $BizTalkSettings.Group.Group) {
    new-
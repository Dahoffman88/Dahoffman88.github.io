<#
.SYNOPSIS
Verify BizTalk installation
.DESCRIPTION
This script verifies a succesful BizTalk installation by checking Registry and Programs and Features
.EXAMPLE
./VerifyInstallation.ps1
.NOTES
Run the script on the BizTalk server you want to verify
#>
cls
# Get Registry entires
Write-Host("Registry entries") -fore Green
Get-ItemProperty "hklm:\SOFTWARE\Microsoft\BizTalk Server\3.0"

# Get Programs and Features
Write-Host("Programs and Features") -fore Green
gwmi -class Win32_Product -Filter "name LIKE 'Microsoft BizTalk%'" | Select -expand Name
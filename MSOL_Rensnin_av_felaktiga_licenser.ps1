# Run line 2 and 3 first to login to the Azure / O365 service
# $O365Cred = Get-Credential
# Connect-MsolService -Credential $O365Cred
#Creator Anton Hoffman - anton.hoffman@uadm.uu.se

#Index över Serviceplans
#1. AAD_BASIC_EDU
#2. SCHOOL_DATA_SYNC_P1
#3. STREAM_O365_E3
#4. TEAMS1
#5. INTUNE_O365
#6. Deskless 
#7. FLOW_O365_P2
#8. POWERAPP_O365
#9. RMS_S_ENTERPRISE
#10. OFFICE_FORMS_PLAN2
#11. PROJECTWORKMANAGEMENT
#12. SWAY
#13. YAMMER_EDU
#14. SHAREPOINTWAC_EDU
#15. EXCHANGE_S_STANDARD
#16. OFFICESUBSCRIPTION
#17. MCOSTANDARD

#Kontrollera en användares services i Office 365 (Get-MsolUser -UserPrincipalName <Account>).Licenses.ServiceStatus

$365user = (Get-MsolUser -all | where {$_.isLicensed -eq $true}).count
# $365WrongLicStud = $365user | where {$_.isLicensed -eq $true -and $_.Licenses[0].ServiceStatus[3].Provisioningstatus -eq "Success" -and $_.UserPrincipalName -like "*@student.uu.se"} | foreeach {Set-MsolUserLicense -UserPrincipalName $_.UserPrincipalName -RemoveLicenses "Uppsalauniversitet:STANDARDWOFFPACK_IW_STUDENT"}






$365user = Get-MsolUser -All
$365stud = ($365user | Where-Object {$_.UserPrincipalName -like "*@student.uu.se"})
#($365stud | Where-Object {$_.licenses.servicestatus.Where({$_.serviceplan.ServiceName -eq "Teams1" -and $_.provisioningstatus -eq "success"})}).count
$365stud | Where-Object {$_.licenses.servicestatus.Where({$_.serviceplan.ServiceName -eq "Teams1" -and $_.provisioningstatus -eq "success"})}
<#
.SYNOPSIS
Configure Windows Firewall
.DESCRIPTION
This script configures Windows Firewall for BizTalk use
.EXAMPLE
./WindowsFirewall.ps1
.NOTES
Run the script on the servers that requires the configuration (BizTalk and SQL)
#>
cls

$BT360 = Read-Host("Do you want to open ports for BizTalk360 (Y/N)?")
# Dom IP som ska ha undantag i brandväggen för att kunna kommunicera fritt
$Remote_address = "130.238.187.65","130.238.187.66","130.238.187.43","130.238.187.38","130.238.187.44","130.238.187.47","130.238.187.48","130.238.187.49","130.238.187.90","130.238.187.91","130.238.187.93","130.238.187.94"

Write-Host("")
Write-Host("Opening and enabling ports for MSDTC and SQL...")  -Fore Green

# Open ports for MSDTC
New-NetFirewallRule -DisplayName "Allow MSDTC" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135,5000-5100 | Out-Null
New-NetFirewallRule -DisplayName "Allow MSDTC" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 135,5000-5100 | Out-Null

# Open ports for SQL
New-NetFirewallRule -DisplayName "Allow SQL" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1433-1434 | Out-Null
New-NetFirewallRule -DisplayName "Allow SQL" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 1433-1434 | Out-Null

# Enable built-in MSDTC ports
Enable-NetFirewallRule -DisplayName "Distributed Transaction Coordinator (RPC)" | Out-Null
Enable-NetFirewallRule -DisplayName "Distributed Transaction Coordinator (RPC-EPMAP)" | Out-Null
Enable-NetFirewallRule -DisplayName "Distributed Transaction Coordinator (TCP-In)" | Out-Null
Enable-NetFirewallRule -DisplayName "Distributed Transaction Coordinator (TCP-Out)" | Out-Null

if ($BT360.ToUpper() -eq "Y" -or $BT360.ToUpper() -eq "YES") {
    Write-Host("")
    Write-Host("Opening and enabling ports for BizTalk360...")  -Fore Green

    # Open ports for BT360
    New-NetFirewallRule -DisplayName "Allow BT360" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135,1433,50000-50200,445,1164 -RemoteAddress $Remote_address | Out-Null
    New-NetFirewallRule -DisplayName "Allow BT360" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 135,1433,50000-50200,445,1164 -RemoteAddress $Remote_address | Out-Null
}
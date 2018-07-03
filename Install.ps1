# Initialize extra datadrive and format
# Get-Disk -Number 1 | where partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DataDisk" -confirm:$false

# Set location - d: e:
$drive = "e:"
$basefolder = "\setup"
$baselocation = $drive+$basefolder
$configlocation = "$baselocation\config"
$scriptlocation = "$baselocation\script"
$UninstallPath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$SQLCompact = "{78909610-D229-459C-A936-25D92283D3FD}"

# Create folder for UUC module
    # Check if UUC folder exist, create if false
    $modulefolder = "$Env:ProgramFiles\WindowsPowerShell\Modules\UUC"
    if (!(Test-Path -path $modulefolder)) {
        New-Item $modulefolder -type directory
        }

# Copy UUC module file to PSpath
    $UUCmodule = "$Env:ProgramFiles\WindowsPowerShell\Modules\UUC\UUC.psm1"
    if (!(Test-Path -path $UUCmodule)) {
        Copy-Item "$configlocation\UUC.psm1" $modulefolder
        }

# Import module
    Import-Module UUC -Force

# Install dbtools module (kräver SQL Server management studios först) 
    Expand-Archive $baselocation\dbatools.zip -DestinationPath "$Env:ProgramFiles\WindowsPowerShell\Modules"
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\dbatools-master\dbatools.psd1" -Force


# WindowsUpdate
    Invoke-Expression -Command "$scriptlocation\WindowsUpdate.ps1 -Install Yes -Reboot No"

# Check Computername length and change if more than 15 characters
    Invoke-Expression -Command $scriptlocation\ComputerName.ps1

# Disable IPv6
    Write-Host("Disabled IPv6 network connections") -ForegroundColor Green
    $netAdapterName = (Get-NetAdapterBinding -ComponentID ms_tcpip6).Name
    Disable-NetAdapterBinding -Name $netAdapterName -ComponentID ms_tcpip6

# Update help
    Update-Help

# Configure Firewall
    Invoke-Expression -Command $scriptlocation\WindowsFirewall.ps1

# Set event log Application to 100032kb
    Limit-EventLog -LogName Application -MaximumSize 100032kb

# Configure MS DTC
    Set-DtcNetworkSetting -DtcName Local -AuthenticationLevel NoAuth -InboundTransactionsEnabled $true -OutboundTransactionsEnabled $true -Confirm:$false

# Install WindowsFeatures
# Get-WindowsFeature | Out-GridView
Install-WindowsFeature Web-Server -IncludeManagementTools
Install-WindowsFeature Web-Common-Http -IncludeManagementTools
Install-WindowsFeature Web-Default-Doc -IncludeManagementTools
Install-WindowsFeature Web-Dir-Browsing -IncludeManagementTools
Install-WindowsFeature Web-Http-Errors -IncludeManagementTools
Install-WindowsFeature Web-Static-Content -IncludeManagementTools
Install-WindowsFeature Web-Http-Logging -IncludeManagementTools
Install-WindowsFeature Web-Log-Libraries -IncludeManagementTools
Install-WindowsFeature Web-ODBC-Logging -IncludeManagementTools
Install-WindowsFeature Web-Request-Monitor -IncludeManagementTools
Install-WindowsFeature Web-Http-Tracing -IncludeManagementTools
Install-WindowsFeature Web-Filtering -IncludeManagementTools
Install-WindowsFeature Web-Basic-Auth -IncludeManagementTools
Install-WindowsFeature Web-Digest-Auth -IncludeManagementTools
Install-WindowsFeature Web-Windows-Auth -IncludeManagementTools
Install-WindowsFeature NET-Framework-Features -IncludeManagementTools
Install-WindowsFeature NET-Framework-Core -IncludeManagementTools
Install-WindowsFeature SMTP-Server -IncludeManagementTools
Install-WindowsFeature Windows-Identity-Foundation -IncludeManagementTools
Install-WindowsFeature FS-FileServer -IncludeManagementTools
Install-WindowsFeature Storage-Services -IncludeManagementTools
Install-WindowsFeature RDC -IncludeManagementTools
Install-WindowsFeature RSAT-SNMP -IncludeManagementTools
Install-WindowsFeature FS-SMB1 -IncludeManagementTools
Install-WindowsFeature SNMP-WMI-Provider -IncludeManagementTools
Install-WindowsFeature Telnet-Client -IncludeManagementTools
Install-WindowsFeature WoW64-Support -IncludeManagementTools
Install-WindowsFeature RSAT-AD-PowerShell -IncludeManagementTools
Install-WindowsFeature RSAT-AD-AdminCenter -IncludeManagementTools
Install-WindowsFeature RSAT-ADDS-Tools -IncludeManagementTools
Install-WindowsFeature RSAT-ADLDS -IncludeManagementTools
Install-WindowsFeature FS-SMB1 -IncludeManagementTools
Install-WindowsFeature WAS-Process-Model -IncludeManagementTools
Install-WindowsFeature WAS-Config-APIs -IncludeManagementTools
Install-WindowsFeature Web-Performance -IncludeAllSubFeature
Install-WindowsFeature Web-App-Dev -IncludeAllSubFeature
Install-WindowsFeature Web-Mgmt-Tools -IncludeAllSubFeature
Install-WindowsFeature NET-Framework-45-Features -IncludeAllSubFeature

# På BizTalk servers
    Install-WindowsFeature MSMQ -IncludeManagementTools

# Enable 32-bit apps IIS for BAM
    Invoke-Expression -Command $scriptlocation\BAM_64bit.ps1

# Configure SMTP

    Set-Service “SMTPSVC” -StartupType Automatic
    Start-Service “SMTPSVC”

    #set Relay to 127.0.0.1
    $ipblock= @( 24, 0, 0, 128, 32, 0, 0, 128, 60, 0, 0, 128, 68, 0, 0, 128, 1, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 76, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 127, 0, 0, 1 )

    $smtpserversetting = get-wmiobject -namespace root\MicrosoftIISv2 -computername localhost -Query "Select * from IIsSmtpServerSetting"
    $smtpserversetting.RelayIpList = $ipblock
    $smtpserversetting.SmartHost = "mail.uu.se"
    $smtpserversetting.put()

# Install Excel 2016
    Start-process "cmd.exe" -ArgumentList "/C $baselocation\OfficeProPlus2016\setup.exe /configure $configlocation\OfficeProPlus2016Configuration.xml" -Wait

# WindowsUpdate
    Invoke-Expression -Command "$scriptlocation\WindowsUpdate.ps1 -Install Yes -Reboot No"

# Install Notepad++ ( silent? ) 
    $sBasePath = """$baselocation"
    $sAppPath = "\npp.7.3.2.Installer.exe"""
    $sShell = "cmd.exe"
    $sCommand = " /c "+ "$sBasePath" +"$sAppPath"
    $sArgument = " /s"
    Write-Output "Shell: $sShell"
    Write-Output "Command: $sCommand"
    Write-Output "Argument: $sArgument"
    $Process = Start-Process $sShell -ArgumentList $sCommand,$sArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode

# Install Git for Windows
    Start-Process "$baselocation\Git-2.12.0-64-bit.exe" -ArgumentList "/silent" -Wait

# Install Visual Studio
    Start-process "cmd.exe" -ArgumentList "/C $baselocation\VisualStudio2015Ent\vs_enterprise.exe /adminfile $configlocation\ConfigurationVisualStudio2015Ent.xml /norestart /quiet /ProductKey TDN67WJBH9G6QQPDCGRH46YJV" -Wait

# Uninstall SQL Compact
    if ((Test-Path -path $UninstallPath\$SQLCompact)) {
        Start-Process msiexec.exe -ArgumentList "/uninstall $SQLCompact /quiet" -Wait
        }


# Install SQL2016DevSp1 ( inte på test eller prod) 
    $sBasePath = """$baselocation\SQL2016DevSP1"
    $sAppPath = "\setup.exe"""
    $sShell = "cmd.exe"
    $sCommand = " /c "+ "$sBasePath" +"$sAppPath"
    $sArgument = " /Configurationfile=$configlocation\ConfigurationFileSQL2016DevSP1.ini"
    Write-Output "Shell: $sShell"
    Write-Output "Command: $sCommand"
    Write-Output "Argument: $sArgument"
    $Process = Start-Process $sShell -ArgumentList $sCommand,$sArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode
    
    if ((Test-Path -Path 'HKLM:\software\microsoft\windows\currentversion\uninstall\Microsoft SQL Server 13')) {
        Write-Host SQL Server Installed Successfully -ForegroundColor Green
        }

# Install SQL Server Data Tools
    $sBasePath = """$baselocation\SSDT\"
    $sAppPath = "\SSDTSetup.exe"""
    $sShell = "cmd"
    $sCommand = " /c "+ "$sBasePath" +"$sAppPath"
    $sArgument = " INSTALLALL=1 /q /norestart"
    Write-Output "Shell: $sShell"
    Write-Output "Command: $sCommand"
    Write-Output "Argument: $sArgument"
    $Process = Start-Process $sShell -ArgumentList $sCommand,$sArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode
    
    if ((Test-Path -Path 'HKLM:\software\microsoft\windows\currentversion\uninstall\{20EA85AA-2A1D-4F11-B09F-4BA2BF3C8989}')) {
        Write-Host SQL Server Data Tools Installed Successfully -ForegroundColor Green
        }

#Install SQL Server Management Studio
    $smBasePath = """$baselocation"
    $smAppPath = "\SSMS-Setup-ENU.exe"""
    $smShell = "cmd.exe"
    $smCommand = " /c "+ "$smBasePath" +"$smAppPath"
    $smArgument = " /install /quiet /norestart"
    Write-Output "Shell: $smShell"
    Write-Output "Command: $smCommand"
    Write-Output "Argument: $smArgument"
    $Process = Start-Process $smShell -ArgumentList $smCommand,$smArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode
    
    if ((Test-Path -Path 'HKLM:\software\microsoft\windows\currentversion\uninstall\{5859189E-B6F4-478F-9D63-503444427E55}')) {
        Write-Host SQL Server Management Studio Installed Successfully -ForegroundColor Green
        }

     
# WindowsUpdate
    Invoke-Expression -Command "$scriptlocation\WindowsUpdate.ps1 -Install Yes -Reboot No"

# Set SQL Memory
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\dbatools-master\dbatools.psd1" -Force
    Set-DbaMaxMemory -SqlServer "localhost" -MaxMb "4096"

# Configure database SMTP

# Sätt upp BizTalk Cluster (editera scriptet med variabler innan körning)
    Invoke-Expression -Command "$scriptlocation\BizTalkCluster.ps1 -Install Yes -Reboot No"

# Sätt upp SSO Cluster (editera scriptet med variabler innan körning)
    Invoke-Expression -Command "$scriptlocation\SSOCluster.ps1 -Install Yes -Reboot No"

# Skapa grupper och konton för BizTalk
[xml] $xml=Get-Content \\uuc-biz008-t\setup\Script\BizTalk-Preconf.xml
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

foreach ($item in $xml.Settings.Groups.Group){
New-ADGroup -Name $item.sAMAccountName -SamAccountName $item.sAMAccountName -GroupCategory Security -GroupScope Global -DisplayName $item.Name -Path $item.OU -Description $item.Description
}

foreach ($item in $xml.Settings.Accounts.Account){
New-ADUser -Name $item.Name -SamAccountName $item.sAMAccountName -Path $item.Path -Description $item.Description -AccountPassword $item.Password -PasswordNeverExpires=$True
}

foreach ($item in $xml.Settings.Groups.Group){
Add-ADGroupMember -Identity $item.sAMAccountName -Members $item.Members.Member
}

# Install BizTalk

# Verify BizTalk installation
    Invoke-Expression -Command $scriptlocation\VerifyInstallation.ps1

# Install Biztalk CU1 KB3208238
    $smBasePath = """$baselocation\BizTalk2016Dev"
    $smAppPath = "\BTS2016-KB3208238-ENU.exe"""
    $smShell = "cmd.exe"
    $smCommand = " /c "+ "$smBasePath" +"$smAppPath"
    $smArgument = " /quiet"
    Write-Output "Shell: $smShell"
    Write-Output "Command: $smCommand"
    Write-Output "Argument: $smArgument"
    $Process = Start-Process $smShell -ArgumentList $smCommand,$smArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode

# Configure BizTalk

# Install ActiveAdapter
    $sBasePath = """$baselocation"
    $sAppPath = "\ActiveADAPTER_Accelerator_STD_Uppsala.msi"""
    $sShell = "cmd.exe"
    $sCommand = " /c "+ "$sBasePath" +"$sAppPath"
    $sArgument = " /quiet"
    Write-Output "Shell: $sShell"
    Write-Output "Command: $sCommand"
    Write-Output "Argument: $sArgument"
    $Process = Start-Process $sShell -ArgumentList $sCommand,$sArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode

# Install DeploymentFramework
    $sBasePath = """$baselocation"
    $sAppPath = "\DeploymentFrameworkForBizTalkV5_7_RC2.msi"""
    $sShell = "cmd.exe"
    $sCommand = " /c "+ "$sBasePath" +"$sAppPath"
    $sArgument = " /quiet"
    Write-Output "Shell: $sShell"
    Write-Output "Command: $sCommand"
    Write-Output "Argument: $sArgument"
    $Process = Start-Process $sShell -ArgumentList $sCommand,$sArgument -NoNewWindow -PassThru -Wait
    Write-Host "Process finished with return code: " $Process.ExitCode


# Disable Defender Real-time Protection
    Set-MpPreference -DisableRealtimeMonitoring $true

# Add a File path exclusion
	#Set-MpPreference -ExclusionPath "C:\folder1", "C:\folder2"
	
#Add process exclusion
	#Set-MpPreference -ExclusionProcess "service.exe", "program.exe", "process.exe"

# WindowsUpdate
    Invoke-Expression -Command "$scriptlocation\WindowsUpdate.ps1 -Install Yes -Reboot No"
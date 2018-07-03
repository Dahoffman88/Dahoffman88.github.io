# Configure Variables
    
    [xml] $xml=Get-Content \\uuc-biz008-t\setup\Script\BizTalk-Preconf.xml
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    # SQL Servers
    $SSOServer01 = $xml.Settings.General.SSO.SSOserver1
    $SSOServer02 = $xml.Settings.General.SSO.SSOserver2

    # Cluster Name
    $ClusterName = $xml.Settings.General.Cluster.ClusternameSSO
    $ClusterOU = $xml.Settings.General.Cluster.ClusterOU
 
    # IPs
    $ClusterIP = $xml.Settings.General.IPs.ClusterIPSSO
    $Subnetmask = $xml.Settings.General.IPs.Subnetmask
    $hb1 = $xml.Settings.General.IPs.HB1SSO
    $hb2 = $xml.Settings.General.IPs.HB2SSO

    # File Server (create witness share)
    $FileServer = $xml.Settings.General.FileShare.Fileserver
    $ShareWitnessDrive = $xml.Settings.General.FileShare.WitnessDrive
    $ShareWitnessName = "$ClusterName-Witness"
  

    $starttime = get-date


# Install Windows Features
    Install-WindowsFeature Failover-Clustering,NET-Framework-Core  -ComputerName $SSOServer01
    Install-WindowsFeature Failover-Clustering,NET-Framework-Core -ComputerName $SSOServer02


# Rename Heartbeat nic
    $c = New-CimSession -ComputerName $SSOServer01
    Rename-NetAdapter "Ethernet1" -newName "Heartbeat" -CimSession $c
    New-NetIPAddress -InterfaceIndex (Get-NetAdapter -CimSession $c | Where-Object {$_.Name -eq "Heartbeat"}).ifIndex -IPAddress $hb1 -PrefixLength 24 -AddressFamily IPv4 -CimSession $c
    Remove-CimSession $c

    $c = New-CimSession -ComputerName $SSOServer02
    Rename-NetAdapter "Ethernet1" -newName "Heartbeat" -CimSession $c 
    New-NetIPAddress -InterfaceIndex (Get-NetAdapter -CimSession $c  | Where-Object {$_.Name -eq "Heartbeat"}).ifIndex -IPAddress $hb2 -PrefixLength 24 -AddressFamily IPv4 -CimSession $c
    Remove-CimSession $c



# Create Cluster
    
    Import-Module FailoverClusters    
    
    New-ADComputer -DisplayName $ClusterName -Name $ClusterName -Path $ClusterOU -Enabled:$false


# Delegate permissions in AD
    
    # Import AD module
    Import-Module ActiveDirectory

    Set-Location AD:

    $ACL = Get-Acl -Path $ClusterOU
    $GroupSID = Get-ADComputer -Identity $ClusterName  | Select-Object -ExpandProperty SID
    $ObjectGUID = New-Object -TypeName GUID -ArgumentList bf967a86-0de6-11d0-a285-00aa003049e2

    $Arguments = $GroupSID,'CreateChild, DeleteChild','Allow',$ObjectGUID
    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Arguments
        
    # Add the new AccessRules to the current ACL
    $ACL.AddAccessRule($rule)
    Set-Acl -Path $ClusterOU -AclObject $ACL



    $ACL = Get-Acl -Path $ClusterOU
    $GroupSID = Get-ADGroup -Identity 'UUC-GG-BizTalkOU-FC'  | Select-Object -ExpandProperty SID
    $ObjectGUID = New-Object -TypeName GUID -ArgumentList bf967a86-0de6-11d0-a285-00aa003049e2

    $Arguments = $GroupSID,'CreateChild, DeleteChild','Allow',$ObjectGUID
    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Arguments
        
    # Add the new AccessRules to the current ACL
    $ACL.AddAccessRule($rule)
    Set-Acl -Path $ClusterOU -AclObject $ACL



    New-Cluster -Name $ClusterName -Node "$SSOServer01","$SSOServer02" -StaticAddress $ClusterIP -NoStorage


    # Create Witness share
    Set-Location c:
    if (!(Test-Path "\\$FileServer\$ShareWitnessName$")) {

        # Share not found, let's create it
        $c = New-CimSession -ComputerName $FileServer
        $folder = New-item -ItemType directory -Path "\\$FileServer\$ShareWitnessdrive$\$ShareWitnessName"
        New-SmbShare -FullAccess Everyone -Path "$($ShareWitnessDrive):\$ShareWitnessName" -Name "$ShareWitnessName$" -CimSession $c
        
        # Give Cluster FullControl on that folder
        $acl = Get-Acl -Path $folder
        $ace = New-Object Security.AccessControl.FileSystemAccessRule("$($ClusterName)$", 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ace)
        $acl.SetAccessRuleProtection($true,$true)
        Set-Acl -AclObject $acl -Path $folder

        Remove-CimSession $c
    }




    # Configure Quorum
    Set-ClusterQuorum -Cluster $ClusterIP -FileShareWitness "\\$FileServer\$ShareWitnessName$"


    $n1 = Get-ClusterNetwork -Cluster $ClusterIP -Name "Cluster Network 2"
    $n1.Name = "Heartbeat"

    $n3 = Get-ClusterNetwork -Cluster $ClusterIP -Name "Cluster Network 1"
    $n3.Name = "Ethernet"
   
    #Get-ClusterResource "Ethernet" | Set-ClusterParameter -ClusterParameter HostRecordTTL 300


    # Test-Cluster $ClusterName -ReportName "c:\temp\Validate$ClusterName"  -Include 'Cluster Configuration','Inventory', 'Network', 'System Configuration' 


    $stoptime = get-date
    $totaltime = $stoptime-$starttime
    Write-Output "Installed in: $totaltime"
#Ladda den xml man vill använda
[xml]$msmq =Get-Content C:\Temp\MSMQ.xml
#För varje nod som finns Under MSMQ->QUeue i xmlen som laddats ovan gör det som står inom {}
foreach ($item in $msmq.msmq.queue){

#sätt env variabel till klusternamnet
$env:_CLUSTER_NETWORK_NAME_ = "UUC-MSMQSRV001"
#skapa ny msmqkö som är transactional
$msgQueue = New-MsmqQueue -Name $item.Name -Transactional -Label $item.label
#sätt ACL på kö "Receive message -Allow" 
$msgQueue | Set-MsmqQueueACL -UserName $item.Read -Allow "ReceiveMessage"
#sätt ACL på kö "Write message -Allow"
$msgQueue | Set-MsmqQueueACL -UserName $item.Write -Allow "WriteMessage"
#sätt ACL på kö "Full kontroll -Allow"
$msgQueue | Set-MsmqQueueACL -UserName $item.Full -Allow "FullControl"

}
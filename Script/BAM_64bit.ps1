<#
.SYNOPSIS
Enable BAM to run in 64-bit environment
.DESCRIPTION
This script enables BAM to run in 64-bit environment
.EXAMPLE
./BAM_64bit.ps1
.NOTES
Run the script on the server that requires this configuration (after IIS installation)
#>
cls
cscript.exe c:\inetpub\adminscripts\adsutil.vbs SET W3SVC/AppPools/Enable32bitAppOnWin64 1
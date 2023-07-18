# Written by Sreeman Shanker
# Incident Response Artefact Collection script
# Aug 31 2020

#Create IR folder to store files
Write-Host "Creating temporary folder to store files at C:\IR"
mkdir C:\IR

Write-Host "******************************"
Write-Host "Artefact Collection script Script v1.0"

# Get date and time
Write-Host "**Time script was ran**"
date

# Obtain list of all files on machine
Write-Host "**Retrieving list of all files**"
tree C:\ /F >> C:\IR\file list

# Obtain list of user and group information
Write-Host "**Retrieving list of user and group information**"

Write-Host "**Whoami**"
whoami

Write-Host "**Whoami /user**"
whoami /user

Write-Host "**Net users**"
net users

Write-Host "**Members of admin group**"
net localgroup administrators
#net group /domain [groupname]
#net user /domain [username]

Write-Host "**WMIC Sysaccount**"
wmic sysaccount

Write-Host "**wmic useraccount get name,SID**"
wmic useraccount get name,SID

Write-Host "**wmic useraccount list**"
wmic useraccount list

# Obtain list of logged on users
Write-Host "**Retrieving list of logged on users**"
wmic netlogin list /format:List

# Obtain list of auto startup processess
Write-Host "**Retrieving list of startup processess**"
wmic startup list full

# Obtain list of running processess
Write-Host "**Retrieving running processess**"
wmic process get name,processid,parentprocessid,ExecutablePath /format:csv >> C:\IR\processess.csv
Write-Host "***Output stored in C:\IR\***"

# Obtain list of running scheduled tasks
Write-Host "**Retrieving schedule tasks which are in running state**"
Get-ScheduledTask | where state -EQ 'running' | Get-ScheduledTaskInfo |
Export-Csv -NoTypeInformation -Path C:\IR\Runningschtask.csv
Write-Host "***Output stored in C:\IR\***"
# Obtain list of running scheduled tasks
Write-Host "**Retrieving schedule tasks which are in ready state**"
Get-ScheduledTask | where state -EQ 'ready' | Get-ScheduledTaskInfo |
Export-Csv -NoTypeInformation -Path C:\IR\Readyschtask.csv
Write-Host "***Output stored in C:\IR\***"

# Obtain SID for all users
Write-Host "**Retrieving user SID information**"
gwmi win32_userprofile | select localpath, sid >> C:\IR\userSID.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain Persistence and Automatic Load/Run Reg Keys from HKCU
Write-Host "**Retrieving Persistence and Automatic Load/Run Reg Keys for current user registry hive**"
Write-Host "Run key"
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Write-Host "Runonce key"
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Write-Host "RunonceEx key"
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows /f run
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows /f load
Get-ItemProperty -Path  HKCU:\Environment /v UserInitMprLogonScript
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\Run /v RESTART_STICKY_NOTES
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\Scripts
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
Get-ItemProperty -Path  HKCU:\SOFTWARE\AcroDC
Get-ItemProperty -Path  HKCU:\SOFTWARE\Itime
Get-ItemProperty -Path  HKCU:\SOFTWARE\info
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\User Shell Folders
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Command Processor
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\RegEdit /v LastKey
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU /s
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\RunOnce
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\IEAK\GroupPolicy\PendingGPOs /s
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\CPLs
Get-ItemProperty -Path  HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Control Panel\CPLs
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
Get-ItemProperty -Path  HKCU:\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM 
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices 
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run 
Get-ItemProperty -Path  HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\load 
Get-ItemProperty -Path  HKCU:\Control Panel\Desktop\Scrnsave.exe

#Obtain Persistence and Automatic Load/Run Reg Keys from software Hive (HKLM)
Write-Host "**Retrieving Persistence and Automatic Load/Run Reg Keys for software hive(HKLM)**"
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
Get-ItemProperty -Path  HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows /f AppInit_DLLs
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Win\Userinit
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options /s
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit /s
Get-ItemProperty -Path  HKLM:\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\policies\explorer\run
Get-ItemProperty -Path  HKLM:\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\run
Get-ItemProperty -Path  HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebugGet-ItemProperty -Path  HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Control Panel\CPLs
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\CPLs
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices 
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify 
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad  
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
Get-ItemProperty -Path  HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
Get-ItemProperty -Path  HKLM:\SYSTEM\ControlSet002\Control\Session Manager
Get-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
Get-ItemProperty -Path  HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler


#Obtain last few opened documents
Write-Host "**Retrieving last few opened documents**"
gci "REGISTRY::HKU\*\Software\Microsoft\Office\*\Word\Reading Locations\*" >> C:\IR\useropeneddocuments.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain hash and established network connections for running executables with dns cache
Write-Host "**Retrieving hash and established network connections for running executables with dns cache**"
Get-NetTCPConnection -State Established | Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress -ea 0).Entry}}|sort|gu -AS|FT | Export-Csv -NoTypeInformation -Path C:\IR\hashandnetworkforrunningexe.csv
Write-Host "***Output stored in C:\IR\***"

#Obtain hash and listening network connections for running executables
Write-Host "**Retrieving hash and listening network connections for running executables**"
Get-NetTCPConnection -State LISTEN | Select LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT | Export-Csv -NoTypeInformation -Path C:\IR\hashandnetworkforListeningexe.csv
Write-Host "***Output stored in C:\IR\***"

#Obtain processes running which are running a DLL
Write-Host "**Retrieving processes running which are running a DLL**"
gps | FL ProcessName, @{l="Modules";e={$_.Modules|Out-String}} >> C:\IR\DLLforRunningProcessess.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain active network connections
Write-Host "**Retrieving network connections**"
netstat -anob >> C:\IR\netstat.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain arp cache
Write-Host "**Retrieving arp cache**"
arp -a >> C:\IR\arptable.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain recent dns requests
Write-Host "**Retrieving recent dns requests**"
ipconfig /displaydns >> C:\IR\dnsrequests.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain List of IPV4 addresses who have connected via RDP
Write-Host "**Retrieving list of IPV4 addresses connected via RDP**"
Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | select -exp Properties | where {$_.Value -like '*.*.*.*' } | sort Value -u  >> C:\IR\RDPipv4connection.txt
Write-Host "***Output stored in C:\IR\***"

#Obtain Remote Desktop Lateral Movement Detection 
Write-Host "***Checking for Remote Desktop Lateral Movement Detection ***"
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='10'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4778';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4779';} | FL TimeCreated,Message

#Obtain Programs specifically set to run as admin 
Write-Host "***Retrieving programs specifically set to run as admin***"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN >> C:\IR\runasadmin.txt
#reg query "HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /s /f RUNASADMIN


#Obtain IE history
Write-Host "***Retrieving IE history***"
reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" >> C:\IR\iehistory.txt
Write-Host "***Output stored in C:\IR\***"

Write-Host "***All outputs collected. Proceeding to zip files***"
Write-Host "***All outputs collected. Proceeding to zip files***"
Write-Host "***All outputs collected. Proceeding to zip files***"

#Zip all files in directory
Write-Host "***Zipping all files in C:\IR***"
Compress-Archive -Path C:\IR* -DestinationPath C:\IR\

Write-Host "***All operations completed. Please grab the compressed IR file and send to the SecOps Team. The directory may be deleted after sending the zip file***"
Write-Host "***All operations completed. Please grab the compressed IR file and send to the SecOps Team. The directory may be deleted after sending the zip file***"
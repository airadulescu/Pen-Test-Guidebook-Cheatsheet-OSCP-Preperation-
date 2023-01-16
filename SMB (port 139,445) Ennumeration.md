## SMB Methodology
1. NETBIOS Port 139. 
2. NetBIOS:Network Basic Input Output System. Software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network.


### User enumeration / SMB Version enumeration

4. SMB Port 445: Comunication protocol used for sharing access to files, printers, serial ports and other resources on a networt
5. `enum4linux -a $IP` 
6. `nmap --script "safe or smb-enum-*" -p 445 <IP>`
7. `nmap -p 445,139 --script=*vuln* $IP`  Check for vulnerabilities
```
crackmapexec smb IP --users [-u <username> -p <password>]
crackmapexec smb IP --groups [-u <username> -p <password>]
crackmapexec smb IP --groups --loggedon-users [-u <username> -p <password>]
```

### Folder Access 
10. `smbmap -H $ip`  List shares #Null user
11. If access is possible, Get share Items. `smbmap -H $IP -R <SHARENAME> ` 
12. If we have credentials `smbmap -H $ip -d <DOMAINNAME> -u <user> -p <Password>` Another way is 
```
crackmapexec smb <IP> -u '' -p '' --shares #Null user
crackmapexec smb <IP> -u 'username' -p 'password' --shares #Guest user
crackmapexec smb <IP> -u 'username' -H '<HASH>' --shares #Guest user
```
13. Another way to connect is smbclinet `smbclient -L \\IP -N --option='client min protocol=NT1'`
14. `smbclient -L \\IP -U <user>` 
15.  smbclient -L \\IP -N 


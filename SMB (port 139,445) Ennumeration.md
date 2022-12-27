## SMB Methodology
1. NETBIOS Port 139. 
2. NetBIOS:Network Basic Input Output System. Software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network.
3. SMB Port 445: 
4. Comunication protocol used for sharing access to files, printers, serial ports and other resources on a networt.
5. Check for vulnerabilities  `nmap -p 445,139 --script=*vuln* $IP`
6. `nmap --script "safe or smb-enum-*" -p 445 <IP>`
7. 

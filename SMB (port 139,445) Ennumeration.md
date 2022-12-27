## SMB Methodology
1. NETBIOS Port 139. 
2. NetBIOS:Network Basic Input Output System. Software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network.
3. SMB Port 445: 
4. Comunication protocol used for sharing access to files, printers, serial ports and other resources on a networt.
5. Check for vulnerabilities  `nmap -p 445,139 --script=*vuln* $IP`
6. `nmap --script "safe or smb-enum-*" -p 445 <IP>`
7.  Full enumeration + vul scan `nmap --script=smb2-capabilities,smb-print-text,smb2-security-mode.nse,smb-protocols,smb2-time.nse,smb-psexec,smb2-vuln-uptime,smb-security-mode,smb-server-stats,smb-double-pulsar-backdoor,smb-system-info,smb-vuln-conficker,smb-enum-groups,smb-vuln-cve2009-3103,smb-enum-processes,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-enum-shares,smb-vuln-ms07-029,smb-enum-users,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-ls,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-os-discovery --script-args=unsafe=1 -T5 $ip`
8. `smbmap -H $ip`

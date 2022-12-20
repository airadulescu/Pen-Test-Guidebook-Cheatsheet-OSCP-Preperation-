## Simple Mail Transfer Protocol (Sending Mail To People)
0. Why is SMTP important? User Ennumeration, Bypass authentication, and Send email. (User name could be used for ssh, telnet brute forcing)\
1.Port 25
## SMTP User Ennumeration
2. `nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} $IP `
3. `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt  -t $IP`
4. `nc -nv $IP 25` (connect to smpt)
5. `VRFY root` Command to check if user exists.
6. `EXPN root` Command to check if user is in a mailing list.
## SMTP Open relay vulnerability, authentication bypass. 
1. `nmap -p 25 --script smtp-open-relay $IP`
## Vulnerability Scanning && user Ennumeration all in one.
1. `nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $IP`

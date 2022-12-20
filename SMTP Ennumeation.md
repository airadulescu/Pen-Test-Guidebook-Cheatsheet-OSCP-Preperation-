## Simple Mail Transfer Protocol (Sending Mail To People)
0. Why is SMTP important? User Ennumeration, bypass authentication, and send email. (User name could be used for ssh, telnet brute forcing)\
1.Port 25
## SMTP User Ennumeration
2. `nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} $IP `
3. `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt  -t $IP`
4. nc -nv $ip 25 (connect to smpt)\
5. `VRFY root` Command to check if user exists.
6. `EXPN root` Command to check if user is in a mailing list.
## SMTP Open relay vulnerability, authentication bypass. 
1. `nmap -p 25 --script smtp-open-relay $ip

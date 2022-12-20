## Simple Mail Transfer Protocol (Sending Mail To People)
0. Why is SMTP important? User Ennumeration, bypass authentication, and send email. (User name could be used for ssh, telnet brute forcing)\
1.Port 25\
2. SMTP user ennumeration. `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt  -t $IP`
3. nc -nv $ip 25 (connect to smpt)\

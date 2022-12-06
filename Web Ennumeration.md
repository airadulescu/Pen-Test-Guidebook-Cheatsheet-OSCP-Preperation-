# Zero-to-Hero-Pen-Testing-Notes-

1.Always maunally ennumerate and check the source code control+u/ Check /robots.txt /sitemap.xml\
2.gobuster dir -u http://$IP:PORT -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\    -b (for bad servercode) -f (add this flag if gobuster is not returing any results for a long time) \
2.5 wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200 http://$IP/FUZZ \
3. nikto -h $IP 
4. If you do not find any specific directory add the -f flag to go buster and rerun\
5. If you find some directory and stuck  make sure to run gobuster again with the new directory i.e http:\\$IP/newDirectory  
6.

##Possible web vulnerabilities
1. LocalFile Inclusion 
2. Check links ending with ?file=index.php ?book=  (Possible vulnerabilities in source code)
3. book= ../../../../etc/passwd   (Window or apache?)
4. ../../../../var/www/html/index.php  html to confirm log poisoning 
5. Add  ../ ../../../../ and check if the following following files exists.
6. /etc/passwd  /var/log/mail/USER  /var/log/apache2/access.log  /proc/self/environ  /tmp/sess_ID /var/lib/php5/sess_ID /var/log/auth/log
7. Now that we have confirmed LFI vulnerablity, lets log poision ../../../../var/log/apache2/access.log via invalid connection request.
8. Connect to nc -nv $IP port. and insert commandline exeuction payload (This depends on what techonology it is using. php ..etc)
9. check for sucessful log poisioning ../../../../var/log/apache2/access.log&cmd=i.
10. If you receive command execution, we will insert a reversshell via url encoding.

 

##Login page
1. Always check for default credentials
2. SQL injection
3. Burpite suite brute force? 
4. 

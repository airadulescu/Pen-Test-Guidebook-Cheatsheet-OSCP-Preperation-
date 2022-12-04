# Zero-to-Hero-Pen-Testing-Notes-

1.Always maunally ennumerate and check the source code control+u\
2.gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\
3. nikto -h $IP 
4. If you do not find any specific directory add the -f flag to go buster and rerun\
5. If you find some directory and stuck  make sure to run gobuster again with the new directory i.e http:\\$IP/newDirectory  
6.

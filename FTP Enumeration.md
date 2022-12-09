##ftp (File Transfer Protocol) 
We can leverage FTP to gain critical information(possibly credentials) for further exploits or upload a reverseshell.

port <21> , commonly used on webserver to upload files/images
ftp://$IP , You can visit the site to see the file. 


1. Check for anonymous login. ID: anonymous Password:x  or password is annoymous
2. Always0 check for version (possible for exploitation (searchsploit)
3.Brtue force login with Hydra. hydra -L user.txt -P pass.txt $IP ftp. (use -l if user name is known)


##Steps: 
ftp $IP $port

#Key commands
get $FileName  (Downloads the file to directory where ftp was ran)
put $FileName  (Uploading the file to ftp)

#Use binary to upload or download files
binary
ascii

#quote PASV
ls-al

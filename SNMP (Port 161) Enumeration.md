## Simple Network Management Protocol 
0. SNMP collects and organizes data on a network, over udp port 161. We want to look at MIB(Management Informaition Based) where each object is assgined an OID(numbers).
1. Objective: we want to intercept these data and gain information , such as user name, services and etc.  
2. Port 161
3. Scanning for SNMP `sudo nmap -sU --open -p 161 $IP`
4. `snmp-check $IP`
5. `snmpwalk -c public -v1 $IP`  -v for version -c for community string . (public, private manager)
6. Once we know what OID is mathed with what object we can futher ennumerate by `snmpwalk -c public -v1 $IP $OID`

MIB values for Microsoft Windows SNMP 
System Processes 
1.3.6.1.2.1.25.1.6.ø 
Running Programs 
1.3.6.1.2.1.25.4.2.1.2 
processes Path 
1.3.6.1.2.1.25.4.2.1.4 
Storage units 
1.3.6.1.2.1.25.2.3.1.4 
Software Name 
1.3.6.1.2.1.25.6.3.1.2 
User Accounts 
1.3.6.1.4.1.77.1.2.25 
TCP Local ports 
1.3.6.1.2.1.6.13.1.3 





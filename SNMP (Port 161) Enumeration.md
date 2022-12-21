## Simple Network Management Protocol 
0. SNMP collects and organizes data on a network, over udp port 161. We want to look at MIB(Management Informaition Based) where each object is assgined an OID(numbers).
1. Objective: we want to intercept these data and gain information , such as user name, services and etc.  
2. Port 161
3. Scanning for SNMP `sudo nmap -sU --open -p 161 $IP -oG open-snmp.txt`
4. `snmpwalk -c public -v1 $IP`  -v for version -c for community string . (public, private manager)
5. Once we know what OID is mathed with what object we can futher ennumerate by `snmpwalk -c public -v1 $IP $OID`

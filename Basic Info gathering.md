## Basic Info gathering

#### Whatweb

example: whatweb 10.10.10.121



#### Robots.txt







## Dir travel technique



#### gobuster

example:



#### ffuf

example: ffuf -u 'http://10.10.10.121/wordpress/FUZZ' -w /home/bbb/CTF/Selects/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt

ffuf -H "Host: FUZZ.editor.htb" -u 'http://editor.htb' -w /home/bbb/CTF/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 4605





# Reverse shell

#### Netcat

nc -nlvp 1234

-l	Listen mode, to wait for a connection to connect to us.

-v	Verbose mode, so that we know when we receive a connection.

-n 	Disable DNS resolution and only connect from/to IPs, to speed up the connection.

-p 	port? maybe



#### Upgrade TTY

python -c 'import pty; pty.spawn("/bin/bash")'



#### Default webroot location

Apache	/var/www/html/

Nginx	/usr/local/nginx/html/

IIS	c:\\inetpub\\wwwroot\\

XAMPP	C:\\xampp\\htdocs\\


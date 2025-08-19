## Basic Info gathering

### Whatweb

example: whatweb 10.10.10.121



### Robots.txt

### Nmap
Even though this rather simple, don't underestimate

/nmaplowercheck1755574551 /NmapUpperCheck1755574720 Lying in nmap source code,

using: --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" 

This will remove the exposed "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" when using normal sSCV scan



## Dir travel technique



### gobuster

example: 



### ffuf

example: ffuf -u 'http://10.10.10.121/wordpress/FUZZ' -w /home/bbb/CTF/Selects/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt

ffuf -H "Host: FUZZ.editor.htb" -u 'http://editor.htb' -w /home/bbb/CTF/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 4605





# Reverse shell

### Netcat

nc -nlvp 1234

-l	Listen mode, to wait for a connection to connect to us.

-v	Verbose mode, so that we know when we receive a connection.

-n 	Disable DNS resolution and only connect from/to IPs, to speed up the connection.

-p 	port? maybe



### Upgrade TTY

python -c 'import pty; pty.spawn("/bin/bash")'



### Default webroot location

Apache	/var/www/html/

Nginx	/usr/local/nginx/html/

IIS	c:\\inetpub\\wwwroot\\

XAMPP	C:\\xampp\\htdocs\\

# Priviledge Escalation

### Bash/SSH
A very simple thing to do: sudo -l

An really simple problem I encountered is this. (user2 : user2) NOPASSWD: /bin/bash

For this case, just use "sudo -u user2 /bin/bash". 

In most priviled escalation in CTF. id_rsa file will be "Viewable" by a user. Copy to a file, then connect to the user that own that id_rsa with

ssh root@IP -p port -i KeyFile

### TCP/IP File Transfering
python3 -m http.server 8000

scp linenum.sh user@remotehost:/tmp/linenum.sh #Alternative of WinSCP we all known

Don't forget to integrity check with MD5sum if possible
# Basic Info gathering

### Whatweb

example: ```whatweb 10.10.10.121```



### Robots.txt

## Nmap
Even though this rather simple, don't underestimate

/nmaplowercheck1755574551 /NmapUpperCheck1755574720 Lying in nmap source code,

using: ```--script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" ```

This will remove the exposed ```"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"``` when using normal sSCV scan

### Favourite scan

This will reveal basically everything. However take a lot of time

    nmap -sSCV -AT4 -v -O -p- <IP>

### Script (NSE)

A very fascinating mechanic

All NSE script is stored in ```/usr/share/nmap/scripts```

```sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands```

### Nmap Firewall and IDS/IPS Evasion

#### Decoys technique 

```
-Pn         DIsable ICMP Echo Request
-n          Disables DNS resolution.
--disable-arp-ping	Disables ARP ping.
--packet-trace	Shows all packets sent and received.
-D RND:5    Generates five random IP addresses that indicates the source IP the connection comes from.
-S <IP>     Scans the target by using different source IP address.
-e tun0     Sends all requests through the specified interface. (We can use Tornet to have tor interface, and scanning from there)
```

#### Ip range scan

```nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5```

Output sample:
- 10.129.2.4
- 10.129.2.10
- 10.129.2.11
- 10.129.2.18
- 10.129.2.19
- 10.129.2.20
- 10.129.2.28

you can push them into a hosts.lst and do this

```nmap -sn -oA tnet -iL hosts.lst```
```
-iL : Performs defined scans against targets in provided 'hosts.lst' list.
-oA tnet: Stores the results in all formats starting with the name 'tnet'.
-sn: disable port scanning
To make range scan even more natural, we can use -PE
-PE: Performs the ping scan by using 'ICMP Echo requests' against the target.
-Pn to disable ICMP echo
--disable-arp-ping
```

Scan top 100 port: ```-F``` Can save significant time. In CTF, I use this right at the moment I have target. After this I run another nmap heavy scan, so I can have something to do of while waiting for that heavy scan to run.

`--reason: Displays the reason a port is in a particular state.`

Example:   `100/udp closed unknown port-unreach ttl 64`


#### UDP scan

All previous technique is TCP scan. Which is a lot more reliable in general. So likely that path will be guarded heavier. So we can using UDP scan

Enable TCP scan: ```-sU```

## SMB

```
Basic SMB config
[sharename]	The name of the network share.
workgroup = WORKGROUP/DOMAIN	Workgroup that will appear when clients query.
path = /path/here/	        The directory to which user is to be given access.
server string = STRING	    The string that will show up when a connection is initiated.
unix password sync = yes	Synchronize the UNIX password with the SMB password?
usershare allow guests = yes	Allow non-authenticated users to access defined share?
map to guest = bad user	    What to do when a user login request doesn't match a valid UNIX user?
browseable = yes	        Should this share be shown in the list of available shares?
guest ok = yes	            Allow connecting to the service without using a password?
read only = yes	            Allow users to read files only?
create mask = 0700	        What permissions need to be set for newly created files?
```

### SMB client

List shares: ```smbclient -N -L //10.129.14.128 ```

Connect to share after list```smbclient //10.129.14.128/notes```

### RPCclient

Basic login: ```rpcclient -U "" 10.129.14.128```

After login, there are some basic info you can query
```
Query	            Description
srvinfo	            Server information.
enumdomains	        Enumerate all domains that are deployed in the network.
querydominfo	    Provides domain, server, and user information of deployed domains.
netshareenumall	    Enumerates all available shares.
netsharegetinfo <share>     Provides information about a specific share.
enumdomusers	    Enumerates all domain users.
queryuser <RID>	    Provides information about a specific user.
```

    You can also bruteforcing RIDs to login with a simple payload like this

    for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done



### Samrdump.py

This is a part of impacket ```samrdump.py 10.129.14.128```

You can access impacket executable location at ```/root/.local/bin```

### SMBmap

```smbmap -H 10.129.14.128```

### CrackMapExec

```crackmapexec smb 10.129.14.128 --shares -u '' -p ''```

### Enum4LinuxNG

Can be consider the best one by useful

```enum4linux 10.129.14.128 -A```

## Dir travel technique

### gobuster

example: ```gobuster dir -u https://example.com -w /wordlists/Discovery/Web-Content/big.txt -t 4 ```

### ffuf

Normal fuzz:
```ffuf -u 'http://10.10.10.121/wordpress/FUZZ' -w /home/bbb/CTF/Selects/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt```

Subdomain fuzz:
```ffuf -H "Host: FUZZ.editor.htb" -u 'http://editor.htb' -w /home/bbb/CTF/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 4605```





# Reverse shell

### Netcat

```nc -nlvp 1234```

```
-l	Listen mode, to wait for a connection to connect to us.
-v	Verbose mode, so that we know when we receive a connection.
-n 	Disable DNS resolution and only connect from/to IPs, to speed up the connection.
-p 	port? maybe
```



### Upgrade TTY

```python -c 'import pty; pty.spawn("/bin/bash")'```

### Default webroot location

```
Apache	/var/www/html/
Nginx	/usr/local/nginx/html/
IIS	    c:\\inetpub\\wwwroot\\
XAMPP	C:\\xampp\\htdocs\\
```

# Priviledge Escalation

### Bash/SSH
A very simple thing to do: ```sudo -l```

An really simple problem I encountered is this. ```(user2 : user2) NOPASSWD: /bin/bash```

For this case, just use ```sudo -u user2 /bin/bash```. 

In most priviled escalation in CTF. ```id_rsa``` file will be "Viewable" by a user. Copy to a file, then connect to the user that own that ```id_rsa``` with

SSH with rsa file: ```ssh root@IP -p port -i KeyFile```

### TCP/IP File Transfering
```python3 -m http.server 8000```

Alternative of WinSCP ```scp linenum.sh user@remotehost:/tmp/linenum.sh``` 

Don't forget to integrity check with MD5sum if possible
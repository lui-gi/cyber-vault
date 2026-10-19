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


## Notes
- Nmap Architecture
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

Determining OS via TTL
- **The Sent Packet:** Your machine sent an ICMP Echo Request _with_ a TTL of 255 (`ttl=255`). This is just your own tool's default outgoing packet configuration.
- **The Received Packet:** The target machine (`10.129.2.18`) responded with an ICMP Echo Reply displaying a TTL of 128 (`ttl=128`).

Since a default initial TTL of **128** is the signature standard for **Microsoft Windows**, and it hasn't decreased (meaning the target is likely on your local network or just 0 hops away after the gateway), you are dealing with a Windows box.

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

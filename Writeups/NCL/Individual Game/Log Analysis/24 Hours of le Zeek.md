---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Log Analysis
difficulty: hard
status: solved
flags: redacted
tags: [writeup, log-analysis]
---

# 24 Hours Of Le Zeek

## Task

Cyber Command

*NOTE: Challenge Instance will not be accessible once challenge is completed.*

This small network contains systems that are running some services that aren't allowed by IT. Can you use the supplied network logs to figure out if these are benign or deserve some additional investigation and forensics? While the labels used for each field aren't very descriptive, they are at least consistent across the logs.

- Q1 (5 pts): There's an unencrypted web server on this network. Based on the first word in the URI's path component, what service is it running?
- Q2 (5 pts): On what IPv4 address is this service running?
- Q3 (10 pts): What external IPv4 address is providing NTP services to this network?
- Q4 (10 pts): Based on the IP address from Q3, what Linux variant is running on 10.0.0.238?
- Q5 (10 pts): What web browser software is being used on 10.0.0.111?
- Q6 (10 pts): The logs show checks for firmware updates over an encrypted connection. What's the DNS name for that server?
- Q7 (15 pts): What device, other than the macbook, advertises itself as having Remote Audio Output Protocol available over TCP? Answer format: `model, product`
- Q8 (10 pts): Exactly one system wants to keep using a DNS name (not a hostname). Of what organization is that name a part? Answer format: `domain.tld`
- Q9 (10 pts): What is the MAC address of a network infrastructure device that requested a DHCP lease?
- Q10 (15 pts): Zeek flagged an anomaly on the very first exchange with a networked device. What Microsoft protocol suite does the exposed API on the device belong to? Use the exact protocol from the logs.

## Approach

24 hours of Zeek logs from a small home/office network, ten questions about the hosts and services on it. The catch is the field labels aren't descriptive but stay consistent across logs. They turned out to be JSON with the real Zeek field names swapped for generic keys like `f1`, `f10`, `f12`. The numbered keys follow Zeek's standard field ordering, so the same number means the same thing in every log.

### Initial recon

The challenge data came as one archive, `pi_ub2004_64.tar.gz`. The name itself is a hint: `pi` (raspberry pi) running `ub2004` (ubuntu 20.04) on `64` bit. I kept that in mind for later.

I listed the archive contents before extracting, then unpacked into an isolated dir so the untrusted data stays contained:

```
tar -tzf pi_ub2004_64.tar.gz | head -50
mkdir -p ~/zeek && tar -xzf pi_ub2004_64.tar.gz -C ~/zeek
cd ~/zeek/pi_ub2004_64
```

Logs are split per protocol and per hour, e.g. `http.11:00:00-12:00:00.log` and `dns.09:00:00-10:00:00.log`. Since they're hourly, any search needs to run across all hours of a protocol, easy with a glob: `cat http.*.log`.

Available log types:

```
ls | sed 's/\.[0-9].*//' | sort -u
capture_loss  conn  dhcp  dns  files  http  known_services  ntp
ocsp  open_conn  software  ssl  stats  weird  x509
```

### Decoding the field labels

I popped open one http and one dns record to see the JSON structure and renamed keys:

```
head -8 http.11:00:00-12:00:00.log
head -8 dns.09:00:00-10:00:00.log
```

Then mapped the numbered keys back to Zeek's standard field order, which gives a reusable decoder. Fields common to every log:

| key   | meaning                        |
|-------|--------------------------------|
| f1    | timestamp                      |
| f7    | log type                       |
| f9    | uid                            |
| f10   | source / client IP (orig_h)    |
| f11   | source port                    |
| f12   | server / responder IP (resp_h) |
| f13   | responder port                 |
| f14   | transport proto                |

Per-protocol fields that mattered:

- HTTP: f79 method, f80 host, f81 URI, f82 referrer, f84 user-agent, f87 status
- DNS: f42 query, f46 query type, f48 rcode, f54 answers
- SSL: f132 server_name (SNI)
- DHCP: f32 client MAC, f33 host_name, f34 client_fqdn, f35 domain
- weird: f123 anomaly name

Once this map is built, every question is just a targeted `jq` filter.

## Solution

### Q1 and Q2: unencrypted web server, its service and IP

HTTP is plaintext by definition so the unencrypted web server is in `http.log`. Every request is a GET on port 80 to host `10.0.0.238`, URI `/skyaware/data/aircraft.json`, referrer `http://10.0.0.238/skyaware/`.

```
cat http.*.log | jq -r '[.f80,.f81] | @tsv' | sort -u | head
```

The first word of the URI path is skyaware, FlightAware's web interface for an ADS-B receiver (dump1090 / piaware stack). That also explains the `pi_` in the archive name.

- Q1: REDACTED
- Q2: REDACTED

### Q3: external NTP server

NTP lives in `ntp.log`. I listed client/server pairs and looked for the one not on the internal `10.0.0.0/8` range:

```
cat ntp.*.log | jq -r '[.f10,.f12] | @tsv' | sort -u
10.0.0.238      <external-ip>
```

The only external address is the NTP server.

- Q3: REDACTED

### Q4: Linux variant on 10.0.0.238

The question says to base the answer on the IP from Q3. There's no `ntp.*` hostname lookup in DNS, so the host hit the time server by raw IP. That external IP sits in a block belonging to Canonical Ltd (operator of `ntp.ubuntu.com`). That pool is the default time source shipped with Ubuntu, so `10.0.0.238` is running Ubuntu, which matches the `ub2004` hint in the archive name. No internet/whois needed, the IP ownership is well known.

- Q4: REDACTED

### Q5: browser on 10.0.0.111

I pulled every distinct user-agent from that client:

```
cat http.*.log | jq -r 'select(.f10=="10.0.0.111") | .f84' | sort -u
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

One consistent string, names Chrome.

- Q5: REDACTED

### Q6: firmware update server over an encrypted connection

Encrypted means TLS, so the server name shows up as SNI in `ssl.log` (f132):

```
cat ssl.*.log | jq -r '.f132' | sort | uniq -c | sort -rn | head
```

The relevant name is the fwupd CDN. fwupd is the Linux firmware update daemon, and the CDN is where it checks/pulls firmware over HTTPS.

- Q6: REDACTED

### Q7: non-macbook device advertising RAOP over TCP

RAOP (remote audio output protocol) is AirPlay audio, advertised via mDNS as `_raop._tcp`. I searched dns/mdns for it and excluded the macbook:

```
cat dns.*.log | jq -r 'select((.f42|test("_raop";"i")) or (.f54|tostring|test("_raop";"i"))) | [.f10, .f42, (.f54|tostring)] | @tsv' | grep -vi macbook | sort -u
```

The other advertiser is "living room" at `10.0.0.110`, whose `_device-info._tcp.local` record has `model=J105aAP`. That's Apple's internal board id for AppleTV6,2 (Apple TV 4K, 1st gen, 2017).

- Q7: REDACTED

### Q8: system that wants to keep a DNS name, not a hostname

DHCP option 81 (client_fqdn) means a client asking to keep a full domain name instead of a plain hostname (option 12). I listed the relevant DHCP fields:

```
cat dhcp.*.log | jq -r '[.f32, .f33, .f34, .f35] | @tsv' | sort -u
```

Exactly one record populates client_fqdn (f34), a `*.kiewit.dartmouth.edu` name. The server-supplied domain `hsd1.vt.comcast.net` on another row is a distractor: that's the domain option on an OFFER, not a client asking to keep its own name. The registrable domain of the FQDN is the answer.

- Q8: REDACTED

### Q9: MAC of a network infrastructure device that requested a DHCP lease

From the same DHCP listing, one client ids itself by hostname as `TL-SG1016DE`, a TP-Link 16-port easy smart switch (OUI = TP-Link). A managed switch is infrastructure, and it requested a lease. The upstream Comcast gateway is also infra but shows up on an OFFER as the modem, so the switch is the clear requester.

- Q9: REDACTED

### Q10: anomaly on the first exchange, which Microsoft protocol suite

Zeek anomalies live in `weird.log` (name in f123):

```
cat weird.*.log | head -3
```

The first entries are `possible_split_routing` and `data_before_established` on an HTTP (port 80) exchange with `fe80::fada:cff:fe33:9ce8`. From the earlier mDNS data that host is the Brother MFC-J5830DW printer (advertised `_pdl-datastream`, `_printer`, `_ipp`, `_scanner`, `_uscan`). The exposed API shows up in the HTTP traffic to it:

```
cat http.*.log | jq -r 'select(.f10=="fe80::fada:cff:fe33:9ce8" or .f12=="fe80::fada:cff:fe33:9ce8") | [.f79, .f80, .f81, .f84] | @tsv' | sort -u
POST    [fe80::fada:cff:fe33:9ce8]      /WebServices/PrinterService     WSDAPI
```

The client user-agent is WSDAPI, Microsoft's Web Services on Devices API: the client stack for WSD, used to discover/control networked printers and scanners over SOAP-over-HTTP. The question asks for the exact protocol string from the logs.

- Q10: REDACTED

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event)

## Lessons

- The hard part wasn't the questions, it was the obfuscated field names. Once I clocked that the numbered keys were just Zeek's standard field order, the rest was routine.
- mDNS / DNS-SD records (`dns.log`) are a goldmine for device id: AirPlay, RAOP, printer services, and device-info model strings all show up there.
- A few answers came out of a single query (Q8 and Q9 from one DHCP listing, printer identity reused for Q10). Reading broadly before filtering saved time.

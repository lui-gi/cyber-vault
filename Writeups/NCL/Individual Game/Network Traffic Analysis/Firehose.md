---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Network Traffic Analysis
difficulty: medium
status: solved
flags: redacted
tags: [writeup, network]
---

# Firehose

## Task

Cyber Command

Our administrator captured network traffic at a conference. Analyze the traffic that went over that network.

- Q1 (10 pts): There's a computer advertising itself as `tdavis-MAC`. What is `tdavis-MAC`'s IPv4 IP?
- Q2 (10 pts): What is its IPv6 IP?
- Q3 (15 pts): `tdavis-MAC` is looking for IPv4 machines to which it can cast to (googlecast). Excluding DNS, which TCP destination port does it try to connect to on the most unique hosts?
- Q4 (15 pts): That same system also appears to be looking for a Drobo file server by sending out broadcasts to a UDP port. What port is this?
- Q5 (15 pts): When it tries to synchronize time it sends NTP traffic to a single NTP server. What's this server's IP address?
- Q6 (15 pts): Based on the first octet of the NTP time server, what company would you say runs the time server?
- Q7 (20 pts): Based on the MAC address, what company made the laptop?

Note: no platform difficulty label was given for this challenge; recorded as medium.

## Approach

Capture: `conference.pcap` (2,361 packets, Ethernet, captured 2019-06-18, about 30 min duration). The pcap is large and was left in `~/PWN` (not copied into the vault).

### Initial recon

```
capinfos conference.pcap
```

The file is small and, like the name "firehose" suggests, it's basically the broadcast/multicast chatter of a single busy laptop at a conference. A quick pass shows only one host actually originates traffic (TCP SYNs, mDNS announcements, NTP, broadcasts), so every question points at the same machine.

Finding the target host:

```
tshark -r conference.pcap -Y 'frame contains "tdavis"' \
  -T fields -e ip.src -e ipv6.src -e eth.src -e _ws.col.Info
```

This surfaces repeated mDNS queries for `tdavis-MAC._googlecast._tcp.local` (SRV, "QU" questions) sourced from:

- MAC `18:65:90:e1:16:bd`
- IPv4 `172.20.29.35`
- IPv6 `fe80::ba:a72d:b016:192c`

Confirmed it's the only active sender in the capture:

```
tshark -r conference.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e ip.src        # every SYN comes from 172.20.29.35
tshark -r conference.pcap -Y 'mdns && dns.flags.response==1 && eth.src != 00:1a:1e:01:74:c0' \
  -T fields -e eth.src       # only 18:65:90:e1:16:bd advertises itself
```

Note on a red herring: the `tdavis-MAC.local A 172.20.20.237` record only ever shows up inside mDNS responses relayed by `172.20.100.20` (MAC `00:1a:1e:01:74:c0`), a Bonjour/mDNS gateway. That address `172.20.20.237` never appears as a real source or destination on the captured segment, so it's a reflected record, not the host we see. The live device is `172.20.29.35`.

## Solution

### Q1 / Q2: IPv4 and IPv6

The host sending the `tdavis-MAC` googlecast queries and all other active traffic uses IPv4 `172.20.29.35` and link-local IPv6 `fe80::ba:a72d:b016:192c`. The IPv6 is confirmed by the host's own reverse record (`...ip6.arpa`) in frame 495, which decodes back to that address.

- Q1: REDACTED
- Q2: REDACTED

### Q3: googlecast TCP port on the most unique hosts

Listed outbound connection attempts and counted unique destination hosts per port:

```
tshark -r conference.pcap -Y 'ip.src==172.20.29.35 && tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e tcp.dstport -e ip.dst | sort -u
```

Results (unique hosts per port):

- port 53 (DNS): 4 hosts, excluded by the question
- port 60000: 4 hosts (172.20.1.38, 172.20.29.206, 192.168.49.1, 203.0.113.1)
- port 8060: 1 host

Excluding DNS, the port it tries against the most unique hosts is the one hitting 4 hosts.

- Q3: REDACTED

### Q4: Drobo discovery broadcast

The host floods directed broadcasts (168 of them) to `172.20.31.255` on a UDP port, which is the Drobo Dashboard discovery port:

```
tshark -r conference.pcap -Y 'ip.src==172.20.29.35 && udp.dstport==<port>' | wc -l
```

- Q4: REDACTED

### Q5 / Q6: NTP server and operator

The host syncs time to a single NTP server:

```
tshark -r conference.pcap -Y 'ntp && ip.src==172.20.29.35' -T fields -e ip.dst
```

The first octet `17` belongs to the `17.0.0.0/8` block, which is owned by Apple (a time.apple.com host).

- Q5: REDACTED (the single NTP server IP)
- Q6: REDACTED (Apple)

### Q7: laptop maker from the MAC

The OUI `18:65:90` resolves to Apple, Inc. (tshark reports `Apple_e1:16:bd`, and the local `manuf`/`oui` database agrees). Consistent with a Mac that uses Apple's NTP pool.

- Q7: REDACTED (Apple, Inc.)

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event)

## Lessons

- When one host dominates a capture, pin it down once (by MAC/IPv4/IPv6 from its own mDNS advertisement) and every question keys off that identity.
- mDNS relays/gateways reflect `.local` records that name IPs which never actually appear on the segment: verify a claimed address shows up as a real src/dst before trusting it.
- First-octet / OUI ownership (17.0.0.0/8 = Apple, OUI 18:65:90 = Apple) answers the "who runs it / who made it" questions without any external lookup.

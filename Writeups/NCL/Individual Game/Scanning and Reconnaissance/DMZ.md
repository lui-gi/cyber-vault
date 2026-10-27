---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Scanning and Reconnaissance
difficulty: hard
status: solved
flags: redacted
tags: [writeup, recon]
---

# DMZ

## Task

Cyber Command. NOTE: Challenge instance will not be accessible once challenge is completed.

We found a Liber8tion server in the wild; we think they've protected some services from scanning, but there might be some holes in those protections. Can you bypass the protections and find out any information about the software on the server? The hostname is `target`.

Q1 - How many open TCP ports are there which are accessible from the remote (Kali) host?
Q2 - On the highest open port from Q1, what software and version are running? (Format: `software D.DD.D`)
Q3 - What string bypasses the software from Q2's filtering controls?
Q4 - Scan from inside `target`, what additional HTTP port is open? (Ignore any ports above 10000)
Q5 - The service from Q4 contains a flag, what is it?

## Approach

Target was ICMP-filtered, so every nmap scan needed `-Pn -n`. A baseline full-range scan only showed two open ports; the rest were silently dropped (no RST/no response), implying a firewall allow-list rather than closed ports.

Service/version detection on the two visible ports showed one of them was a DNS service running on an unusual TCP port. Given the task's "protected from scanning, but holes" framing, that pointed at a source-port-based firewall bypass: the host trusts traffic that appears to originate from its own DNS port. Spoofing the Nmap scan's source port to match that DNS port (`nmap -g <port>`) revealed a third, previously hidden HTTP port.

That HTTP service answered requests with a 403 and a terse rejection message, but only when the request's source port matched the trusted one, so every follow-up request (including version grabs) had to reuse that exact local port. A fixed source port on repeated requests immediately hits TIME_WAIT; a small raw-socket Python client with `SO_REUSEADDR` solved that where the host's `sysctl` was locked down (container, no privilege to tune it).

The 403 response's `Server` header gave the software name and version directly. The rejection body text implied the service was checking some header value against an IP; brute-forcing common header names with a valid loopback IP value found the one header the app actually checked. The success response leaked a Base64-encoded HTTP Basic credential in a response header, decoded to a username and password that worked over SSH.

From an authenticated shell on the target, `ss`/`netstat` output was unreliable over the mangling paste-terminal, so listening ports were read straight from `/proc/net/tcp{,6}` (state `0A` = LISTEN), converting hex ports to decimal. Filtering out the already-known ports and anything above 10000 left one new HTTP port, bound to loopback only. Probing it returned a host-allowlist rejection; reading the web server's actual running configuration file on disk (not the unused default config) showed the port was the web server's **admin API**, relocated off its default port, and that the admin API's config dump endpoint contained the flag directly.

## Solution

1. **Q1 (port count)**: full `-Pn -sS -p-` scan with the source port spoofed to the trusted DNS port (`-g <port>`) revealed all open TCP ports (answer REDACTED).
2. **Q2 (software/version)**: grabbed via the `Server` response header on the newly-revealed HTTP port, requested with the same fixed, trusted source port (answer REDACTED).
3. **Q3 (bypass string)**: a specific request header name set to a loopback IP value (`127.0.0.1` or `localhost`) satisfied the service's IP allowlist check (answer REDACTED, both header name and value matter).
4. **Q4 (internal HTTP port)**: found by reading `/proc/net/tcp{,6}` from an authenticated shell on the target and filtering to ports under 10000 not already known (answer REDACTED).
5. **Q5 (flag)**: read from the admin API's running-config dump endpoint, reachable from `target` itself by sending the correct `Host` header (answer REDACTED).

Credentials and other internal details recovered along the way (SSH login, internal secret-endpoint path/token) have been redacted as this is a graded event; the method above is intact for study.

## Flag

REDACTED

## Lessons

- "Protected from scanning but has holes" is a strong hint to think firewall evasion: try spoofing the scan's source port (`nmap -g <port>` / `--source-port`) against any oddly-placed service you already found (a trusted port often correlates with a service running on an unusual port number).
- When a service only answers requests from a specific source port, every follow-up request needs to reuse that exact port; a raw socket with `SO_REUSEADDR` dodges `TIME_WAIT` when you can't tune `sysctl` (e.g. inside a container).
- A 403/error response that names what it rejected is an allow-list keyed on something you control; brute-force systematically through header name, header value, `Host`, query, path, body, and method until the response changes.
- Always inspect response headers for leaked credentials (`Authorization:`, `Set-Cookie`, internal hostnames), and decode any Base64 you find.
- "Scan from inside" when `ss`/`netstat` are missing or the terminal mangles their output: read `/proc/net/tcp{,6}` directly (state `0A` = LISTEN) and convert hex ports with `printf '%d\n' "0x<hex>"`.
- Read the application's own live configuration file instead of guessing at an allow-list's logic; a relocated admin API (e.g. a web server's management port moved off its well-known default) is a common pattern and often dumps its entire running config, secrets included, from one endpoint once the origin/host check is satisfied.
- Terminal paste corruption on long pastes: push logic into a small script, base64-encode it, and decode remotely with whitespace stripped (`tr -d '[:space:]' | base64 -d`) rather than inlining multi-line payloads.

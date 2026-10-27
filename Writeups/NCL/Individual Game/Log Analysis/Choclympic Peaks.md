---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Log Analysis
difficulty: easy
status: solved
flags: redacted
tags: [writeup, log-analysis]
---

# Choclympic Peaks

## Task

Cyber Command

Choclympic Peaks, a small one-person chocolate shop, is a few days away from announcing a brand new seasonal bar. Before the announcement went out, photos and details of the unreleased treat show up in a chocolate fan forum. The owner pulled their web server's access logs. Help them figure out how the leak happened, and exactly what got out.

- Q1 (15 pts): What IP address did the attacker use during all three days?
- Q2 (15 pts): What was the exact User-Agent string the attacker used?
- Q3 (15 pts): Which path on the site was vulnerable to directory traversal?
- Q4 (10 pts): On the attacker's first day, what value did they pass to the `file` parameter when they first tested whether directory traversal was possible?
- Q5 (20 pts): What is the *slug* of the unreleased product the attacker successfully leaked?
- Q6 (15 pts): What was the full path and query string of the request that successfully retrieved the leaked product's data file?
- Q7 (10 pts): On what date did the attacker successfully retrieve the unreleased product's data? Note: use the pop-up calendar to select the date.

## Approach

A one-person chocolate shop was about to announce a new seasonal bar. Photos/details of the unreleased treat leaked to a fan forum *before* the announcement. The task is to go through the web server's `access.log` (661 lines, traffic across 3 days, 01-03 Aug 2026) and figure out how the leak happened and what got out.

Note: the raw `access.log` is large and was left in `~/PWN` (not copied into the vault).

### Log format

Standard Apache-style combined log, with a quirky trailing space before `]` in the timestamp:

```
83.84.36.109 - - [01/Aug/2026:00:21:47 ] "GET /products/dark-truffle HTTP/1.1" 200 4235 "-" "Mozilla/5.0 (...)"
```

Field map (whitespace-split, i.e. awk default):

| Field | Meaning              |
|-------|----------------------|
| `$1`  | client IP            |
| `$4`  | `[01/Aug/2026:...`   |
| `$6`  | `"GET` (method)      |
| `$7`  | request path         |
| `$9`  | status code          |
| `$10` | response size (bytes)|

The user-agent is quoted and has spaces, so whitespace-splitting mangles it. Re-split on `"` (`awk -F'"'`) and the UA lands in `$6`.

## Solution

### Q1: what IP did the attacker use during all three days?

"All three days" is the first filter but not enough on its own: three IPs show up on all three days. The tiebreaker is behavior, only one of them sends attack traffic (directory traversal, see Q3). That's the attacker.

Build, per IP, the set of distinct days it appears on, then look for size-3 sets:

```bash
awk '{
  day = substr($4, 2, 11)          # "01/Aug/2026"
  key = $1 SUBSEP day
  if (!(key in seen)) { seen[key]=1; days[$1]++ }
} END { for (ip in days) print days[ip], ip }' access.log | sort -rn | head
```

Then disambiguate the 3 candidates by cross-referencing with the traversal hits from Q3; only one shows up there.

- Q1: REDACTED

### Q2: exact User-Agent string the attacker used

Once the attacker IP is known, pull every UA string on that IP's requests and dedupe. The attacker used exactly one UA across all 15 requests.

```bash
awk -F'"' '$0 ~ /^<attacker-ip> / { print $6 }' access.log | sort | uniq -c
```

Splitting on `"` keeps the full UA (with spaces) intact, which matters because "exact" gets graded character-for-character. Note: this UA looks like an ordinary Chrome string, not an obvious scanner like curl/sqlmap, so you can't spot the attacker by a weird UA. Id them by behavior first, then read off the UA.

- Q2: REDACTED

### Q3: which path was vulnerable to directory traversal?

Directory traversal means escaping the intended directory with `../` sequences, often URL-encoded (`..%2f`, `%2e%2e`). Searching for those patterns shows every traversal attempt targeting a single endpoint.

```bash
awk 'tolower($0) ~ /\.\.(\/|%2f)|%2e%2e/ { print $1, $7 }' access.log | sort | uniq -c
```

All hits come from the attacker IP against `/assets/products?file=...`. Normal/legit use of this endpoint is `?file=<image>.jpg` (serving product images). The `file=` param gets passed to the filesystem without sanitization, so `../` lets the attacker read arbitrary files.

- Q3: REDACTED (the `/assets/products` endpoint, exploited via its `file=` parameter)

### Attacker timeline (basis for Q4-Q7)

Filtering to the attacker hitting the vulnerable endpoint, chronological:

```bash
awk '$1=="<attacker-ip>" && $7 ~ /assets\/products\?/ {
  print substr($4,2), "|", $7, "| status="$9, "| bytes="$10
}' access.log
```

```
01/Aug 00:23:52  file=dark-truffle.jpg                                200   <- legit baseline
01/Aug 00:23:53  file=salted-caramel-bar.jpg                          200   <- legit baseline
01/Aug 00:24:38  file=../salted-caramel-bar.jpg                       404   <- FIRST traversal probe (Q4)
02/Aug 00:26:41  file=../../                                          200   <- directory mapping
02/Aug 00:26:41  file=../../../                                       200
02/Aug 00:26:42  file=../../etc/passwd                               200   <- classic traversal proof
02/Aug 00:26:42  file=..%2f..%2fetc%2fpasswd                         200   <- encoded variant
02/Aug 00:26:42  file=../../staging/                                 200   <- found staging dir
02/Aug 00:26:42  file=../../staging/products.json                    200   <- product index
03/Aug 00:21:02  file=../../staging/midnight-mystery-bar.json        200   <- SUCCESSFUL data leak (Q6/Q7)
03/Aug 00:21:03  file=../../staging/midnight-mystery-bar.jpg         200   <- leaked image too
```

The key discriminator is the HTTP status code: 404 is a failed probe (testing), 200 is a successful read. That separates "tested" (Q4) from "successfully retrieved" (Q6/Q7).

### Q4: first value passed to `file` when testing whether traversal was possible

On day 1 (01 Aug) the first two `file=` requests are legit image loads (both 200), normal usage, not an attack. The first request that injects `../` returned 404. That's the attacker's first probe to see if traversal works (and the 404 shows it was just a test, not a successful read yet).

- Q4: REDACTED

### Q5: slug of the unreleased product that was successfully leaked

The successfully-read staging file is `<slug>.json`. The product slug is the filename stem (no dir, no extension).

- Q5: REDACTED

### Q6: full path + query string of the successful data-file retrieval

"Data file" means the `.json` (structured product data), not the `.jpg` (image). The successful request returned 200 with 2636 bytes. Answer the full path including the query string (`/assets/products?file=...`).

- Q6: REDACTED

### Q7: date of the successful retrieval

The successful `.json` read is timestamped `03/Aug/2026:00:21:02`. Earlier staging reads were on 02 Aug, but the unreleased product's data was first pulled on 03 Aug. Use the pop-up calendar to select that date.

- Q7: REDACTED

### What leaked

The traversal walked up and into the server's `staging/` directory and grabbed the unreleased bar's `.json` details and its `.jpg` photo. The attacker also tested the classic `../../etc/passwd` to confirm the traversal worked before pivoting to the staging assets.

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event)

## Lessons

- Understand the log format first, know your field positions before writing filters.
- Narrow, then confirm: "appears all 3 days" narrowed to 3 IPs, attack behavior confirmed the one.
- Pivot on the attacker IP: once identified, the UA (Q2) and target path (Q3) fall out of that IP's activity.
- Watch encoding: traversal payloads can be literal (`../`) or URL-encoded (`..%2f`, `%2e%2e`), so match both case-insensitively.

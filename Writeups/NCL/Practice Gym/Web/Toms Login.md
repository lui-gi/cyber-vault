---
type: writeup
source: NCL/Practice Gym
event: NCL Practice Gym
category: Web
difficulty: medium
status: solved
flags: kept
tags: [writeup, web, nosql-injection, mongodb]
---

# Tom's Login

## Task

> We have found a hacker's website posing as our beloved friend Tom's personal website. Can you identify the security vulnerability and log in as `tom`? We think it's possibly vulnerable but they've implemented a rate limiter on the website.
>
> *Note: Scope is limited to HTTPS. Educated & limited fuzzing is okay, but no automated/random bruteforce tools.*

Target: `https://<id>-toms-login.web.cityinthe.cloud/login`, a single login page.

## Approach

- Recon on the login page (no binary, so HTTP headers and page behavior):
  - `curl -sI` showed `Server: nginx`, `X-Powered-By: Express` (Node.js/Express), and `X-RateLimit-Limit: 12` + `X-RateLimit-Remaining` (an app-level limiter, 12 requests per window). Express + Mongo is the classic pairing for this bug class.
- The login takes `username` and `password` as query parameters and the response renders a document count: `<div class="sub header">Database Documents : 1</div>`. That count is the server telling us how many records matched.
- Because Express parses query strings with `qs`, bracket notation becomes a nested object, not a string:
  ```
  ?username=tom&password[$regex]=^j   →   { username: "tom", password: { $regex: "^j" } }
  ```
  Reconstructed server logic (source not provided, inferred from behavior):
  ```js
  const count = await users.countDocuments({
    username: req.query.username,   // "tom"
    password: req.query.password,   // attacker-controlled: string OR operator object
  });
  res.send(render(`Database Documents : ${count}`));
  ```
- Two behaviors pinned the attack surface:
  - **Operator blacklist**: `username[$eq]=tom&password=password` returns *"Your login has one or more disallowed operations"*, so `$eq`/`$ne`/etc. are filtered. A naive `{$ne: null}` bypass is blocked.
  - **`$regex` is NOT filtered**: `password[$regex]=...` returns a document count. Since `username=tom` is unique, that count is only ever `1` (match) or `0` (no match), a perfect blind-boolean oracle.

## Solution

The vulnerability is MongoDB operator injection via Express/`qs` query-string parsing. Operators never actually log you in (every operator query returns "Invalid Operation" + count), so this is blind extraction, not an auth bypass: recover the password character by character with the `$regex` oracle, then do a clean plaintext login.

1. **Confirm the oracle:** `password[$regex]=.*` → `Documents : 1`; `password[$regex]=^zzNOMATCH$` → `Documents : 0`.
2. **Bypass the rate limiter:** the limiter is keyed on client IP read from `X-Forwarded-For` (confirmed by watching `X-RateLimit-Remaining` change with the header). Rotating a random `X-Forwarded-For` per request gives each request a fresh bucket, no bruteforce tooling required.
3. **Find the length:** binary search on `^.{0,n}$`.
4. **Extract each char:** binary search on `^<prefix>[<class>]` over `[A-Za-z0-9]` (special chars are sanitized). A boolean oracle gives `log2(alphabet)` per char, so ~6 requests/char for a 62-char set instead of ~62, roughly a 10x reduction.
5. **Verify:** `^<password>$` → `Documents : 1`.
6. **Log in for real:** `username=tom&password=<recovered>` with no operators → the authenticated page.

Solve scripts (binary-search blind extractor): [[Toms Login/solve.py]] (Python), [[Toms Login/optimized.sh]] (bash, binary search), [[Toms Login/extract.sh]] (bash, earlier linear version).

### Pivots (what failed first)
- **Bad success-detection.** First logic was "response differs from the known-fail response." Per-request jitter wobbled the body size and false-positived a password of `5`. Fix: calibrate against a guaranteed-TRUE query (`.*`) and a guaranteed-FALSE one, and lock onto a stable discriminator (the parsed count).
- **Marker spacing.** A literal match on `database documents: 1` never matched; the real text is `Database Documents : 1` (spaces around the colon). Fix: parse with a whitespace-tolerant regex `Documents\s*:\s*(\d+)`.
- **Linear scan was slow.** Up to 62 requests/char; switched to binary search over regex character classes.

## Flag

Flag not recorded in the writeup: the solve recovered the password and reached the plaintext-login step, but the final flag string from the authenticated response was not captured.

## Lessons
- Don't detect success by "it's different." Page jitter produced a false positive; always calibrate against a known-true and known-false signal.
- Match the real output, not the output you assumed (the `Database Documents : 1` spacing cost a round-trip).
- A boolean oracle is `log2(n)` per character, so binary search should be the default, not the fallback after a slow linear pass.
- Reading response headers handed over the rate-limit bypass (`X-Forwarded-For`) for free.

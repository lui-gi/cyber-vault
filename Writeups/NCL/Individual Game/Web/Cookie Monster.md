---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Web
difficulty: easy
status: solved
flags: redacted
tags: [writeup, web]
---

# Cookie Monster

## Task

Cyber Command

_**NOTE: Challenge Instance will not be accessible once challenge is completed. Your scope is limited to HTTPS. You may use automated tools that make educated guesses for this challenge, but blind automated brute force is not permitted.**_
We finally have access to Liber8tion's internal project dashboard. Can you help us find admin-only information?

https://00152bc0df7c7d5983ee28746a85f1b8-cookie-monster.web.cityinthe.cloud

Q1 - 30 points: What is the first flag?
Q2 - 35 points: What is the admin flag?
Q3 - 35 points: What is the flag from the /resources endpoint?

## Approach

- Did normal initial recon and enumeration of the webapp.
- Checked `robots.txt`, found `/admin-panel`, navigated there and grabbed the first flag.
- Noticed cookie values on the site and enumerated a `user_id` value from 0 to 5, which grabbed the admin flag (broken access control via a predictable, sequential identifier).
- Went to the `/resources` endpoint and saw the cookie value was base64-encoded.
- Decoded the cookie, saw it held a JSON-like structure such as `{"userId":1,"tier":"standard","dataLevel":2}`, then edited the decoded value to raise the data level and re-encoded it to re-set the cookie.
- Nuance: the base64 padding at the end of the original cookie was `0%3D` (a URL-encoded `=`), not a literal `03`. The edited value had to keep that percent-encoded padding to match the format the server expected, otherwise the cookie was rejected. Once the cookie was rebuilt correctly, the `/resources` endpoint returned the last flag.

## Solution

1. Enumerate `robots.txt` to find the disallowed `/admin-panel` path. Flag: REDACTED.
2. Inspect the session cookie, identify a `user_id` field, and increment/brute through small integer values (0-5) to access another user's admin session (insecure direct object reference / missing authorization check on `user_id`). Flag: REDACTED.
3. On `/resources`, decode the cookie from base64, tamper with the `dataLevel` field to escalate privilege, re-encode to base64 while preserving the exact URL-encoded padding (`%3D` for `=`) the server expects, and resubmit the cookie. Flag: REDACTED.

## Lessons

- Never trust client-side state (cookies) for authorization decisions; `user_id` and privilege/tier fields must be validated server-side against the authenticated session, not read back from a value the client can edit.
- Sequential, predictable identifiers (`user_id` 0-5) make horizontal privilege escalation trivial; use non-guessable identifiers or enforce per-user authorization checks regardless of the ID supplied.
- Encoding (base64) is not encryption or integrity protection: if a cookie carries meaningful authorization data, it should be signed/encrypted server-side (e.g. signed session tokens) so client-side tampering is detected and rejected.
- Small format details (percent-encoding of padding characters) can make or break a replay; understanding the exact encoding the server expects is often as important as finding the vulnerability itself.

---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Web
difficulty: hard
status: solved
flags: redacted
tags: [writeup, web]
---

# Cookie Security Protocol

## Task

Cyber Command

_**NOTE: Challenge Instance will not be accessible once challenge is completed. Your scope is limited to HTTPS. You may use automated tools that make educated guesses for this challenge, but blind automated brute force is not permitted.**_
Some pesky browser security setting called "Same Origin Policy" kept breaking our seamless user experience. We made sure to turn on every other protection we could to compensate, so we should be secure now. We are so confident in our security, we are even giving you source code access!

It may take up to a minute for the server to boot up. You may get 404 errors until the server boots.

https://6adce13ba2dc1a9328f2ac2b-8000.gateway.cityinthe.cloud/

Q1 - 10 points: What is the CWE number of the vulnerability on `/login`? Give the 3 digit CWE weakness ID of the vulnerability. There are multiple correct answers.
Q2 - 25 points: What is the flag set in the bot's cookie for `https://callback/`?
Q3 - 10 points: Which page displays unsanitized user input? Enter as a path, ex: `/api/example`
Q4 - 55 points: What is the flag displayed in `/admin`?

Source was provided as a Flask app (`app.py`, included below).

## Approach

The challenge hints that `SameSite` cookie protection was deliberately disabled ("Same Origin Policy... turned off") but claims every other control was hardened to compensate. Reading `app.py` (see `Cookie Security Protocol/app.py`) confirmed:

- `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="None"`, `SESSION_COOKIE_SECURE=True`: the session cookie can't be read by JavaScript, but it is sent on every cross-site request over HTTPS.
- A strict, nonce-based Content-Security-Policy with `default-src 'none'` and no script execution anywhere except nonce-tagged inline scripts: this blocks classic reflected/stored XSS from running arbitrary attacker JavaScript on the portal pages.
- A CSRF token stored server-side in the session and compared with `secrets.compare_digest` against a `csrf_token` form field on every POST.

**Q1 - open redirect on `/login` (CWE-601).** The `/login` route reads a `next` query parameter and redirects to it after a successful login, gated only by:

```python
def is_safe_next(target):
    return bool(target) and target.startswith("/")
```

This only checks for a single leading `/`. A value like `//example.com` still starts with `/` but browsers resolve a double-slash path as a protocol-relative URL to an external host, giving an open redirect. CWE-601 (Open Redirect) fits; CWE-610 (externally controlled reference to a resource) was considered but is less specific.

**Q2 - leaking the admin bot's cookie via the open redirect.** An admin-privileged headless browser ("the bot") can be pointed at a path under the portal. It can't be sent directly to an external origin, but the open redirect on `/login` can bounce it there: requesting the bot to visit `login?next=//callback/<path>` makes the browser resolve the protocol-relative redirect to the external callback origin. Because the session cookie is `SameSite=None` and `Secure`, it rides along on that cross-site navigation. Watching the callback service's request log showed the bot's cookie arrive on the forwarded request, containing the flag.

**Q3 - unsanitized input on `/board`.** The app escapes HTML by default (Flask/Jinja2 auto-escaping), so most tags came back encoded. Posting comments containing various tags to the user-facing comment board at `/board` showed that some inline tags (e.g. italics, anchors) rendered unescaped in certain contexts, while others didn't. This indicated `/board` was the page reflecting unsanitized/under-sanitized user input back into the page.

**Q4 - escalating to admin via `/admin`.** `/admin` requires the `admin` role, and `/admin/promote` (which grants that role) requires both the admin session and a valid CSRF token compared with `compare_digest`. The bot cannot be scripted to click or submit anything, the CSP blocks inline/attacker script execution on portal pages, and SOP/CORS blocks directly reading another origin's response. In short, every obvious script-based or form-based exfiltration channel (subresource loads, cross-origin fetch/XHR reads, cross-origin form posts) was closed off by the CSP (`default-src 'none'`, `form-action 'self'`, `img-src 'none'`, etc.) and SOP.

The eventual path combined several of the lab's own weaknesses rather than any single flaw:
- The response headers were missing `frame-ancestors`/`X-Frame-Options`, so the portal could still be embedded in a frame from the callback origin despite the otherwise strict CSP.
- A stored-comment injection on `/board` could plant markup that, when rendered inside a frame, captured the authenticated admin's CSRF token into a browsing-context property (a frame's `name`) rather than into a URL. Browser mitigations that block "dangling markup" from leaking data through a navigation URL don't apply to a plain string property like `window.name`, and that property survives a same-context navigation, so it could be read back from the attacker-controlled (callback) origin once that origin initiated the navigation.
- With the real CSRF token in hand, a cross-site `fetch(..., credentials: 'include')` from the callback origin to `/admin/promote` rode the admin's `SameSite=None` session cookie and supplied the correct token, satisfying `compare_digest` even though the response itself couldn't be read back (CORS still blocked reading it, but the side effect, the promotion, still happened server-side).
- Finally, the open redirect from Q1 (`/login?next=//callback/<path>`) was reused to make the *admin* bot (already authenticated) navigate to the malicious callback page and trigger the whole chain in a single bot run.
- After promotion, logging back in as the attacker-controlled (newly promoted) user and visiting `/admin` returned the flag.

## Solution

1. CWE on `/login`: **601** (URL Redirection to Untrusted Site, "Open Redirect") via `is_safe_next`'s naive `startswith('/')` check, bypassed with a protocol-relative `//host/path` value.
2. Flag in the bot's cookie at `https://callback/`: obtained by bouncing the admin bot off the open redirect (`/login?next=//callback/<path>`) and reading its forwarded `SameSite=None` cookie from the callback service's request log. Flag: REDACTED.
3. Page displaying unsanitized user input: `/board`.
4. Flag in `/admin`: obtained by chaining the missing frame-blocking headers, a stored markup injection on `/board` that exposed the admin's CSRF token through a browsing-context `name` property (not a URL, so dangling-markup URL mitigations didn't apply), a cross-site authenticated POST to `/admin/promote` using that token, and the Q1 open redirect to drive the admin bot through the whole chain in one run. After self-promotion, `/admin` returned the flag. Flag: REDACTED.

## Lessons

- `SameSite=None` cookies are sent on cross-site requests by design; pairing that setting with any other weakness that can trigger a cross-site POST (open redirect, CSRF-token leak, missing frame protections) effectively undermines CSRF defenses even when a per-request CSRF token is implemented correctly in isolation. Defense in depth matters: one bypassed control compensates for the others being disabled.
- A "safe" redirect check that only validates a single leading `/` is not sufficient; browsers treat `//host/path` as protocol-relative, so always resolve/parse the target and compare against an explicit allow-list of in-app paths or hosts, not a prefix check.
- A strict Content-Security-Policy is a strong mitigation against classic XSS, but it is not a substitute for `X-Frame-Options`/`frame-ancestors`; omitting frame-blocking headers can let an otherwise CSP-hardened page be embedded and abused in ways the CSP wasn't designed to stop.
- Not all data exfiltration techniques route through a URL. Browsing-context properties such as `window.name` persist across certain navigations and are a known side channel ("dangling markup via iframe name") that isn't covered by mitigations aimed only at URL-based leaks; secrets (CSRF tokens, etc.) should never be reflected into any part of the DOM that could end up addressable from another origin.
- CORS blocking the ability to *read* a cross-origin response does not stop the *request* from completing; a cross-site POST with credentials still executes server-side even if the attacker's JS never sees the response. State-changing actions should additionally require something an attacker genuinely cannot obtain or replay (e.g. a token bound to an interaction the bot can't be forced into, or re-authentication for sensitive privilege changes), not rely solely on CORS opacity.

## Supporting files

See `Cookie Security Protocol/app.py` for the full Flask source referenced above.

Left in `~/PWN` (not copied, per ingestion rules): `pages.md` (the full HTML template dump, ~13KB) and `app.py.md` (a near-duplicate rendering of `app.py`, ~5KB) are summarized above rather than reproduced in full; `local-test-ignore.zip` (>1MB) and the `.claude/scheduled_tasks.lock` file were also left in place.

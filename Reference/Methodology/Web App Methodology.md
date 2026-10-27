---
type: reference
category: Methodology
tags: [reference, methodology, web]
---

# Web App Methodology

General workflow for web-app CTF challenges and lab targets. Payload details live in `Reference/Payloads/`; this note is the checklist and the glue between vuln classes.

## 1. Recon and enumeration

Run this on every target before touching a specific vuln. On harder challenges the recon *is* the hint.

- **Read the page.** Load the site, read visible text, note every input: forms, search boxes, URL parameters, file uploads, cookies.
- **View source and JS.** Check HTML comments, hidden fields, dev notes, linked JS. Authors leave hints in source more often than you'd think.
- **Watch requests.** DevTools Network tab or Burp. Note method (GET/POST), parameter names, and how your input comes back. Input reflected in the response is the first tell for any injection.
- **Read the full response.** Flags and tokens often come back in the response body or a JSON field, not the rendered page (see [[No SQLi]], where the flag was in the `/login` response `token` field).
- **Fingerprint the stack.** Response headers (`Server`, `X-Powered-By`, custom headers like `X-Real-Server`), cookie format (a signed `session` cookie is a Flask tell), error-page styling. Custom headers can leak exact software + version (see [[You Have Been Pwned]], `X-Real-Server: Caddy 2.8.0`).
- **Check default/discovery files.**
  ```
  /robots.txt        (disallowed paths often point at admin panels)
  /sitemap.xml
  /.git/
  /admin  /admin-panel
  /openapi.json  /docs  /swagger   (API auto-docs leak undocumented routes)
  ```
- **Probe each input.** Submit something benign, then something special. Does HTML render? Does `{{ }}` evaluate? Does a Mongo/SQL operator change behavior? This is where recon hands off to exploitation.

## 2. Pick the attack by what you observed

| Observation | Likely class | Payloads |
|---|---|---|
| Input reflected and `{{7*7}}` -> `49` | Template injection | [[SSTI]] |
| Login/search feeds a SQL DB | SQL injection | [[SQLi]] |
| Login feeds Mongo / JSON body accepted | NoSQL injection | [[NoSQL Injection]] |
| Input reflected into HTML/JS unescaped | Cross-site scripting | [[XSS]] |
| `next`/`url`/`redirect` parameter | Open redirect (-> cookie theft, CSRF chain) | [[Open Redirect]] |
| Predictable `user_id` / sequential or hashed IDs in URL or cookie | IDOR / broken access control | see below |
| Client-side state (cookie) carries role/tier | Cookie tampering | see below |
| User-controlled value echoed into a proxy/template placeholder | Server-side injection / LFI | see below |

## 3. Access-control and client-trust techniques

These showed up repeatedly in the NCL web set and are more "methodology" than "payload".

### IDOR / broken access control
Sequential or guessable identifiers let you walk to other users' data. Increment `user_id` 0..N, or reconstruct a hashed ID offline.
- Hashed-ID enumeration: an admin profile hidden behind `md5(id)` is trivially brute-forced when the input is a small numeric range. Scope hints ("20 employees") bound the search (see [[Hashgate]]).
  ```python
  import hashlib, requests
  for i in range(3001, 3021):
      h = hashlib.md5(str(i).encode()).hexdigest()
      r = requests.get(base + h)
      if "admin" in r.text.lower():
          print(i, r.text); break
  ```
- Fix: enforce per-user authorization server-side regardless of the supplied ID; use non-guessable identifiers.

### Cookie tampering
Encoding is not integrity protection. If a cookie carries authorization data (`tier`, `dataLevel`, `userId`), decode it, edit it, re-encode it (see [[Cookie Monster]]).
- base64 cookie -> decode -> edit JSON (`{"userId":1,"tier":"standard","dataLevel":2}`) -> re-encode.
- Preserve the server's exact encoding, including URL-encoded padding (`%3D` for `=`), or the cookie is rejected.
- Fix: sign or encrypt session state server-side so tampering is detected.

### Header / placeholder injection (local file read)
A reverse proxy or template that substitutes placeholder syntax from a request header is an injection point. Caddy's placeholder mechanism (CVE-2026-30852) let a header value like `{file./flag.txt}` or `{file./proc/self/environ}` reflect file contents back (see [[You Have Been Pwned]]).
- Leak env vars via `/proc/self/environ`, pull a token, replay it to an undocumented API route found in `/openapi.json`.
- Fix: never let user-controlled input flow into a placeholder/templating engine unsanitized.

### Credential stuffing
Replay leaked email/password pairs against a login to find reused credentials (see [[Credential Stuffing]]). Automated educated guesses may be allowed; blind brute force usually is not. Check challenge rules.

## 4. Chaining (hard targets)

One control being hardened does not save you if another is disabled. The [[Cookie Security Protocol]] chain is the canonical example: `SameSite=None` cookies + an open redirect + missing `frame-ancestors`/`X-Frame-Options` + a CSRF-token leak via `window.name` combined into an authenticated cross-site POST, even though CSP and the CSRF token were individually correct. Defense in depth matters; so does attacking in depth.

Key chaining facts:
- `SameSite=None; Secure` cookies ride along on cross-site requests by design.
- CORS blocking the *read* of a cross-origin response does not stop the *request* (and its side effects) from completing.
- Not all exfiltration routes through a URL: `window.name` persists across navigations and dodges dangling-markup URL mitigations.

## Related
- Payloads: [[SSTI]], [[SQLi]], [[NoSQL Injection]], [[XSS]], [[Open Redirect]]
- Writeups: [[SSTI1]], [[No SQLi]], [[Cookie Monster]], [[You Have Been Pwned]], [[Cookie Security Protocol]], [[Hashgate]]

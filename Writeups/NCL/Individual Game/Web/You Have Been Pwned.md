---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Web
difficulty: medium
status: solved
flags: redacted
tags: [writeup, web]
---

# You Have Been Pwned

## Task

Cyber Command

_**NOTE: Challenge Instance will not be accessible once challenge is completed. Your scope is limited to HTTPS. You may use automated tools that make educated guesses for this challenge, but blind automated brute force is not permitted.**_
Liber8tion left a web server open with their collection of stolen creds and other data. Since they forgot to keep the site private, maybe there are other vulnerabilities you can find?

It may take up to a minute for the server to boot up. You may get 404 errors until the server boots.

https://6adc28fd9a497ed16bde434a-80.gateway.cityinthe.cloud/

Q1 - 10 points: What software is the web server running and what is its version? Answer format: `Software x.x.x`
Q2 - 40 points: What are the contents of the flag on the server at /flag.txt?
Q3 - 10 points: What CVE was used to get the flag in Q2? Answer Format: `CVE-YYYY-NNNNN`
Q4 - 40 points: What is the flag retrieved from querying the v2 API?

## Approach

Initial recon showed two versions of the same `/creds` endpoint behind one gateway: an `X-Api-Version: 1` response served by Werkzeug/Python (Flask) and an `X-Api-Version: 2` response served by uvicorn (FastAPI/Starlette). Both returned the same leaked credential dump, just with differently ordered JSON keys, confirming the API-version header picked between two backend implementations.

A plain `curl -I` on the root page revealed a non-standard `X-Real-Server: Caddy 2.8.0` response header, answering Q1 directly: information disclosure via a custom header the server didn't need to send.

Fuzzing the `X-Api-Version` header with a Caddy placeholder-style payload (`{file./flag.txt}`) caused the server to reflect the contents of that file back in an "Invalid API Version" error message. This is a known Caddy vulnerability (CVE-2026-30852) where request headers that get echoed through Caddy's reverse-proxy/placeholder substitution can be abused to inject placeholder syntax such as `{file.<path>}`, letting an attacker read arbitrary files on the host through a header that is naively reflected back without sanitizing placeholder syntax. This answered Q2 and Q3.

For Q4, the v2 API additionally exposed an `/openapi.json` (FastAPI auto-docs) that revealed an undocumented `POST /internal-vault` endpoint requiring a `vault_access_token` in the JSON body. The same Caddy placeholder-injection primitive was reused, this time with `{file./proc/self/environ}`, to dump the backend process's environment variables, which contained `VAULT_ACCESS_TOKEN`. Posting that token to `/internal-vault` (using the exact, case-sensitive JSON field name `vault_access_token`, not the uppercase env var name) returned a list of internal secrets including the final flag.

## Solution

1. `curl -I` the site root; the `X-Real-Server` response header discloses `Caddy 2.8.0` directly. Answer: `Caddy 2.8.0`.
2. Send a request with `X-Api-Version: {file./flag.txt}`. Caddy's placeholder substitution (CVE-2026-30852) treats the header value as a placeholder expression and reflects the target file's contents into the "Invalid API Version" error body. Flag: REDACTED.
3. CVE used: `CVE-2026-30852`.
4. Enumerate the FastAPI backend (`X-Api-Version: 2`) via `/openapi.json`, discover `POST /internal-vault`. Reuse the Caddy placeholder injection with `X-Api-Version: {file./proc/self/environ}` to leak environment variables, including `VAULT_ACCESS_TOKEN`. POST `{"vault_access_token": "<token>"}` (lowercase, exact field name per the OpenAPI schema) to `/internal-vault` to retrieve a list of secrets. Flag: REDACTED.

## Lessons

- Custom debug/diagnostic response headers (like `X-Real-Server`) leak exact software and version information that should never reach an unauthenticated client; strip or omit non-essential headers in production.
- Reverse proxies that substitute placeholder syntax from request data (headers, query params) into responses or logs must strictly validate and sanitize that data; letting user-controlled input flow into a templating/placeholder engine is effectively an injection vulnerability (here, arbitrary local file read via Caddy's placeholder mechanism).
- Auto-generated API documentation (`/openapi.json`, Swagger/FastAPI docs) is a reconnaissance goldmine: always check framework-default discovery endpoints for hidden or undocumented routes.
- Secrets management: putting access tokens in process environment variables is only as safe as the surrounding system; any local file/environment read vulnerability on the host becomes a full secrets leak. Secrets should be pulled from a vault/secret manager with short-lived, scoped credentials instead of long-lived tokens sitting in `environ`.
- JSON field names are case-sensitive; API input validation errors (`422 field required`) are useful for diagnosing exact expected payload shape instead of guessing blindly.

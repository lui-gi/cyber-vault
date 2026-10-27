#!/usr/bin/env python3
# Generate policy-matching password candidates from a CeWL-style word base.
# Policy: length >= 10, exactly ONE uppercase, exactly ONE special char.
import sys

words_file = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "first"  # "first" or "anypos"

specials = list("!@#$%^&*_-.?+")
digits = ["", "1","2","3","7","9","12","21","23","24","42","69","77","88","99",
          "100","101","123","007","111","121","222","321","420","666","777","999",
          "1234","2019","2020","2021","2022","2023","2024","2025"]

def is_special(c):
    return not c.isalnum()

def emit(s):
    if len(s) < 10:
        return
    u = sum(1 for c in s if c.isupper())
    sp = sum(1 for c in s if is_special(c))
    if u == 1 and sp == 1:
        out.append(s)

out = []
with open(words_file, encoding="utf-8", errors="ignore") as f:
    base = [w.strip() for w in f if w.strip().isalpha()]

seen = set()
for w in base:
    w = w.lower()
    # capitalization variants
    caps = []
    if mode == "first":
        caps.append(w[0].upper() + w[1:])
    else:  # anypos: capitalize each single letter position
        for i in range(len(w)):
            caps.append(w[:i] + w[i].upper() + w[i+1:])
    for W in caps:
        for d in digits:
            for s in specials:
                for cand in (W + d + s, W + s + d, s + W + d, d + W + s):
                    if cand not in seen:
                        seen.add(cand)
                        emit(cand)

sys.stdout.write("\n".join(out))
sys.stdout.write("\n")

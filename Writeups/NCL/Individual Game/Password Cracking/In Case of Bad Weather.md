---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Password Cracking
difficulty: medium
status: solved
flags: redacted
tags: [writeup, password-cracking]
---

# In Case of Bad Weather

## Task

Cyber Command

We found Jamie Pendergast's password hint sheet on the floor of a restaurant. We'd like to use it to log in to dev6, but the password on the sheet doesn't work! The clues we have are that the password sheet has some reminders listed, and that Jamie's a bit of a math nerd. The passwords do not contain: zero (`0`), one (`1`), "ell" (`l` or `L`), or vertical pipes (`|`).

Q1 - What is the jpendergast password for dev2?
Q2 - What is the jpendergast password for dev6?
Q3 - What is the jpendergast password for web1?
Q4 - What is the name of the conjecture used to generate numbers used in adjusting the passwords?

## Approach

Given three `yescrypt` (`$y$`) shadow entries for the same user across three hosts, plus a "hint sheet" listing a near-miss password for each host, and three word reminders on the sheet. The stated rule (no `0`, `1`, `l`/`L`, or `|` in any password) is a strong filter on what the *real* passwords can look like, and the sheet passwords already obeyed that rule too, so the sheet values were close but not exact.

Reading the reminder words as clues: one word maps directly to the Collatz conjecture (also called the hailstone sequence, generating the "math nerd" numbers), one word signaled that the issue was specifically about *letter casing*, not characters. That meant the digits already present on the sheet were correct, only the upper/lowercase pattern of the letters needed fixing, the Collatz/hailstone angle was a (slight) red herring for brute-forcing digit substitutions; it was really the answer to Q4 on its own, not a transformation to actually apply to the passwords.

`hashcat` has no `yescrypt` mode, so candidate verification used Python's `crypt(3)` binding directly against each hash's own salt. For each sheet password, every alphabetic character's case was flipped in every combination (2^n for n letters, a few hundred to ~1000 combinations per host) while leaving digits and symbols untouched, and each candidate was checked against the correct per-host hash. All three cracked within a few hundred tries each. An earlier attempt that tried mutating only the digit (via Collatz-sequence-derived numbers, replacing or appending digits) found nothing, confirming the digit was never the actual problem.

## Solution

1. Read `hail` as a reference to the Collatz conjecture / hailstone sequence (directly answers Q4).
2. Read the casing-related reminder word as the real hint: only letter case needed correcting, not the digits.
3. For each host's sheet password, brute-forced every upper/lowercase combination of just its alphabetic characters, verifying each against the host's own `yescrypt` hash with `crypt(3)`.
4. All three (dev2, dev6, web1) passwords cracked this way; all satisfy the stated no-`0`/`1`/`l`/`L`/`|` rule.

Answers: Q1-Q3 = the corrected-casing passwords for dev2/dev6/web1 (all REDACTED). Q4 = the Collatz conjecture (hailstone sequence).

## Flag

REDACTED

## Lessons

- `yescrypt` isn't supported by `hashcat`; verify candidates directly with the system's own `crypt(3)` (Python's `crypt` module) against the hash's embedded salt/params instead.
- When a "hint sheet" password is close-but-wrong, don't assume the character set needs mutating; test the cheapest hypothesis first (here, just flipping letter case) before brute-forcing digit substitutions from a themed math sequence.
- Read flavor-text reminder words literally as independent clues, one may answer a sub-question directly (the conjecture's name) while another describes the actual fix needed to the password (casing), rather than both describing the same transformation.
- An explicit character-exclusion rule (no `0`/`1`/`l`/`L`/`|`, chosen because those characters are visually ambiguous) is itself a clue about font/readability-driven password policy design, worth recognizing as a pattern.

Supporting file: `digexp.py` (digit/Collatz-substitution experiment script, confirmed the digit was not the issue) copied alongside this note. The actual `.shadow` hash files and the plaintext password sheet are left in `~/PWN/ncl_individual/password-cracking/in-case-of-bad-weather_medium/` and not copied per ingestion rules.

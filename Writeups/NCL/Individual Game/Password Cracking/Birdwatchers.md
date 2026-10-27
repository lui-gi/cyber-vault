---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Password Cracking
difficulty: hard
status: solved
flags: redacted
tags: [writeup, password-cracking]
---

# Birdwatchers

## Task

Cyber Command

A small subset of Liber8tion is believed to be part of a society of birdwatchers, and they might be using their forum to transmit sensitive information. We were trying to obtain their credentials, and managed to tap their misconfigured server, which exposed backend auth traffic. Can you crack their passwords? We think their passwords are at least 10 characters, with exactly one uppercase character and exactly one special character.

Q1 - What is alice.wren's password?
Q2 - What is bob.finch's password?
Q3 - What is charlie.hawk's password?
Q4 - What is diana.swift's password?
Q5 - What is eve.martin's password?

## Approach

Given a TLS-encrypted pcap plus the leaked TLS session keylog (the "misconfigured server" leak). Decrypted with `tshark` using the keylog file, which revealed one HTTP exchange: a debug endpoint dumping a JSON blob of five `sha512crypt` (`$6$`) password hashes, one per bird-species-themed username (all five usernames are bird species, and the group name itself is leetspeak).

Policy constraint given in the task (>=10 chars, exactly one uppercase, exactly one special character) is the key lever against slow `sha512crypt` hashing: generate mangled candidates from a word list, filter to the exact policy, and only hash the survivors (since hashing is the slow part on CPU, no GPU/OpenCL backend was available on the cracking host).

Progression of attempts (CPU-only `john`, ~1,500 candidates/sec against 5 salts):
1. Plain rockyou filtered to the policy, 0 hits (passwords are not raw rockyou words).
2. A curated bird-name word list (capitalize first letter, trailing special+digits), 0 hits.
3. Same bird list with capital/special at any position, 0 hits, meaning the specific bird word wasn't in that narrower list.
4. rockyou x `best64` rules, filtered to policy, partially tested (truncated by a time cap).
5. A much larger bird-vocabulary word list (ABA checklist style corpus), interrupted by shared-host CPU contention before meaningful coverage.

The strongest unresolved lead going into a later session was a **CeWL-style** word list scraped from the birdwatchers forum site itself (a retired-challenge URL was still reachable), since the task's framing ("their forum to transmit sensitive information") pointed at the site's own vocabulary as the true password base, not a generic bird list. The site's pages were fetched and tokenized by hand (CeWL itself wasn't installed) into a base word list plus concatenated adjacent-word bigrams, which captured full species names and scientific binomials verbatim as they appeared on the site. Per-member thematic associations were also derived from the site text (each username's apparent species/location theme). A reusable candidate generator (`gen_candidates.py`, included alongside this note) applies the exact policy filter (length >= 10, exactly one uppercase, exactly one special) to any word-list base, with configurable capitalization placement (first-letter vs. any-position) and a set of common specials/digit suffixes/prefixes.

## Solution

Status at the point this was last worked: 0 of 5 hashes cracked, work paused mid-run. The CeWL-derived site word list (and its bigrams) had a bird-watchers-forum round in progress when work stopped, with several un-tried ranked hypotheses remaining (finishing the bigram run, capitalizing at any position rather than just first-letter, a special character placed *between* two words in username-dot style, and a leet-speak substitution matching the group's "Liber8tion"-style branding). The best64 x rockyou run had an estimated ~10M untested policy-matching survivors remaining when paused.

No final passwords were recovered in the material available for this writeup; the technique (decrypt via leaked TLS keylog -> extract sha512crypt hashes -> policy-filtered, site-themed wordlist mangling against CPU-only john) is the reusable part of this one.

## Flag

REDACTED (no answers were confirmed as cracked in the session material available)

## Lessons

- A leaked TLS session keylog decrypts captured traffic cleanly with `tshark -o "tls.keylog_file:<file>"`, worth checking for in any "misconfigured server" framing.
- An explicit password-composition policy (exact length/uppercase/special-char counts) is a major lever against slow hashes: generate candidates from a themed word base, filter to the policy *before* hashing, and only feed survivors to the cracker.
- When usernames or a group name carry a clear theme (bird species, leetspeak branding), prefer scraping the actual in-fiction source (a forum/site mentioned in the task) for a CeWL-style word list over a generic themed dictionary; a word list built from the specific site's vocabulary is far more likely to contain the real base words than a general list of the same theme.
- `sha512crypt` with no GPU/OpenCL backend available is genuinely CPU-bound (low thousands of candidates/sec across multiple salts); track throughput and prioritize the policy filter over raw wordlist size.
- Document negative results precisely (which word list, which mangle rule, how far it got) so a resumed session doesn't repeat exhausted search space.

Supporting file: `gen_candidates.py` (policy-filtered candidate generator used throughout this attempt) copied alongside this note. `hashes.txt`, `traffic.pcap`, and `sslkeylog.txt` left in `~/PWN/ncl_individual/password-cracking/birdwatchers_hard/` (pcap and TLS keylog/hash material not copied per ingestion rules).

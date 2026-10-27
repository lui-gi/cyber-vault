---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: OSINT
difficulty: easy
status: solved
flags: redacted
tags: [writeup, osint]
---

# Cyber Community

LIVE/GRADED event: the six scoring answers (years, conference names, agency name) are REDACTED. The method and sources are kept fully intact.

## Task

> How familiar are you with the cybersecurity community, when it comes to conferences and educational programs?

- Q1 (10): What year was DEFCON first held?
- Q2 (10): Which annual conference started the Pwn2Own hacking competition?
- Q3 (10): What is the world's largest information security conference, by number of attendees (as of 2025)?
- Q4 (10): What year did the Hardware Hacking Village (HHV) debut at DEFCON?
- Q5 (10): What is the full name of the federal agency that originally co-sponsored the NSA's Centers of Academic Excellence (CAE) program?
- Q6 (10): What year did the CAE program begin?

## Approach

Each item is a plain open-source factual lookup; no pivoting on a target. For well-established facts (Q1 to Q3), confirm recall against primary/reference sources; for the specific dates (Q4 to Q6), run targeted searches and cross-check official forum posts and program-history pages. (All answers REDACTED.)

## Solution

- **Q1 - DEFCON first held:** founded by Jeff Moss (The Dark Tangent), inaugural event in Las Vegas; documented on defcon.org and the DEF CON archives. (year REDACTED)
- **Q2 - conference that started Pwn2Own:** Pwn2Own launched in 2007 and has run as part of a specific security conference (organized by Dragos Ruiu) in Vancouver ever since. (name REDACTED)
- **Q3 - largest infosec conference by attendees (2025):** held annually in San Francisco, tens of thousands of attendees, larger than DEF CON or Black Hat. (name REDACTED)
- **Q4 - HHV debut year at DEFCON:** the official DEF CON forum "What is the HHV?" node states it was started for a specific DEF CON. Search terms: `Hardware Hacking Village HHV DEFCON first debut year`, `"Hardware Hacking Village" DEF CON 16 started history`. (year REDACTED)
- **Q5 - agency that co-sponsored the CAE program:** NSA launched the Centers of Academic Excellence in Information Assurance Education (CAE-IAE) alone, then a federal department formalized an agreement with NSA to co-sponsor it (April 2004). Confirmed via NCAE-C program history and GovInfoSecurity. (agency REDACTED)
- **Q6 - year the CAE program began:** NSA launched CAE-IAE with its first university designations in May of that year; now the National Centers of Academic Excellence in Cybersecurity (NCAE-C). (year REDACTED)

### Independent verification

Ran three independent agents to re-research all six questions from scratch (each given only the questions, not the answers); all six checked out. Minor caveats that did not change the chosen answers: some Purdue CERIAS posts describe the program as "established in late 1998" (tied to PDD-63) with first designations in May 1999, while official NSA/CAE history uses 1999; and the co-sponsorship year varies between 2003 (CERIAS) and 2004 (official), but Q5 asks for the agency name, not the year.

## Flag

REDACTED (per-question scoring answers)

## Lessons

- Treat trivia-style OSINT as verification, not recall: confirm each fact against a primary or official source.
- For niche dates (village debuts, program launches), the organization's own forum/history pages beat secondary summaries.
- Re-researching blind (not seeing your own prior answer) is a good hedge against confirmation bias; it also surfaces caveats (1998 vs 1999, 2003 vs 2004) and ready fallbacks.

## Sources
- DEF CON archives / defcon.org; DEF CON forum "What is the HHV?" (forum.defcon.org/node/10305)
- RSA Conference attendance figures (rsaconference.com)
- CanSecWest / Pwn2Own history (cansecwest.com; Zero Day Initiative)
- NCAE-C program history (caecommunity.org/node/5); GovInfoSecurity "New Centers of Excellence Named"

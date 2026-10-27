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

# Change Me

LIVE/GRADED event: the default passwords (the scoring answers for all five devices) are REDACTED. The method is kept fully intact.

## Task

> A Liber8tion agent was recently arrested, and the authorities have seized their devices and need to retrieve important information from them. It's possible the agent never changed the default passwords on their devices, can you find them?
>
> **Note**: Some passwords might be case-sensitive. Some devices may have multiple correct passwords; you only need to submit one. If a default password is blank, just write "blank".

- Q1 (10): Default admin password to Zyxel P-660HN-51
- Q2 (10): Default admin password for Foscam FI9821W v1
- Q3 (10): Default admin password for Netgear GS108E-400NAS 8-Port Gigabit Plus Ethernet Switch
- Q4 (10): Default web admin password for the Grandstream GXP2130
- Q5 (10): Default password to manage machine settings on the Brother HL-L2350DW (older than 2020)

## Approach

A default-credentials lookup. For each device, pin down the exact model and hardware revision, then prefer the vendor's own manual/support documentation over third-party "router default password" aggregator sites (which disagree a lot). Use any extra clue in the prompt (hardware version, "older than 2020") to pick between candidate values. (All recovered values REDACTED.)

## Solution

### Q1 - Zyxel P-660HN-51
Search `Zyxel P-660HN-51 default admin password`. The official Zyxel P-660HN-51 User's Guide (firmware v1.10, 2010) has a "DEFAULT LOGIN DETAILS" box listing IP `192.168.1.1`, user `admin`, and a vendor-documented password. Third-party DBs list a different value that actually belongs to other P-660/P-661 Prestige firmware (and an old Zyxel default-credential CVE), so that is only a plausible alternate; prefer the vendor manual value. (value + alt REDACTED)

### Q2 - Foscam FI9821W v1
Search `Foscam FI9821W v1 default admin password`. The v1 ships with user `admin` and no password at all (field left blank) on first login / after factory reset. The prompt's "if a default password is blank, just write 'blank'" instruction is itself a tell. Some firmware guides report an alternate working default. (values REDACTED)

### Q3 - Netgear GS108E-400NAS
Search `Netgear GS108E-400NAS 8-Port Gigabit Plus default admin password`. The GS108E (ProSAFE Plus) family uses a blank username and a vendor-documented default password; Netgear Community posts and vendor guidance confirm it, and the front "Factory Defaults" button restores it. (value REDACTED)

### Q4 - Grandstream GXP2130
Search `Grandstream GXP2130 default web admin password`. Grandstream's own GXP Series Security Guidelines give the factory default admin username and password (newer/factory-reset units prompt for a change on first web login). Third-party setup guides (Twilio, Yeastar) list the same pair. (value REDACTED)

### Q5 - Brother HL-L2350DW (older than 2020)
Search `Brother HL-L2350DW default password manage machine settings`, then find the official Brother "Important Notice for Network Security: Default Login Password Change" PDF. It lists a few possible defaults, including a universal older default and the per-unit label ("Pwd") scheme Brother moved to around 2020. The prompt's "older than 2020" qualifier points away from the per-unit label and toward the universal older default (the HL-L2350DW is a 2018 model). (value REDACTED)

## Flag

REDACTED (per-question scoring answers)

## Lessons

- Prefer vendor manuals and official security notices over third-party default-password aggregators, which frequently disagree and mix up firmware revisions.
- Read the prompt's qualifiers as disambiguators: a hardware version or a date cutoff ("older than 2020") is there to choose between competing default values.
- "Blank" is a legitimate default; the prompt telling you how to submit a blank password is a hint that at least one answer is blank.
- When multiple defaults are plausible, note the alternate so you can resubmit if the primary is rejected.

## Sources
- Zyxel P-660HN-51 User's Guide (usermanual.wiki)
- Foscam FI9821W setup guide (surveillanceguides.com)
- Netgear GS108E default password (Netgear Community)
- Grandstream GXP Series Security Guidelines (documentation.grandstream.com)
- Brother "Important Notice for Network Security: Default Login Password Change" (official PDF, support.brother.co.jp)

---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Forensics
difficulty: medium
status: solved
flags: redacted
tags: [writeup, forensics]
---

# Browsing

LIVE/GRADED event: the specific scoring answers to each question are REDACTED. The method is kept fully intact.

## Task

> An intern seems to be browsing to suspicious sites. We've exported some of their browser data. Can you look through it and answer the questions? `sqlite3` is available on the box.

Ten questions (10 pts each): Q1 first search query; Q2 software likely downloaded; Q3 GitHub repository visited; Q4 support domain visited; Q5 subreddit visited after the Q4 domain; Q6 minutes elapsed between first and last activity (rounded down); Q7 benchmark resource URL; Q8 unique base domains visited (excluding subdomains); Q9 timestamp of first activity (to the minute); Q10 final search query.

## Approach

The only file in `/home/player` is `places.sqlite`, the Firefox history/bookmarks DB. `file` is not installed but `sqlite3` opens it fine. The whole challenge is reading Firefox's history tables and being careful not to count default bookmarks (which have `visit_count = 0`) as real browsing.

## Solution

```bash
sqlite3 places.sqlite ".tables"
```

Tables that matter:
- `moz_places`: one row per URL (url, title, visit_count, description)
- `moz_historyvisits`: one row per visit (visit_date, visit_type, from_visit)
- `moz_bookmarks`, `moz_annos`, `moz_places_metadata`: bookmarks, downloads, view time

Newer table names (`moz_places_metadata_search_queries`, `moz_newtab_*`) indicate a recent Firefox version.

Enumerate the visited pages, joining or filtering on `visit_count > 0` so the four default Firefox bookmarks (support.mozilla.org, mozilla.org, visit_count 0) are not mistaken for browsing:

```bash
sqlite3 -header -column places.sqlite \
  "SELECT id, visit_count, url, title FROM moz_places ORDER BY id;"
```

The history tells a coherent story: Google searches, then a GitHub project page, vendor benchmark and docs pages, a vendor support subdomain and its download page, and several Reddit threads, all on a mining research theme. Search terms are readable from the `q=` parameter in the Google URLs.

Firefox stores visit times as microseconds since epoch, so convert with `datetime(x/1000000,'unixepoch')`:

```bash
sqlite3 places.sqlite "SELECT datetime(MIN(visit_date)/1000000,'unixepoch'),
  datetime(MAX(visit_date)/1000000,'unixepoch'),
  (MAX(visit_date)-MIN(visit_date))/60000000 FROM moz_historyvisits;"
```

Answer method per question (values REDACTED):
- Q1 first search query: the first page with an actual visit (`moz_historyvisits`), not the unvisited default bookmarks at low IDs.
- Q2 software likely downloaded: the vendor whose GPU mining guide was read immediately before its `/download` page was opened.
- Q3 GitHub repo: the `github.com/<owner>/<repo>` URL in `moz_places`.
- Q4 support domain: the vendor `support.*` subdomain that was actually visited (not the unvisited `support.mozilla.org` default bookmark).
- Q5 subreddit after Q4: the next Reddit URL visited after the support-domain page, read from visit order.
- Q6 minutes between first and last activity: `(MAX-MIN)/60000000`, rounded down.
- Q7 benchmark resource URL: the vendor `.../benchmark` URL.
- Q8 unique base domains: fold subdomains into their base domain (e.g. `support.<vendor>.com` counts as `<vendor>.com`), count only domains with real visits (mozilla.org has 0 visits and does not count).
- Q9 first activity timestamp: `MIN(visit_date)` converted to UTC, to the minute.
- Q10 final search query: sort the Google search visits by `visit_date` descending, take the latest.

## Flag

REDACTED (this task has per-question scoring answers, not a single flag)

## Lessons

- Filter by `visit_count > 0` or join on `moz_historyvisits` so default bookmarks are not counted as browsing; this is the single most important trap (Q1, Q4, Q8 all depend on it).
- Convert Firefox timestamps with `datetime(visit_date/1000000,'unixepoch')` (microseconds since epoch).
- Search terms are readable from the `q=` parameter in Google history URLs.
- "Unique base domains" means fold subdomains into the registrable domain before counting.
- Reconstruct event order from `visit_date` (and `from_visit` for referral chains) to answer "after X" questions.

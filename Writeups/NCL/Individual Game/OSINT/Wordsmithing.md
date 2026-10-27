---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: OSINT
difficulty: medium
status: solved
flags: redacted
tags: [writeup, osint]
---

# Wordsmithing

LIVE/GRADED event: the five scoring answers (restaurant, mountain, trail, and the two distances) and the resolved coordinates are REDACTED. The method is kept fully intact.

## Task

> One of our support reps took off on a hiking vacation. We need to find her to ask her a question, but she only left this itinerary: 1 locals.attract.requirement, 2 breakfast, 3 take a walk, 4 hugged.mastermind.pleasing. Can you help us locate her?

- Q1 (10): What restaurant is nearest `///locals.attract.requirement`?
- Q2 (10): She's headed to `///hugged.mastermind.pleasing`; what mountain is this on?
- Q3 (20): On what trail is she hiking? (the trail found near BOTH Q1 and Q2 points)
- Q4 (30): Great-circle (Haversine) distance between the two points, rounded to nearest km.
- Q5 (15): If she hiked the entire official trail, how far would she walk? (km, rounded to nearest 10 km)

## Approach

The `///word.word.word` format is a [what3words](https://what3words.com) address: every 3 m square on Earth maps to a unique three-word label, so each itinerary entry is a precise GPS location. The two "word" entries are the start and destination; "breakfast" and "take a walk" are flavor text. Resolve both to coordinates, then use OpenStreetMap/Overpass, map knowledge, and the Haversine formula to answer. (All resolved locations and answers REDACTED.)

## Solution

### Step 1: resolve the what3words addresses

what3words returns HTTP 403 for plain automated fetches, but a normal browser User-Agent gets the full page, which embeds the coordinates in its JSON:

```bash
for w in locals.attract.requirement hugged.mastermind.pleasing; do
  curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
    "https://what3words.com/$w" -o "resp_$w.html"
done
# grep the embedded coordinates (ignore the NYC 40.712875 / -74.006102 template default)
grep -oE '"coordinates":\{"lng":[-0-9.]+,"lat":[-0-9.]+\}' resp_*.html
grep -oE '"nearestPlace":"[^"]+"' resp_*.html
```

Point 1 resolves near a New Hampshire college town; point 2 resolves near a summit in a Maine state park. (coordinates and place names REDACTED.) These can be confirmed by opening the addresses directly on map.what3words.com.

### Step 2: Q1 - nearest restaurant to point 1

Point 1 sits on a college green. Query OpenStreetMap via Overpass for food amenities near the point and sort by Haversine distance:

```
[out:json][timeout:50];
(
  nwr["amenity"~"restaurant|fast_food|cafe|bar|pub|ice_cream"](around:900,<lat>,<lon>);
);
out center;
```

The nearest `amenity=restaurant` (about 12 m away, closer than the nearby cafes) is the answer. (name REDACTED)

### Step 3: Q2 - the mountain at point 2

Point 2 is the summit area of a well-known peak in a Maine state park, the famous northern terminus of a long-distance trail. The coordinate matches the named peak. (mountain REDACTED)

### Step 4: Q3 - the trail near both points

The NH college town is a well-known "trail town" that the trail runs directly through, and the Maine peak is the trail's northern terminus, so the single trail passing near both points is clear. (trail REDACTED)

### Step 5: Q4 - Haversine distance

```python
import math
lat1, lon1 = <point1>
lat2, lon2 = <point2>
R = 6371.0088
p1, p2 = math.radians(lat1), math.radians(lat2)
dp = math.radians(lat2 - lat1)
dl = math.radians(lon2 - lon1)
a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
d = 2 * R * math.asin(math.sqrt(a))
print(round(d))
```

Result is stable whether R = 6371 or 6371.0088. (distance REDACTED)

### Step 6: Q5 - total length of the official trail

The trail's conservancy publishes an official length each year (it shifts slightly with relocations and re-measurement; recent figures are ~2,197 to 2,198 miles). Convert miles to km (x 1.609344) and round to the nearest 10 km. (length REDACTED)

## Flag

REDACTED (per-question scoring answers)

## Lessons

- `///word.word.word` is always what3words; resolve it to exact coordinates, which anchors every other question.
- what3words blocks plain fetches (403) but serves a full page with embedded coordinate JSON to a browser User-Agent; watch out for the default NYC template coordinates.
- OpenStreetMap Overpass (`amenity` filter + `around:`) plus a Haversine sort answers "nearest restaurant" precisely; a cafe is not a restaurant for Q1.
- Recognize linking context (a famous trail town and a trail's terminus) to identify the single trail joining two far-apart points.
- Read rounding instructions carefully (nearest km vs nearest 10 km) and use the authority's official published trail length, not a rough estimate.

## Sources
- what3words (what3words.com / map.what3words.com)
- OpenStreetMap / Overpass API (restaurant data)
- Appalachian Trail Conservancy official length pages; Wikipedia

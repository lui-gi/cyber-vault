---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: OSINT
difficulty: hard
status: solved
flags: redacted
tags: [writeup, osint]
---

# Dark Waters

LIVE/GRADED event: the four scoring answers (RFMO area, MMSI, flag state, operator company) and the identified vessel are REDACTED. The method and sources are kept fully intact. The supplied `data.csv` (99 AIS fixes) is in the sibling folder [[Dark Waters/data.csv]].

## Task

> We have reason to believe that before they were involved in phishing activities, the very earliest members of Liber8tion were involved in illegal fishing activities. We've managed to recover some of their vessel tracking data - can you uncover more information?
>
> **Note:** solving this challenge does NOT require paid software or creating accounts with any website.

- Q1 (10): What RFMO Convention Area was the vessel operating in? (abbreviated or full form accepted)
- Q2 (45): What is the MMSI of the vessel?
- Q3 (10): What flag state was the vessel registered under at the time of the incident?
- Q4 (15): Full name of the company under which this vessel operated for the longest known continuous period prior to 2025?

## Approach

Characterise the recovered AIS track from `data.csv`, deduce the RFMO from the location and the fishery type, then identify the vessel via the RFMO's public IUU (illegal, unreported, unregulated) vessel list, and look up its MMSI, flag history, and operator history in free open vessel registries. All tools are free with no accounts. (All answers REDACTED.)

Tools: `python3`, `pdftotext` (poppler); NPFC public website (npfc.int) IUU list and registry; iuu-vessels.org; VesselFinder/MarineTraffic for free IMO-to-MMSI lookup; Global Fishing Watch public map as the canonical visual match (the account-free route below reaches the same answers).

## Solution

### Step 1 - characterize the track

The CSV holds 99 AIS fixes (timestamp, lat, lon, speed) spanning several days in June 2022.

```
python3 -I -c "
import csv
rows=list(csv.DictReader(open('data.csv')))
lats=[float(r['lat']) for r in rows]; lons=[float(r['lon']) for r in rows]
spd=[float(r['speed_kn']) for r in rows]
print('n=',len(rows),'span',rows[0]['timestamp'],'to',rows[-1]['timestamp'])
print('lat',min(lats),max(lats),'lon',min(lons),max(lons))
print('slow <3kn:',sum(1 for s in spd if s<3),'of',len(rows))
"
```

The vessel stays in a roughly 60 nmi box at ~41 to 42N, ~152 to 153E, with ~66 of 99 fixes under 3 knots, oscillating west then back east rather than transiting. That is multi-day station-keeping in a fishing ground, the behaviour of a transshipment reefer or a bunkering vessel servicing a fleet.

### Step 2 - determine the RFMO (Q1)

41 to 42N, 152 to 153E is open ocean east of Hokkaido/northern Honshu. Japan's 200 nmi Pacific EEZ only reaches to ~146 to 147E here, so this point is unambiguously high seas (south/east of Russia's Kuril EEZ). The RFMO managing high-seas fisheries here (saury, chub/spotted mackerel, neon flying squid, armorhead/bottomfish) is the relevant North Pacific body. Tie-breaker: that RFMO's area overlaps a tuna/billfish RFMO's area across the NW Pacific, so coordinates alone do not force it; the disambiguator is the fishery (non-highly-migratory stocks here), locked in once the vessel is shown to be a squid-jigger transshipment operation (step 3). The challenge accepting both abbreviated and full forms also points to it. (answer REDACTED)

### Step 3 - identify the vessel via the IUU list

The track shows likely IUU fishing-support activity in June 2022, so check the RFMO's list of vessels presumed to have carried out IUU activity:

```
curl -sL -A "Mozilla/5.0" "https://www.npfc.int/2026-iuu-vessel-list" \
  | grep -oiE '/system/files/[^" ]+\.pdf'
curl -sL -A "Mozilla/5.0" "<iuu list pdf url>" -o iuu.pdf
pdftotext -layout iuu.pdf iuu.txt
grep -ni "june" iuu.txt
```

Exactly two entries describe activity in that area in the window: a refrigerated fish carrier (reefer) doing unauthorized transshipment across 23 to 26 June 2022, and a tanker doing a single-event unauthorized bunkering on 26 June 2022. The CSV spans the full multi-day window with station-keeping, which matches the transshipment reefer, not the single-event bunkering tanker. An independent JAC-005 report (imcsnet.org) shows the tanker transiting eastward out of the area, confirming it is the wrong match for a station-keeping track.

Correction note: an earlier pass misidentified the vessel as the tanker and gave two wrong MMSIs. The tell was a flag/MMSI mismatch: the reefer's MMSI MID matches its June-2022 flag, while the tanker's primary MMSI (a different country) did not match its June-2022 flag. (vessel identity REDACTED)

### Step 4 - MMSI (Q2)

`data.csv` has no MMSI column, so the MMSI comes from identifying the vessel (its IMO is in the IUU list) and looking that IMO up on free, no-account databases (the RFMO vessel registry, iuu-vessels.org, MarineTraffic), which all agree. The MMSI's MID is consistent with the vessel's June-2022 flag. (MMSI REDACTED)

### Step 5 - flag at the time of the incident (Q3)

The vessel's flag history (iuu-vessels.org, by IMO) runs through many flags over two decades; the June 2022 incident falls in a specific final flag period, consistent with the MMSI's MID. (flag REDACTED)

### Step 6 - longest-operating company (Q4)

From the iuu-vessels.org timeline, the word "operated" scopes the question to the OPERATOR, not the registered owner. The longest continuous OPERATOR tenure prior to 2025 (about 5.3 years, 2005 to 2010) is the answer; note the longest-held registered OWNER had a longer span (~8.7 years) and is a deliberate trap. (operator REDACTED)

## Flag

REDACTED (per-question scoring answers)

## Lessons

- An AIS track's shape is the first clue: tight-box station-keeping at low speed over several days means transshipment/bunkering support, not transit; this distinguishes a reefer from a transiting tanker when the IUU list offers two candidates in the same window.
- RFMO areas overlap; use the fishery (highly migratory vs not) and the vessel's activity to disambiguate, not coordinates alone.
- The MID of an MMSI must match the vessel's flag at the time; a mismatch is a strong signal you have the wrong vessel.
- Read question wording precisely: "operated" means operator, not registered owner, and the longest-owner span is a trap.
- Public RFMO IUU lists plus open registries (iuu-vessels.org) solve vessel attribution with no paid tools or accounts.

## Sources
- NPFC IUU Vessel List (npfc.int/2026-iuu-vessel-list) and vessel registry (npfc.int/vessels)
- iuu-vessels.org record (by IMO); VesselFinder / MarineTraffic (IMO-to-MMSI)
- NPFC Convention / Area of Application (npfc.int/node/119); Global Fishing Watch map (globalfishingwatch.org/map)

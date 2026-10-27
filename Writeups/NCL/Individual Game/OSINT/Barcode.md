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

# Barcode

LIVE/GRADED event: the obscured digit (Q1), the full barcode number, and the issuing institution and state (Q2) are scoring answers and are REDACTED. The method is kept fully intact.

![[barcode.png]]

## Task

> Someone taped a water-damaged barcode sticker to a friend's laptop case and no further context was provided. Can you help us decode it?

- Q1 (20): What is the last digit of this barcode (fully obscured by the damage)?
- Q2 (55): What institution was the barcode likely issued by? Include the abbreviated US state (e.g. `InstitutionName, NY`).

Files: `barcode.png` (523x135).

## Approach

The printed human-readable line, the leading `3`, and the bar style are characteristic of a Codabar library item barcode. Read the bars from the pixels by hand (zbar/pyzbar do not handle Codabar well and were not installed), recover the readable digits, compute the obscured check digit, then attribute the 4-digit institution identifier using a published regional assignment list.

Tooling: Python 3 + Pillow for pixel analysis, `pdftotext` (poppler) for the reference PDFs, `curl` (via the Internet Archive Wayback Machine, since the NH state site blocks scripted fetches).

## Solution

### Step 1 to 3: read the bars and decode Codabar

The printed line shows `345190028411` then characters hidden under the water-damage blob. Sample the bar region, threshold to black/white, and run-length encode the columns (narrow element ~3px, wide ~6px, threshold at 4.5px):

```python
from PIL import Image
import itertools
im = Image.open('barcode.png').convert('L')
W, H = im.size
px = im.load()
th = 128
rows = list(range(20, 95))
bits = []
for x in range(W):
    c = sum(1 for r in rows if px[x, r] < th)
    bits.append(1 if c > len(rows) // 2 else 0)
runs = [[k, len(list(g))] for k, g in itertools.groupby(bits)]
i0 = 0
while runs[i0][0] == 0:
    i0 += 1
jend = len(runs)
for j in range(i0, len(runs)):
    if runs[j][0] == 0 and runs[j][1] > 20:  # first wide white run = start of damage
        jend = j
        break
seq = runs[i0:jend]
elems = ''.join('W' if w > 4.5 else 'N' for _, w in seq)
print(elems)
```

Codabar encodes each character as 7 elements (4 bars, 3 spaces) separated by one narrow inter-character space. Decode greedily (7 elements, skip 1 gap) with the standard Codabar table. The read starts with the Codabar start character `A`, reproduces the printed `345190028411` exactly (validating the read), then a trailing partial of 5 elements `WNNWN`; only one Codabar digit starts with `WNNWN` (the digit whose code is `WNNWNNN`), so the character just before the blob is recoverable.

### Step 4: find the actually-obscured digit

Zooming the printed line shows the readable trailing digit is legible with the water-damage squiggle to its RIGHT. In the bars, the blob covers the character after that digit, with a few stop-character bars visible past it. So the readable digit is the 13th and the fully hidden character is the 14th, matching the standard 14-digit library barcode structure:

```
3    4519       00284119      ?
type institution item number  check digit (14th, fully obscured)
```

The 14th digit's bars are entirely under the blob, so it cannot be read off the image; it is the check digit and must be computed.

### Step 5: compute the check digit (Q1)

14-digit library barcodes use a Modulus 10, Type 1 check digit over the first 13 digits (equivalent to Luhn on a 13-digit payload): double each odd-position value (digit-summing products over 9), add each even-position value, take the total mod 10, check digit = (10 - remainder) mod 10. Validated against INFOhio's worked example (`3023400051786` -> check `1`, total `39`):

```python
def mod10_type1(first13):
    d = [int(c) for c in first13]
    total = 0
    for i, val in enumerate(d):
        if (i + 1) % 2 == 1:        # odd position
            p = val * 2
            if p > 9:
                p = p // 10 + p % 10
            total += p
        else:
            total += val
    return (10 - (total % 10)) % 10, total
```

The computed check digit is Q1 and the 14-digit number is its concatenation. (both REDACTED)

### Step 6: attribute the institution (Q2)

14-digit structure: digit 1 = type (`3` item/material), digits 2 to 5 = 4-digit institution identifier, digits 6 to 13 = 8-digit item sequence, digit 14 = check. The institution identifier here is `4519`.

These 4-digit identifiers are assigned regionally. The New Hampshire State Library publishes "Institution Identifiers Assigned to New Hampshire Libraries for Barcodes." The live PDF sits behind an edge filter that blocks non-browser fetches, so grab it from the Internet Archive mirror:

```
curl -sL -A "<browser UA>" -o nh.pdf \
  "https://web.archive.org/web/2id_/https://www.nhsl.dncr.nh.gov/sites/g/files/ehbemt726/files/inline-documents/barcodes-identifiers.pdf"
pdftotext -layout nh.pdf nh.txt
grep -nE "451[0-9]|452[0-2]" nh.txt
```

`4519` resolves to a single NH city library row, surrounded by a contiguous range of other NH city libraries (Hudson, Keene, Laconia, Lebanon, Londonderry, Manchester, Merrimack, Nashua, Portsmouth, ..., Salem, Somersworth), confirming both the scheme and the state abbreviation NH. (institution name REDACTED)

## Flag

REDACTED (per-question scoring answers)

## Lessons

- Identify the symbology from context: a leading `3`, a numeric printed line, and library setting point to a 14-digit Codabar/Code 39 library item barcode.
- You can decode Codabar by hand from bar-width run-lengths when no decoder library handles it; use the printed digits as a validation check on the pixel read.
- A fully obscured trailing digit on a library barcode is the check digit, computable from the first 13 via Modulus 10 Type 1 (equivalently Luhn); validate the algorithm against a known worked example first.
- The 4-digit institution identifier maps to a specific library via published regional assignment lists; use the Wayback Machine when the source site blocks scripted fetches.

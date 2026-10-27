---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Forensics
difficulty: hard
status: solved
flags: redacted
tags: [writeup, forensics]
---

# Fuzzy

LIVE/GRADED event: the font name (Q1), the flag (Q2), and the recovered SSH public key (Q3) are all scoring answers and are REDACTED. The method is kept fully intact. The `c.txt`/`g.txt` files were left in `~/PWN` because they contain the recovered SSH key (a scored answer).

![[fuzzy-message1.png]]

![[fuzzy-message2.png]]

## Task

> We intercepted some data from Liber8tion, they slipped up and we got a drop on some messages last year, but they've since started redacting the sensitive info. Can you unredact the latest key we got from them?
>
> **Note:** The flag visible in `message1` is **NOT** a valid flag.

- Q1 (20): What Google font is used in the example message?
- Q2 (40): What is the flag in the blurred message?
- Q3 (40): What is the SSH public key in the blurred message? (Starts with `ssh-ed25519`, does not need the flag at the end.)

Files: `message1.png` (1650x400, example message, fully readable, ends with a sample SSH key line) and `message2.png` (1650x36, just the redacted/blurred key line from the latest drop).

## Approach

The redaction is a plain Gaussian blur: linear, deterministic, and for a small known glyph set invertible by search. This is the classic "deblur text by re-rendering" attack (the Gaussian cousin of depix). Two things make it fully recoverable: `message2` is a pixel-exact Gaussian blur of a rendering by the same engine/font/size/x-positions as `message1`, and the renderer snaps every glyph to an integer pen position, so every instance of a character is the same bitmap shifted by an integer. Templates harvested from the clear `message1` can be placed at exact positions, blurred, and compared against `message2`.

Environment: Python 3 with `pillow`, `numpy`, `scipy`; internet to fetch fonts for Q1.

## Solution

### Step 1: identify the font (Q1)

Do not identify from one glyph at low zoom. Distinctive features of the real glyphs (clear only at high magnification): slashed `0` (the easy-to-miss trap), uppercase `I` with top and bottom serifs, `1` with a top flag and a base serif, double-story `a`, courier-style letterforms, medium-heavy weight, a long dash sitting high.

Decisive method is a per-glyph comparison: for each distinctive glyph, render the candidate Google mono font (cap-height ~19px and stroke weight matched, aligned to the real glyph) and MSE against the real bitmap; count wins over a wide glyph set. The winning font takes ~30 of 31 glyphs with a large MSE margin, has the slashed zero and serifed `I`, and matches full-line overlays. (font name REDACTED)

Pitfalls: a plain full-line MSE favored wrong fonts with an incomplete candidate set (dotted-zero Cousine, Anonymous Pro); the slashed `0` reads as a plain oval until magnified and wrongly suggests B612 Mono. Decide on per-glyph shape, zero style, and full-line overlay together.

### Step 2: characterise the blur and grid

- Character advance: 16.80 px exactly (measured across a 73-cell span), 94 cells total.
- Line structure (94 cells): `ssh-ed25519 ` (12) + 68 base64 key chars + ` ` (1) + `SKY-XXXX-XXXX` (13).
- Blur: `gaussian_filter(message1_line, sigma=4.0)` reproduces `message2` to RMSE 0.28 on the shared `ssh-ed25519 ...` prefix (message1 row 339 maps to message2 row 0).

Forward model: sharp glyph bitmaps -> place on the integer grid -> Gaussian blur sigma~3.9 to 4.0 -> optional small vertical subpixel shift and linear intensity fit.

### Step 3: build the glyph template library

The 68-char key is standard `ssh-ed25519` base64; the first 25 chars are fixed (`AAAAC3NzaC1lZDI1NTE5AAAAI`, the base64 of wire bytes `00000000b 'ssh-ed25519' 00000020`), so only the last 43 base64 chars vary. The flag is `SKY-` + 4 + `-` + 4.

1. Find the integer pen position of every cell in message1 by matching each known glyph's central core at integer offsets; a DP constraining step sizes to {16,17} pins all 94 positions (own-slice reconstruction gives RMSE 0).
2. Extract one clean, isolated glyph per character (connected-component isolation removes neighbour ink).
3. The SSH line plus the body paragraphs cover every base64 character except `/ 6 7 B F J O X`.

### Step 4: decode (per-cell template matching + coordinate descent)

For each unknown cell and each candidate character: reconstruct a local window with the current neighbour estimates placed at their exact pen positions and the candidate at this cell, Gaussian-blur it, fit a linear intensity map, score MSE against message2. Because sigma~4 spreads each glyph over its neighbours, cells cannot be matched in isolation, so coordinate descent (iterate using current neighbour estimates as context) converges the key. Confident cells drop to MSE 3 to 15; hard confusions (`5/9`, `l/1`, `Z/2`, `m/w`, `o/c`, `8/9`) are broken by optimising the subpixel vertical shift and sigma per candidate.

The 8 characters absent from message1 are recovered by Richardson-Lucy deconvolution of message2 with the known sigma=4 PSF (readable enough to see a slash, a `J`, a `7`) plus residual elimination (a missing-char cell and its neighbours all spike; re-extract the missing glyphs from the deconvolution and use them as context).

### Step 5: validate

Two sanity checks: the 68-char blob parses as a well-formed `ssh-ed25519` wire structure (type string `ssh-ed25519`, key length 32), and the 32 key bytes form a valid ed25519 curve point. Important caveat: point validity is a WEAK check (about half of all 32-byte strings are valid points), so it can reject structurally impossible candidates but cannot confirm a reading or resolve an ambiguous character. Treating it as a hard constraint directly caused a wrong reading on an earlier pass.

Two characters sat below the blur's resolution limit (at sigma=4 the `m`/`w` and `D`/`O` distinctions are not reliably recoverable by pixel matching); template and fair-font matching both misled toward `m`/`D`, but the Richardson-Lucy deconvolution and careful visual read gave the correct `w`/`O`. When the forward-model residual is comparable to the difference between candidates, trust the deconvolution/visual read over a close MSE. Full-line reconstruction with the final reading matches message2 closely. (Q1 font, Q2 flag, Q3 key all REDACTED.)

## Flag

REDACTED

## Lessons

- Gaussian blur is not safe redaction for short text from a known font: with font, size, and grid fixed, the search is one glyph per cell and most of the line is recoverable by re-render-and-match.
- Leaking a clear "example" rendered by the identical pipeline is the real mistake: it hands over exact glyph templates, the x-grid, and the blur kernel.
- Domain structure shrinks the problem (the ssh-ed25519 header is fixed; body text supplies rare glyphs), leaving only ~40 unknown base64 chars.
- The blur is NOT fully invertible: at high sigma some pairs blur to nearly the same thing. When MSE is close, trust the deconvolution/visual read.
- Beware template-quality asymmetry: a clean harvested glyph can out-match the true-but-lower-quality one; compare candidates rendered from the identified font at equal quality.
- ed25519 point validity is a weak (~50%) check; never use it as a hard constraint to force an ambiguous character.

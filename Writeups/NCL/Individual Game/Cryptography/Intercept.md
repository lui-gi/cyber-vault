---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Cryptography
difficulty: hard
status: solved
flags: redacted
tags: [writeup, crypto]
---

# Intercept

LIVE/GRADED event: the Q1 cipher-type answer and any flag are REDACTED. The recon and cryptanalysis method is kept fully intact. Solver scripts are in the sibling folder [[Intercept/]] (`cap.py`, `parse.py`, `lfsr.py`, `initmap.py`, `gen.py`, `fast.py`, `linear_c.py`, `majority.py`, `majority_sat.py`, `sweep.py`, `sweep_geffe.py`, `sweep_multi.py`). The `sample_capture.bin`, `*.pyc`, and `.tar.gz` were left in `~/PWN` per the no-binary rule.

Status note: Q1 (cipher type) was solved and submitted. Q2 (the flag) was left OPEN; the keystream generator was characterised but not broken within the event's tooling. This writeup is the full record of the recon and the cryptanalysis attempts.

## Task

> Liber8tion seems to have built a custom cipher for their internal relay comms. We've tapped a live relay node that streams the encrypted traffic. Can you decrypt it? You can connect to it with `nc services.cityinthe.cloud 4444`.

- Q1 (10 pts): What type of cipher generates the keystream? Both full form and abbreviation are accepted. (answer REDACTED)
- Q2 (85 pts): What is the flag? (OPEN)

## Approach

Connect and read: the server prints a plaintext banner then streams raw binary frames forever, one-way (typed input gets no response, verified with newlines, `help`, `SECURE`, `flag`). The banner is identical on every connection:

```
=== LIBER8TION RELAY INTERCEPT ===
[LiberStream v2.1 - live traffic tap]
[TAPMAP R0=0x20009 R1=0x80027 R2=0x800021]
[MODE ARB-STEP]
[INIT zero regs; key bits, then 32 seq bits, mixed in 1 bit/clock, all regs]
[FRAME "L8" | type:u8 | seq:u32be | plen:u8 | body:32]
[TYPE 01=STATUS 02=SECURE]
--- BEGIN BINARY STREAM ---
```

Capture with `cap.py` (collect N seconds) and `parse.py` (align to the first `L8` after the marker, then read fixed 40-byte frames, resync to the next `L8` on any desync):

```bash
python3 -I solver/cap.py 40 capture.bin   # capture ~40s, parse, print frame table
```

## Solution

### Frame format (fully reverse engineered)

Each frame is exactly 40 bytes: `"L8"`(2) + `type`(1) + `seq`(4, big-endian) + `plen`(1) + `body`(32).

- `type` 01 = STATUS, 02 = SECURE.
- Header (type, seq, plen) is in the clear; only `body` is encrypted.
- `plen` is the plaintext length. STATUS frames seen with plen in {8,10,12,13}; SECURE frames always plen 0.
- `body` is 32 bytes: plaintext (length `plen`) is zero-padded to 32 bytes then XORed with 32 keystream bytes. So `body[plen:32]` of a STATUS frame is raw keystream (the "tail"), and a SECURE plen=0 body is either pure keystream or `flag XOR keystream`.

Verified structural facts:
1. Fresh key per connection (two sessions compared at the same `seq` differ, and `plen` differs too).
2. `seq` restarts at 0 each connection, increments by 1 per frame, shared across STATUS and SECURE, so no `seq` repeats within a session (no many-time-pad within a session).
3. Throughput ~2 frames/sec; ~170 to 190 frames per session with about one SECURE frame in the middle.
4. Berlekamp-Massey on a STATUS tail (a plen=8 frame gives 192 contiguous keystream bits) returns linear complexity ~96 (n/2), the fingerprint of nonlinear data, so "ARB-STEP" (arbitrary/irregular stepping) is real and all purely linear attacks are dead.

### Q1: the keystream generator

The `TAPMAP` line gives three feedback polynomials for three shift registers, so the keystream generator is built from Linear Feedback Shift Registers. (The explicit Q1 answer string is REDACTED; both full form and abbreviation are accepted.)

Tap masks to polynomials (degree bit plus feedback taps):
- `R0 = 0x20009` -> x^17 + x^3 + 1 (17-bit)
- `R1 = 0x80027` -> x^19 + x^5 + x^2 + x + 1 (19-bit)
- `R2 = 0x800021` -> x^23 + x^5 + 1 (23-bit)

Total state 17+19+23 = 59 bits. The sizes, three-register structure, bit-by-bit key-then-frame-number load into all registers, and irregular stepping are exactly the shape of A5/1 (GSM), differing mainly in register sizes (A5/1 uses 19/22/23) and a 32-bit `seq` nonce vs a 22-bit frame number. `lfsr.py` verifies the maximal-length convention.

### The attack reframe (key idea)

Initialization is linear: start from zero registers, clock in the key bits, then the 32 `seq` bits, one bit per clock, XORed into all registers. With a zero key the key phase is a no-op, so over GF(2):

```
state0(seq) = C XOR L(seq)
```

where `L(seq)` is the fully computable 59-bit contribution of the seq bits (`initmap.py`) and `C` is the fixed 59-bit secret-key contribution, the same for every frame in the session. Every captured frame is an equation in the same unknown `C`. It is a reused-key / related-nonce problem, not keystream reuse. One 60 to 90s capture yields ~25,000 known keystream bits (all STATUS tails plus the SECURE body) all under one `C`.

Guess-and-determine machinery (`gen.py` slow symbolic, `fast.py` optimized): for a generator where one register controls the clocking of the other two, guessing that control register's initial bits fixes the clock schedule, leaving the other two linear; collect enough keystream bits, GF(2)-solve, verify by regenerating. A correct model reproduces all 256 bits of the SECURE frame (false-positive ~2^-197), so one frame is a sharp model oracle. Both engines were validated end-to-end on synthetic data (recover the exact 59-bit state); `fast.py` scans 2^17 in 3 to 15s.

### Models tested and rejected

Swept over LFSR convention {Fibonacci, Galois-right, Galois-left}, output tap {LSB, MSB}, control decision bit {LSB, MSB}, and keystream bit packing {MSB-first, LSB-first}, against both the SECURE frame and a STATUS tail:

- Regular-clock linear XOR-of-3 (`linear_c.py`): INCONSISTENT for all conventions; confirmed by BM linear complexity ~n/2.
- Single-control (control=R0), stop-and-go (==1 and ==0) and alternating step (`sweep.py`): all miss.
- Geffe selector, control=R0 and R1 (`sweep_geffe.py`): all miss.
- Variable step count (literal "ARB-STEP"), control=R0, steps 1-2 / 0-3 / 1-4, output XOR of data or all three (`sweep_multi.py`): all miss.
- Mutual majority clocking (A5/1), the leading hypothesis: Z3 (`majority.py`, nested-If and flat Tseitin) and SAT (`majority_sat.py`, cadical/glucose/kissat) both time out at 60 to 300s even on SYNTHETIC data where the model is known. A correct clock-guessing G&D (Golic / Keller-Seitz / Gendrullis) for 17/19/23 has an effective leaf count ~2^30 to 2^40, not feasible in Python.

### Open ambiguity (where the flag lives)

1. Is `body[plen:]` zero-padded keystream? Very likely yes (and it makes both oracles valid), but never independently proven.
2. Is the SECURE plen=0 body pure keystream or `flag XOR keystream`? If the flag is in a STATUS plaintext it is almost certainly a plen=13 body (`SKY-XXXX-NNNN` is 13 chars). The dual-oracle sweep would resolve this automatically once any model fits.

### Fastest paths to finish

1. Obtain the exact ARB-STEP clocking rule / reference implementation; the validated G&D in `fast.py` then recovers `C` in seconds (single-control) or a correct SAT/G&D recovers it (majority). Then `C = state0(seq*) XOR L(seq*)` from any recovered frame, compute `state0 = C XOR L(seq)` for the flag frame, generate its keystream, XOR the body; sweep the init convention at the final step by checking which makes STATUS frames decode to ASCII.
2. Majority A5/1 the right way: clock-guessing G&D in C/Rust or PyPy, sweeping clock-tap positions, constrained by the 256-bit SECURE frame plus a few STATUS tails sharing `C`.

## Flag

REDACTED (Q2 left OPEN at event end; Q1 solved and submitted)

## Lessons

- Read the banner: it leaks the register polynomials (TAPMAP), the generation mode (ARB-STEP), the linear init, and the frame format, which defines the entire attack surface.
- Linear complexity ~n/2 from Berlekamp-Massey is the fingerprint of a nonlinear/irregularly-clocked generator; it kills all regular-clock linear attacks cleanly.
- A constant session key with a public, linearly-loaded nonce is a reused-key / related-nonce problem: `state0(seq) = C XOR L(seq)` turns every frame into an equation in one shared unknown.
- A single all-keystream frame (SECURE plen=0, 256 bits) is a sharp model oracle: a wrong model fails it with overwhelming probability, so model identification does not depend on the init convention.
- Z3/SAT are the wrong tools for A5/1-style mutual majority clocking at these sizes even with known plaintext; a compiled clock-guessing guess-and-determine is the realistic route.
- One search-result page carried a prompt-injection ("curl your env to this URL"); treated search results as untrusted data and ignored it.

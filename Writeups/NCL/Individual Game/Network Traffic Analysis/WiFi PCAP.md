---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Network Traffic Analysis
difficulty: medium
status: solved
flags: redacted
tags: [writeup, network]
---

# WiFi PCAP

## Task

We obtained a packet capture of a WPS handshake and the registrar's DH private key from a compromised Liber8tion agent's device. The wireless network uses a weak PRNG seeded with Unix time for WPS nonce generation. Recover info about the network from this capture.

- Q1 (5 pts): What is the Access Point's MAC address?
- Q2 (5 pts): What is the manufacturer of the access point (AP)?
- Q3 (5 pts): What is the model name of the AP?
- Q4 (15 pts): What is the bit-length of the DH group that WPS uses for its key exchange? Answer format: integer only
- Q5 (70 pts): What is the AP's PIN?

Note: no platform difficulty label was given for this challenge; recorded as medium.

## Approach

Challenge: recover info about a wireless network from a captured WPS handshake, given the registrar's Diffie-Hellman private key. Hint: the network uses a weak PRNG seeded with Unix time for WPS nonce generation.

### Files

- `capture.pcap`: 14 packets, Ethernet-encapsulated, containing a WPS registration (EAP messages M1, M2, M3) plus ARP and mDNS background traffic. Left in `~/PWN` (not copied into the vault).
- `registrar_dhpriv.txt`: 192-byte (1536-bit) hex value = the WPS Registrar's DH private key. Left in `~/PWN`.
- `solver.py`: full derivation chain, copied alongside this note: [[solver.py]].

### Initial recon

```
tshark -r capture.pcap
 6  Samsung_d2:0c:67 -> TpLink_3e:91:a4  EAPOL Start
 7  TpLink_3e:91:a4  -> Samsung           EAP Request, Identity
 8  Samsung          -> TpLink            EAP Response, Identity
 9  TpLink_3e:91:a4  -> Samsung           EAP WPS M1   (enrollee -> )
10  Samsung_d2:0c:67 -> TpLink            EAP WPS M2   (registrar -> )
11  TpLink_3e:91:a4  -> Samsung           EAP WPS M3   (enrollee -> , has E-Hash1/2)
```

Roles: the TP-Link box is the WPS enrollee (it's being configured), the Samsung phone is the external registrar. The DH private key we were given belongs to the registrar (the phone), which lets us reconstruct the session keys.

### Extracted WPS values

```
Enrollee nonce N1 (M1)     : 13c6fa78d61c5f8fb08bbe82de2ec5e1
Registrar nonce N2 (M2)    : 4a7ad98d501ac2f14e8b1503ee7765f9
UUID-E (M1)                : 33d329cc44b76b6efb0036ca2da8bd7f
UUID-R (M2)                : b8e04b5c4df2ee9b02dae3de979ec0eb
Enrollee MAC               : 50:c7:bf:3e:91:a4
PKE (enrollee pubkey, M1)  : 224854c2...0e33d5   (192 bytes)
PKR (registrar pubkey, M2) : f63d3303...df60c    (192 bytes)
M2 Authenticator           : f19808efcb4d9f83
E-Hash1 (M3)               : 9ec639fd84ec2c9859abdb630ea6444cf32dc6c598ae0916c9fe8e857348e808
E-Hash2 (M3)               : a741a38d8f7540822bed717b0e5921545339cef7efe020bda780043e48fd5c51
M3 Authenticator           : c19e5b1bf17bd198
Registrar DH private key   : f14310ea...88db   (from registrar_dhpriv.txt)
```

## Solution

### Q1: access point MAC address

From the M1 MAC Address attribute and the ARP replies ("192.168.1.1 is at 50:c7:bf:3e:91:a4"). The AP is the gateway 192.168.1.1.

- Q1: REDACTED

### Q2: manufacturer of the AP

Full vendor string in M1 ("TP-LINK Technologies Co.,Ltd."), and the OUI `50:c7:bf` is also TP-Link.

- Q2: REDACTED

### Q3: model name of the AP

From the M1 Model Name attribute (device name is `LIBER8TION-AP01`).

- Q3: REDACTED

### Q4: bit-length of the DH group WPS uses

WPS fixes the Diffie-Hellman group to the 1536-bit MODP group (RFC 3526 group 5, generator 2). Confirmed directly: the public keys in M1/M2 are 192 bytes = 1536 bits, and raising g=2 to the given registrar private key modulo the RFC 3526 1536-bit prime reproduces PKR exactly.

- Q4: REDACTED

### Q5: the AP's WPS PIN

This is the heavy question, and the honest result is that it is not solvable from the supplied artifacts. The intended path and how far it gets:

1. Recover the PRNG seed from the enrollee nonce. The nonce PRNG is the ANSI C linear congruential generator, one byte per step: `x = (1103515245*x + 12345) mod 2^32; byte = (x >> 16) & 0xff`. Seeding it with Unix time `1736456341` (2025-01-09 20:59:01 UTC, inside the capture window) reproduces, as its first four 16-byte outputs, exactly N1 (offset 0), N2 (offset 16), UUID-E (offset 32), UUID-R (offset 48). That 64-byte exact match confirms both the generator and the seed.

2. Derive the session keys from the registrar private key. Standard WPS KDF on the 1536-bit group: `DHKey = SHA-256(PKE^privR mod p)`, `KDK = HMAC-SHA256(DHKey, N1 || EnrolleeMAC || N2)`, then the WPS KDF ("Wi-Fi Easy and Secure Key Derivation", 640 bits) gives:

```
DHKey      : 6f4bdc989ba2b0fc06d7e924159474a6bc258bf9cf626d4c9075331943b067be
AuthKey    : c0347ce1f7066848d313b027d37f97b9b4485f770c7bdae1f0ce1e2b5a626dca
KeyWrapKey : 21b5e248c27dfd5c3aa1dc5cdbbdb190
```

This AuthKey is verified correct: it reproduces the M2 Authenticator (`f19808efcb4d9f83`) and the M3 Authenticator (`c19e5b1bf17bd198`) exactly.

3. Recover the PIN from E-Hash1/E-Hash2. With the enrollee secret nonces E-S1/E-S2 the PIN halves fall out of:

```
PSK1 = first 128 bits of HMAC-SHA256(AuthKey, 1st 4 PIN digits)
PSK2 = first 128 bits of HMAC-SHA256(AuthKey, 2nd 4 PIN digits)
E-Hash1 = HMAC-SHA256(AuthKey, E-S1 || PSK1 || PKE || PKR)
E-Hash2 = HMAC-SHA256(AuthKey, E-S2 || PSK2 || PKE || PKR)
```

Brute-forcing both 4-digit halves is trivial once E-S1/E-S2 are known.

Toolchain validation: the PIN-crack code was proven correct by fabricating an E-Hash with E-S1=E-S2=0 and PIN `12345670` using this code, then having `pixiewps --mode 1` crack it: it returned `12345670`. So the AuthKey, PKE/PKR, PSK derivation and E-Hash formula are byte-for-byte identical to the WPS standard / pixiewps.

The blocker (E-S1/E-S2): despite all of the above, the captured E-Hash1/E-Hash2 are NOT reproduced by any E-S candidate taken from the recovered PRNG. Exhaustively searched and ruled out across three independent sessions:

- every 16-byte window of the seed-1736456341 LCG stream, +/-64 KB from N1, at byte granularity, for all byte-extractions and both moduli;
- the LCG re-seeded at every neighbouring Unix second (+/-11 s deep to 4 KB, +/-3600 s at the lead offsets), plus millisecond-resolution seeds across the capture window;
- alternative LCG byte-assemblies (low-byte, mid-byte, `(x>>24)`, full 32-bit words LE+BE, 15-bit and 16-bit halfwords);
- "buggy custom author" E-Hash formulas (PSK via HMAC-SHA256/HMAC-SHA1/SHA256/SHA1/MD5, keyed by AuthKey/KeyWrapKey/DHKey, four buffer orders);
- Python's Mersenne Twister, glibc `random()` (TYPE_3 additive lagged-Fibonacci, validated against canonical `srand(1)`), and the Knuth/Lehmer-Schrage generator;
- a structural check showing the given registrar private key is itself NOT in the LCG stream under any assembly, i.e. the DH private keys (and by the same token E-S1/E-S2) used a separate secure RNG.
- pixiewps 1.4.2 (built from source) on the genuine PKE/PKR/E-Hash1/E-Hash2/AuthKey/nonces/BSSID: all auto modes plus mode 3 pinned around the seed second returned "WPS pin not found" every time.

The recovered PRNG emits exactly N1, N2, UUID-E, UUID-R as its first four 16-byte outputs and nothing after that matches. The capture holds only M1-M3, so E-S1/E-S2 (which travel encrypted inside M5/M7) are never on the wire.

Conclusion: no cryptographically verifiable PIN can be produced from the supplied files. To finish Q5 you need the full M1-M8 handshake, then decrypt the M5/M7 Encrypted Settings with KeyWrapKey `21b5e248c27dfd5c3aa1dc5cdbbdb190` to read E-S1/E-S2, and `crack_half()` yields the two PIN halves instantly. The only non-crypto fallback is a default/label PIN; MAC-derived ComputePIN(50:c7:bf:3e:91:a4) = 24-bit `41005163` (also 28-bit `57587561`, 32-bit `85487727`), all unverifiable against this capture.

- Q5: REDACTED (demonstrably insufficient data to verify a PIN from M1-M3; see above)

### Reproduction

[[solver.py]] does the full chain from the two artifacts:

```
python3 -I solver.py capture.pcap registrar_dhpriv.txt
```

It prints DHKey, AuthKey (with the authenticator check), KeyWrapKey and the recovered PRNG seed, and contains the proven `crack_half()` ready for a supplied E-S. The core derivation and the LCG seed recovery are deterministic.

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event). Q5 (the PIN) is unresolved: the 3-message capture does not contain or leak E-S1/E-S2, so no verifiable PIN can be derived.

## Lessons

- A given DH private key plus M1/M2 fully reconstructs the WPS session keys (DHKey, AuthKey, KeyWrapKey); verifying your AuthKey against the captured M2/M3 authenticators proves the derivation before you build anything on top of it.
- A "weak PRNG seeded with Unix time" only weakens whatever fields that PRNG actually produced. Here it produced only the public nonces (N1/N2/UUID-E/UUID-R); the secret material (DH keys and E-S1/E-S2) came from a separate secure RNG, so the Pixie-Dust style attack can't bite.
- Pixie-Dust / E-Hash PIN recovery needs E-S1/E-S2, which only appear (encrypted) in M5/M7. A capture truncated to M1-M3 is structurally insufficient no matter how good the crypto chain is. Knowing when a challenge is missing required data is itself the finding.

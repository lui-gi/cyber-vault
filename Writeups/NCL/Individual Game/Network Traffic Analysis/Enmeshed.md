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

# Enmeshed

## Task

Cyber Command

Your suspects left a phone unlocked and you were able to grab the channel information for their private chat, along with the captured traffic of their discussion. Can you tell what they're planning?

- Q1 (15 pts): What is the radio technology used between the two communicating nodes?
- Q2 (15 pts): What 128 bit hex key is used to encrypt the messages between them?
- Q3 (15 pts): Where is Catherine transmitting from? Answer format: `MajorCity, XX` (`XX` is the abbreviated regional code)
- Q4 (15 pts): What does Catherine intend to bring back?
- Q5 (25 pts): What specialty shop closest to Catherine's location likely provided the goods?
- Q6 (15 pts): What agency might derail the weekend plans?

Note: no platform difficulty label was given for this challenge; recorded as medium.

## Approach

### Provided material

- `access.png` (copied to the vault as `enmeshed-access.png`): a QR code grabbed from the suspect's unlocked phone (the "channel information").
- `raw_packets.txt` (copied alongside this note): 8 captured radio packets, one hex string per line.
- `task.md`: the six questions.

![[enmeshed-access.png]]

### Initial recon

The challenge name "enmeshed" plus a "private chat channel" QR code points at a LoRa mesh messenger. Decoding the QR gives:

```
meshcore://channel/add?name=Planning&secret=<32-hex-secret>
```

That's a MeshCore channel-add URI, not Meshtastic. So:

- The link scheme confirms the protocol (MeshCore over LoRa radio).
- The `secret=` value is the shared channel key (32 hex chars = 128 bits).

Looking at the raw packets, two different first bytes show up: `0x11` (lines 1-2) and `0x15` (lines 3-8). Two of the lines also end in readable ASCII tails ("Catherine" and "wstearns-t1000e"), which is the giveaway that lines 1 and 2 are node advertisements and the rest are channel messages.

### MeshCore packet format (from the firmware source)

Header byte bit layout:

- bits 0-1: route type (`0x01` = FLOOD)
- bits 2-5: payload type
- bits 6-7: version

Payload types seen here: `0x04` = ADVERT, `0x05` = GRP_TXT (group channel text). So `0x11` = FLOOD + ADVERT, `0x15` = FLOOD + GRP_TXT.

General frame: `header | path_len | path | payload`. All captured packets use `path_len = 0x00`.

Group text payload and crypto, `createGroupDatagram` builds the payload as:

```
[ channel_hash : 1 byte ][ MAC : 2 bytes ][ AES ciphertext ]
```

From `Utils::encryptThenMAC` / `MACThenDecrypt`:

- cipher: AES-128 in ECB mode, key = the 16-byte channel secret, final block zero-padded.
- MAC: HMAC-SHA256 over the ciphertext, truncated to 2 bytes (only used to pick the channel, not needed to read the text).

Every GRP_TXT payload here starts with channel hash `0x6B`, confirming one shared channel.

Advert payload: `pub_key(32) | timestamp(4) | signature(64) | app_data`. The app_data flags byte `0x91` sets the lat/lon bit, so 8 bytes of coordinates follow (int32 little-endian, divided by 1e6), then the node name.

## Solution

Decrypted each `0x15` payload with AES-128-ECB and the channel key, got a 4-byte timestamp, a flags byte, then `name: text`. Reassembled in time order (2026-06-30, UTC):

```
15:06:00  Catherine: Wally?
15:06:39  wstearns-t1000e: Ok, I'm back online.
15:06:51  wstearns-t1000e: Did you get the goods?
15:07:49  Catherine: Yup, and a little extra.  I'm not sure Canadian customs will let me bring it all back.
15:08:10  wstearns-t1000e: How much Brie did you get?
15:08:46  Catherine: A pound and a half - plenty for the weekend.
```

So the "plan" is pretty mundane: a weekend cheese run. The "goods" are Brie, and the risk is getting it across the border.

Parsed Catherine's ADVERT app_data for her location:

- Catherine: lat `45.545863`, lon `-73.626719` -> Villeray, Montreal, Quebec.
- wstearns-t1000e: lat `43.645832`, lon `-72.181418` -> Vermont / New Hampshire side, which fits the border-crossing context.

Reverse geocoding Catherine's point lands on Rue Jarry Est in Villeray. The closest specialty food shop to that exact coordinate (about 18 m away, at 738 Rue Jarry Est) is a neighbourhood cheese shop (fromagerie) carrying roughly 200 cheeses, almost certainly where the Brie came from. The next nearest dedicated cheese shops are much farther (about 1.35 km and 1.43 km near Jean-Talon Market).

The agency Catherine's worried about ("Canadian customs") is the Canada Border Services Agency (CBSA), which enforces import limits on dairy at the border.

- Q1 (radio technology): REDACTED (LoRa, MeshCore mesh over LoRa)
- Q2 (128-bit encryption key): REDACTED (the 32-hex channel secret from the QR)
- Q3 (Catherine's location): REDACTED (Montreal, QC)
- Q4 (what she brings back): REDACTED (Brie)
- Q5 (specialty shop): REDACTED (the Villeray fromagerie at 738 Rue Jarry Est)
- Q6 (agency): REDACTED (Canada Border Services Agency / CBSA)

### How to reproduce

1. Decode `access.png` to get the MeshCore channel URI and 128-bit secret.
2. Parse each packet by header byte into ADVERT vs GRP_TXT.
3. For GRP_TXT, strip `channel_hash(1) + MAC(2)` and AES-128-ECB decrypt the rest with the secret.
4. For ADVERT, read the lat/lon from app_data (offset 100, flags `0x91`).
5. Geolocate Catherine's coordinate and find the nearest fromagerie.

## Flag

REDACTED (all answers redacted; this is a live/graded NCL event)

## Lessons

- A QR "channel" artifact for a mesh messenger is both the protocol fingerprint (URI scheme) and the key handover: MeshCore uses AES-128-ECB with the channel secret from the `channel/add` URI.
- Reading the firmware source for the packet/payload layout (header bit fields, `channel_hash | MAC | ciphertext`, advert app_data flags) is what turns raw hex into messages and coordinates.
- Advert packets leak node GPS when the lat/lon flag is set, which is enough to geolocate a sender precisely and chain into an OSINT question (nearest shop).

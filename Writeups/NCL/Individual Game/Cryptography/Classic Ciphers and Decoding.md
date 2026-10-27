---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Cryptography
difficulty: easy
status: solved
flags: redacted
tags: [writeup, crypto]
---

# Classic Ciphers and Decoding

This is a combined note covering several easy/medium Cryptography sub-tasks from the NCL Individual Game: decode-1, decode-2, Cooking With This XOR That, Three is a Crowd, and Collision. The Intercept (hard) netcat challenge is written up separately. This is a LIVE/GRADED event, so all decoded plaintexts, flags, and scoring answers are REDACTED; the method is kept intact.

## Task

Verbatim prompts (from `all-tasks.md`):

**decode-1 (easy)** - four short sub-messages, each a different classic encoding:

```
19-12-15-23-12-25-17-21-9-5-20-6-15-18-5-19-20-20-8-9-14-11-9-14-7

--... . ..-. ..-. .. -.-. .. . -. - .-.. -.-- -... --- .-.. -.. - .... ..- -. -.. . .-. -- --- -. .. - --- .-. . -.. ---..

frpherylfreraruneobevagreprcgrq

.---- ----. -....- ..--- ----- -....- .---- ---.. -....- .---- -....- ..--- ----- -....- ..... -....- --... -....- ----. ... (morse digits/dashes)
```

**decode-2 (easy):**

```
Tango-Hotel-Echo Echo-Sierra-Sierra-Echo-November-Tango-India-Alpha-Lima Charlie-Oscar-November-Foxtrot-Echo-Romeo-Echo-November-Charlie-Echo India-Sierra India-November Delta-Uniform-Bravo-Alpha-India

.... .... .. ... . ..... . ... .... .. ..... .... ... ..... .... .... .. .... . ... . . ... (dot groups)
```

**Cooking With This XOR That (medium):** "We have found four messages from Liber8tion we believe were encoded using a variety of XOR schemes with CyberChef and sent in base64. If they used a key for the encoding, it was the key xor. Decode each message and submit the entire message." Four base64 strings supplied.

**Three is a Crowd (medium):** "We've managed to intercept three transmissions from Liber8tion's internal communications. One of them we've already cracked. Can you crack the others?" Three base64 ciphertexts plus a known plaintext are supplied.

**Collision (medium):** "We found a file that doesn't look encrypted, but the code might be scrambled." Supplied: `collision.pyc`. Q1: file type of the `.pyc`. Q2: flag from reverse engineering the source.

## Approach

Each is a recognition-then-decode task. The trap in several of them is submitting a token when the grader wants the full sentence, and submitting a decoded component rather than the final answer.

## Solution

### decode-1 (easy)

Four separate classic encodings chained or standalone:

1. `19-12-15-23...` is A1Z26 (number equals letter position). Decodes to a lowercase word string. (answer REDACTED)
2. `--... . ..-.` is Morse code. Decodes to a digit-wrapped uppercase string. (answer REDACTED)
3. `frpherylfreraruneobevagreprcgrq` is ROT13. (answer REDACTED)
4. `.---- ----. -....-` is Morse where each symbol is a digit or dash, giving an A1Z26 number string, then A1Z26 again. (answer REDACTED)

### decode-2 (easy)

1. `Tango-Hotel-Echo ...` is the NATO phonetic alphabet; take the first letter of each word. (answer REDACTED)
2. The dot groups like `.... .... .. ...` are Tap Code (5x5 Polybius square, row then column taps map to letters). (answer REDACTED)

### Cooking With This XOR That (medium)

Each of the four base64 strings is `From Base64` then an XOR using one of CyberChef's XOR schemes; the key, when present, is the word `xor`.

CyberChef's XOR Scheme dropdown:
- Standard: `out[i] = in[i] XOR key[i]`
- Input differential: after each byte, the key position is overwritten with the input byte
- Output differential: after each byte, the key position is overwritten with the output byte

Decoding inverts whatever scheme encoded it: Standard inverts itself; input-differential is reversed with output-differential and vice versa; message 4 is a keyless running XOR seeded with the first char. Verified by re-encoding each recovered plaintext with its scheme and key `xor`, which reproduces the exact original base64.

The decoded text is `The Nth password is <TOKEN>`; the grader wants the whole sentence, not just the token. (all four sentences REDACTED)

```python
import base64

def bitop(data, key, scheme):
    key = list(key); L = len(key); out = []
    for i, x in enumerate(data):
        k = key[i % L]; o = x ^ k; out.append(o)
        if scheme == "input":  key[i % L] = x   # input differential
        elif scheme == "output": key[i % L] = o # output differential
    return bytes(out)

msgs = {
  "standard": "LAcXWAkbChwGWB8TCxwFFx0WWAYBWDY9Iio1OzUiOSYoIS0xOw==",
  "output":   "LAcXdBsAQxwLB08eBVMDFhwBE08bFwA+OXUCDxYDBAUDEwEAER8=",
  "input":    "LAcXDHN/ZQEbRXF6NgINWXBpeRkaWVtdAw4QWkNKCAEbXVFOHw==",
}
for scheme, b64 in msgs.items():
    print(bitop(base64.b64decode(b64), b"xor", scheme))

# message 4 has no key; running XOR seeded with the first char
raw = base64.b64decode("PA1FRgkaBwYcSFAREgAEGB0WREkaU3UeBwAfBg0cExwABxwcAU0=")
pt = [ord("T")]
for b in raw:
    pt.append(pt[-1] ^ b)
print(bytes(pt))
```

### Three is a Crowd (medium)

Classic many-time-pad / keystream reuse. The "faulty encryption script" reused the same keystream across two of the three messages. Recover the keystream from the known-plaintext message (`keystream = cipher XOR plaintext`), then apply it to the ciphertext that shares it (`plaintext = cipher XOR keystream`). The known plaintext matches ciphertext 1; its keystream decrypts ciphertext 3 to a status line containing the flag. Ciphertext 2 used a different, non-reused keystream and is not recoverable (which is the whole point of the "faulty" reuse). (recovered plaintext and flag REDACTED)

```python
import base64
cts = [c1, c2, c3]  # the three base64 strings
pt  = b"Reminder: the on-call rotation begins Friday evening and ends Monday morning as usual."
ks  = bytes(a ^ b for a, b in zip(base64.b64decode(cts[0]), pt))
print(bytes(a ^ b for a, b in zip(base64.b64decode(cts[2]), ks)))
```

### Collision (medium)

`collision.pyc` is compiled Python 3.8 bytecode.

- Q1 (file type): `file collision.pyc` reports along the lines of `Byte-compiled Python module for CPython 3.8`. Answer: compiled Python bytecode (.pyc). (exact expected string REDACTED; checker is permissive)
- Q2 (flag): the module reads `sys.argv[1]` and for each index checks `arr[x] XOR ord(input[x]) == compArr[x]`, printing `Pass` only on a full match. So the required input is `chr(arr[x] XOR compArr[x])`. Parse `arr` and `compArr` from the bytecode and XOR them.

```python
arr  = [106,184,0,77,37,23,47,88,101,137,107,175,52]
comp = [57,243,89,96,96,91,108,17,72,190,91,157,2]
print("".join(chr(a ^ b) for a, b in zip(arr, comp)))
```

(flag REDACTED)

## Flag

REDACTED

## Lessons

- Recognize encodings by shape first: dash/dot groups are Morse, number triples are A1Z26, NATO phonetic words spell an acronym, 5x5 dot groups are Tap Code.
- Encodings chain: Morse can decode to A1Z26 numbers which decode again to letters.
- Submit the entire decoded message, not just an embedded token; graders here reward the full sentence.
- For CyberChef XOR, decoding is the inverse of the encode scheme; verify by re-encoding to reproduce the original base64.
- Keystream reuse (many-time-pad) is broken with one known plaintext: XOR to recover the keystream, then reuse it. Only messages sharing a keystream are recoverable.
- A `.pyc` is reversible: read the bytecode to recover the per-index XOR check and invert it.

---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Password Cracking
difficulty: medium
status: solved
flags: redacted
tags: [writeup, password-cracking]
---

# Upload 2

## Task

Cyber Command

During a routine Slack audit, the security team turned up a message in `#random` containing one enormous block of text. Our best guess is the employee's connection dropped right as the company's file-transfer tool finished packaging up a personal backup. Rather than start over they pasted an encoded version of the archive straight into a DM to get it to a coworker, then deleted the message. Slack's export kept it anyway. Compliance wants to know what was in that archive, can you find it?

Hint: BOTH passwords are AT LEAST 8 characters long and contain AT LEAST ONE of EACH: a lowercase letter, an uppercase letter, a digit, and a symbol.

Q1 - What is the password to the archive?
Q2 - What is the password to the encrypted file inside the archive?
Q3 - What is the flag?

## Approach

Given a single file, one huge line of text starting with `UEsDBB`. Recognizing that prefix as the Base64 encoding of `PK\x03\x04` (the local file header magic of a ZIP archive) was the key first step, this is a Base64-encoded ZIP, not a hash to feed straight to a cracker.

```bash
base64 -d to-upload.txt > archive.zip
file archive.zip        # Zip archive data
unzip -l archive.zip    # single member: a .docx file
```

The ZIP turned out to be WinZip AES-encrypted (confirmed via `zip2john`'s `$zip2$*0*3*...` output, where `3` denotes AES-256), and its single member was a Word document. This is a two-stage nested-encryption problem: crack the ZIP password, extract the document, then crack the document's own Office encryption password.

**Stage 1 (ZIP password)**: no GPU/OpenCL backend available, so `hashcat` refused to start; `john` runs the `$zip2$` format natively on CPU.

```bash
zip2john archive.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 zip.hash
john --show zip.hash
```

Cracked in seconds, a plain rockyou entry (the `best64` identity rule alone found it, no real mangling needed). `unzip` can't decrypt AES zips, so extraction used `7z` instead: `7z x -p'<password>' -ocontents archive.zip`.

**Stage 2 (Office document password)**: the extracted file was an OLE2 compound document (`CDFV2 Encrypted`), i.e. a password-protected Office 2007-era file (`$office$*2007*`, 50,000 SHA-1 iterations, slow per guess). Since the stage-1 password turned out to be a plain dictionary word and the task pins down an exact complexity policy, pre-filtered rockyou to only policy-compliant candidates *before* running the slow office hash, cutting the wordlist from ~14M to roughly 47K entries while confirming the known stage-1 password still survived the filter (sanity check that the filter itself was correct).

```bash
office2john.py "contents/<path>/document.docx" > office.hash
LC_ALL=C grep -aP '^(?=.{8,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).*$' \
    /usr/share/wordlists/rockyou.txt > rockyou_policy.txt
john --wordlist=rockyou_policy.txt office.hash
john --show office.hash
```

**Stage 3 (reading the flag)**: decrypted the `.docx` with the recovered password using `msoffcrypto-tool`, then unzipped the decrypted document and read `word/document.xml` for the flag text.

## Solution

1. Q1 (archive password): a plain rockyou entry cracked via `zip2john` + `john --rules=best64` (REDACTED).
2. Q2 (document password): a policy-compliant rockyou entry, found after pre-filtering the wordlist to the exact stated complexity policy before running the slow Office hash (REDACTED).
3. Q3 (flag): read from the decrypted Word document's text after both passwords were recovered (REDACTED).

## Flag

REDACTED

## Lessons

- Recognize common Base64 magic-byte prefixes directly, `UEsDBB` is the Base64 encoding of `PK\x03\x04` (ZIP), so a giant blob of Base64 text pasted into chat may be a whole archive, not a hash.
- `$zip2$*0*3*` indicates WinZip AES-256; standard `unzip` cannot decrypt AES zips, use `7z x -p'<password>'` instead.
- With no GPU/OpenCL backend, prefer `john` over `hashcat` for both `$zip2$` and `$office$` formats, it runs them natively on CPU.
- When a task states an exact password-complexity policy (length + character-class requirements), filter the wordlist down to only matching candidates *before* running it against a slow hash (like Office 2007's 50,000-iteration SHA-1 KDF); this is the single biggest speed lever available, and verify the filter itself is correct by checking a known-good password still survives it.
- Nested encryption (archive -> document, or similar chains) is common in these challenges; expect to crack more than one password in sequence, with each stage's output feeding the next.
- `msoffcrypto-tool` decrypts password-protected legacy and OOXML Office documents once the password is known; the decrypted file is then just a normal (unencrypted) ZIP container you can inspect directly.

Supporting file: `to-upload.txt` (the Base64-encoded archive blob, not itself a credential) copied alongside this note.

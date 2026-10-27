---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Password Cracking
difficulty: easy
status: solved
flags: redacted
tags: [writeup, password-cracking]
---

# Rock Your Formats

## Task

We've got a couple of encrypted files here. Can you figure out what formats they are and crack the passwords using a popular wordlist?

Q1 - What is the password for `file1.yaml`
Q2 - What is the password for `file2.ppk`
Q3 - What is the password for `file3`

## Approach

Three files, three unrelated encrypted-container formats, identified by file signatures/headers rather than extension alone:

| File | Format | Identifying clue |
|------|--------|------|
| `file1.yaml` | Ansible Vault | first line `$ANSIBLE_VAULT;1.1;AES256` |
| `file2.ppk` | PuTTY private key | header `PuTTY-User-Key-File-2: ssh-rsa` |
| `file3` | 7-Zip archive | magic bytes `37 7a bc af 27 1c` |

Same method for each: extract a crackable hash representation with the matching `*2john` tool from the john-jumbo toolset, then run `john` against the rockyou wordlist, then `john --show` to reveal the cracked password.

```bash
python3 /usr/libexec/john-jumbo/ansible2john.py file1.yaml > h1.txt
john --wordlist=/usr/share/wordlists/rockyou.txt h1.txt
john --show h1.txt

/usr/libexec/john-jumbo/putty2john file2.ppk > h2.txt
john --wordlist=/usr/share/wordlists/rockyou.txt h2.txt
john --show h2.txt

perl /usr/libexec/john-jumbo/7z2john.pl file3 > h3.txt
john --wordlist=/usr/share/wordlists/rockyou.txt h3.txt
john --show h3.txt
```

The Ansible and PuTTY hashes cracked almost instantly. The 7z hash took roughly 3.5 minutes because of its 2^19 SHA-256 KDF iterations (slow by design). `7z2john.pl` kept failing with a missing Perl module (`Compress::Raw::Lzma`) with no privilege to install it; worked around by copying the script locally and wrapping the `use` line in a `BEGIN { eval { require ... } }` guard so the missing module is non-fatal. Turned out moot anyway: this particular archive stored its header uncompressed, so LZMA decompression was never actually needed for the hash extraction.

## Solution

All three passwords were plain rockyou entries, no rule mangling needed.

- Q1 (`file1.yaml`, Ansible Vault): REDACTED
- Q2 (`file2.ppk`, PuTTY private key): REDACTED
- Q3 (`file3`, 7-Zip archive): REDACTED

## Flag

REDACTED

## Lessons

- Identify unknown "encrypted file" challenges by magic bytes/header content, not by extension: Ansible Vault's `$ANSIBLE_VAULT;1.1;AES256` line, PuTTY's `PuTTY-User-Key-File-2:` header, and 7-Zip's `37 7a bc af 27 1c` signature are all distinctive and easy to `file`/`xxd`/`head` for.
- The `*2john` family of extractors (`ansible2john.py`, `putty2john`, `7z2john.pl`, etc., under `john-jumbo`) converts a wide range of container formats into a crackable hash representation for `john`.
- 7-Zip's AES KDF uses many SHA-256 iterations by design, expect orders of magnitude slower cracking throughput than a fast hash like MD5/SHA1.
- A missing optional Perl/Python dependency in a `*2john` helper can often be bypassed by making the `use`/`import` non-fatal if the feature it enables (e.g. LZMA decompression) isn't actually needed for the specific file at hand.

Supporting files: `file1.yaml` and `file2.ppk` copied alongside this note (both small, safe to keep for reference). `file3` (binary 7-Zip archive) left in `~/PWN/ncl_individual/password-cracking/rock-your-formats_easy/`, not copied.

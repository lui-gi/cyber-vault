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

# Start Your Nginxs

## Task

Cyber Command

We found a web server that appears to be using password protection for some of it's content, something that shouldn't happen here. We believe the passwords are 5 characters, letters only. Please investigate how this is being used.
Note: You only need to crack one of the two passwords correctly. Cracking time may take up to 40 minutes for both with no GPU, depending on tool use.

Q1 - We need one of the passwords for either account to see what's stored there.
Q2 - What is the full filesystem path to the directory protected by passwords?
Q3 - What specific subdirectory is excluded from this password requirement?

## Approach

Given three files: the task text, an `htpasswd` file with two Apache-MD5 (`$apr1$`) basic-auth entries, and the relevant `nginx-root.conf` site config.

**Q2/Q3 (config reading, no cracking needed)**: nginx resolves a request URI against the server block's `root` directive. The config had a protected `location` block requiring basic auth, nested under a server with a known `root` path, so the filesystem directory is simply `root` + the location path. A more specific nested `location` block inside the protected one set `auth_basic off`, overriding the parent's auth requirement for just that one subdirectory, that's the exclusion the task is hinting at (a sub-path left open underneath an otherwise-protected directory).

**Q1 (cracking)**: `$apr1$` is Apache MD5 (md5crypt variant, salted, 1000 rounds); `hashcat` mode 1600 needs a GPU/OpenCL backend that wasn't available, so used `john` on CPU instead. Given the stated constraint (5 characters, letters only):
- Tried an all-lowercase mask first (`?l?l?l?l?l`, 26^5 ≈ 11.9M candidates): exhausted with no hits, so not all-lowercase.
- Tried a mixed-case mask (`?1?1?1?1?1` with the custom charset `?l?u`, 52^5 ≈ 380M candidates), targeting just one of the two hashes since the task only required one: cracked within seconds.

Only one hash was targeted deliberately, since `john` checks every candidate against every salt in the file regardless, so limiting the input file to one hash runs twice as fast per candidate and the task only needed one password anyway.

## Solution

```bash
# exhausted, no hits:
john --mask='?l?l?l?l?l' --format=md5crypt-long htpasswd

# cracked in seconds once limited to one hash + mixed-case mask:
head -1 htpasswd > htpasswd.one
john --mask='?1?1?1?1?1' -1='?l?u' --format=md5crypt-long htpasswd.one
john --show --format=md5crypt-long htpasswd.one
```

- Q1: the cracked password for one of the two basic-auth accounts (REDACTED), a capitalized first letter is why the all-lowercase mask missed it initially.
- Q2: the filesystem path is the server's `root` directive joined with the protected `location` path (REDACTED).
- Q3: the subdirectory with `auth_basic off` nested under the protected location (REDACTED).

## Flag

REDACTED (no separate flag field was given beyond the three graded answers above)

## Lessons

- nginx auth and path resolution are both just reading the config: a `location` block's protected path combined with the server's `root` directive gives the on-disk directory; a more specific nested `location` can override a parent's `auth_basic` setting entirely, a common (and exploitable) misconfiguration pattern.
- `$apr1$` (Apache MD5 / md5crypt) maps to hashcat mode 1600 / john format `md5crypt-long`; without a GPU/OpenCL backend, `john` on CPU with a tight character-set mask is still fast enough for a short, fully-constrained keyspace.
- When a task only requires cracking *one of several* hashes, splitting that one hash into its own file roughly doubles `john`'s effective throughput, since it otherwise checks every candidate against every salt present.
- Exhaust the cheapest hypothesis first (all-lowercase mask) before expanding the character set; a quick negative result narrows the real keyspace (here, revealing a capital letter must be present) for free.

The `htpasswd` credential file itself is left in `~/PWN/ncl_individual/password-cracking/start-your-nginxs_medium/` and not copied, per ingestion rules. `nginx-root.conf` is copied alongside this note since it is configuration, not a credential.

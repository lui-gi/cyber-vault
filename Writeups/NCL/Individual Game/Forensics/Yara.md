---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Forensics
difficulty: easy
status: solved
flags: redacted
tags: [writeup, forensics]
---

# Yara

LIVE/GRADED event: the four scoring answers and the secret values the rule matched (the planted credentials/tokens/keys) are REDACTED. The method is kept fully intact.

## Task

> We discovered a suspicious project directory in a compromised repository. Use YARA rules to hunt down all the exposed secrets hiding in the codebase.

- Q1 (25): Run `scan.yara` on all files in `files.zip`. How many files match the rule?
- Q2 (25): What YARA string identifier matched in `database.ini`? (Format: `$<identifier>`)
- Q3 (25): How many different types of sensitive patterns matched across all files?
- Q4 (25): Which pattern did NOT match any files?

## Approach

Both challenge files sit in `/home/analyst`: `files.zip` and `scan.yara`. Unzip into a working folder and run the provided rule recursively with matched-string output, then answer four counting questions that hinge on the distinction between matching files and matching pattern types.

## Solution

```bash
mkdir -p work && unzip -o files.zip -d work
ls -R work
yara --version      # 4.5.2
```

The archive holds a small project tree: `README.md`, `database.ini`, a `docs/` folder, a `code/` folder with Python source and config files (`.env`, `settings.ini`, `credentials.yaml`, `secrets.json`), and logs.

The rule:

```
rule sensitive_data
{
    strings:
        $password    = /password\s*=\s*[^\n]+/i
        $api_key     = /api[_-]?key\s*[=:]\s*[^\n]+/i
        $private_key = "BEGIN PRIVATE KEY"
        $token       = /token\s*[=:]\s*[^\n]+/i
        $certificate = "BEGIN CERTIFICATE"
    condition:
        any of them
}
```

Five strings; condition `any of them`, so a file matches as soon as one string hits.

Scan recursively with matched bytes shown so each hit maps to a string identifier:

```bash
yara -r -s scan.yara work
```

The output shows hits on seven files (`database.ini`, `credentials.yaml`, `debug.log`, `config.py`, `secrets.json`, `.env`, `app.py`) across four distinct string identifiers; `secrets.json` hits `$private_key` twice (offsets `0x26` and `0xf3`) but is still one file and one pattern type. (The matched secret values are REDACTED.)

Answer method (values REDACTED):
- Q1 (files matching): count distinct file paths in the output.
  ```bash
  yara -r scan.yara work | awk '{print $NF}' | sort -u | wc -l
  ```
- Q2 (identifier in `database.ini`): the single string that fired on that file.
- Q3 (distinct pattern types): collapse hits to unique string identifiers (four fired).
- Q4 (pattern that never matched): set difference of the five defined strings minus the four that fired, i.e. the one literal that never appears in any file.

## Flag

REDACTED (this task has per-question scoring answers, not a single flag)

## Lessons

- Q1 and Q3 look similar but measure different things: with `condition: any of them`, Q1 counts matching files while Q3 counts distinct string types that fired. A file matching one pattern twice inflates neither count.
- `yara -r -s` is the key invocation: `-r` recurses, `-s` prints matched bytes so each hit can be pinned to its `$identifier`.
- Answer "which pattern never matched" as a set difference of defined vs fired identifiers rather than by eye.

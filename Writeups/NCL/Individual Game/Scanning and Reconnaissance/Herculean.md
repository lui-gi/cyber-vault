---
type: writeup
source: NCL/Individual Game
event: NCL Individual Game
category: Scanning and Reconnaissance
difficulty: medium
status: solved
flags: redacted
tags: [writeup, recon]
---

# Herculean

## Task

Cyber Command. NOTE: Challenge instance will not be accessible once challenge is completed.

We've gained access to a machine belonging to a member of Liber8tion. The hostname is `target`. We have a compliance scanner to audit it, but we're having trouble getting it to run. Can you help?

Q1 - What is the name of the guest-accessible SMB share?
Q2 - What is the SSH username found in the leaked credentials file?
Q3 - What is the full path to the compliance check profile hidden on your own machine?
Q4 - What is the SSH username used to run the compliance check?
Q5 - What is the password for that service account?
Q6 - What is the flag from the compliance-protected file?

## Approach

Started from a jump box with a custom "hercules" compliance scanner installed on PATH, tasked with auditing a separate target host. First step was orienting on the jump box itself: a hidden dot-directory in the home folder contained the scanner's "profile" for the check, an INI file with a `[connection]` block (naming the SSH account the check runs as) and a `[check]` block (naming the exact shell command the check runs: a plain `cat` of a protected file on the target). The profile shipped without a password, which was the first missing piece.

Reading the scanner binary's own source/help showed it just wraps `sshpass`+`ssh` to run the profile's command as the named user, with CLI flags to override the username/password at scan time.

SMB enumeration against the target started anonymous: an anonymously-listable share turned up a Base64-encoded credentials file, decoding to a username and password for SSH. Logging in with that account and reading the target's own Samba config revealed a *second*, non-guest share gated to that same user, hiding a handoff note that named the actual service account the compliance check needed to run as, along with its password.

Logging in as the service account and checking `sudo -l` showed it had passwordless sudo to run one specific root-owned wrapper script with an arbitrary argument. Reading that wrapper's source showed it dispatches on a check ID to the exact command the compliance profile intended to run, as root. The service account could not read the protected file directly (permission denied on its own), but running the sudo-allowed wrapper with the right check ID did the job as root.

## Solution

1. **Q1**: anonymous `smbclient -L //target -N` listed the guest-accessible share (answer REDACTED).
2. **Q2**: pulled a file from that guest share, decoded it from Base64, got a `username:password` pair; the username is Q2 (REDACTED), the password was used for the SSH foothold.
3. **Q3**: the compliance profile, hidden in a dot-directory on the local jump box, named Q3's path (REDACTED).
4. **Q4**: the profile's `[connection]` block named the SSH account the check is meant to run as (REDACTED).
5. **Q5**: found via a second, credential-gated SMB share only visible after authenticating as the Q2 account; a handoff note inside it gave the Q4 service account's password (REDACTED).
6. **Q6**: the service account had passwordless sudo on a root-owned dispatcher wrapper; running it with the correct check ID (matching the profile's intended check) printed the protected file's contents as root, which is the flag. Also reproduced "properly" by editing a copy of the scanner's own profile to use the sudo-wrapped command and running it through the hercules tool with the recovered credentials, rather than just bypassing it manually.

## Flag

REDACTED

## Lessons

- Orient on your own machine first: hostname, IP, installed tooling, and hidden dot-directories in `$HOME` are almost always in-scope and worth reading, a bespoke scanner on PATH is a strong hint about the intended technique.
- Read every provided tool's source or `--help` output; knowing exactly how a wrapper authenticates and what command it runs (shells out via `sshpass`/`ssh user@host "<command>"`, here) tells you precisely what credentials and command you need to supply.
- Treat config/profile files as a map: an INI/conf file naming an account, host, and command with no password is a direct pointer to what to hunt for next.
- Enumerate SMB from least to most privileged: anonymous share listing, anonymous share contents, then (once authenticated) read the server's own `smb.conf`, it reveals non-browseable or `valid users`-gated shares anonymous listing hides. Re-list with each new credential found.
- Decode anything that looks encoded (Base64, hex, etc.); leaked "creds" files are usually just `user:pass`.
- Credential tiering / lateral movement: after every new login, re-run the same triage (`id`, `sudo -l`, home directory dotfiles, samba config, grep for credential-looking strings). Each foothold is a stepping stone to the next.
- `sudo -l` is the pivot point for protected data; a NOPASSWD wrapper with a wildcard argument usually means reading its source reveals which sub-command reaches the target file. Prefer making the intended tool actually succeed (fix its profile and run it through the real scanner) over just bypassing it manually, it proves you understood the mechanism.
- On minimal BusyBox/Alpine targets, GNU-only flags may not exist; keep remote one-liners simple, and prefer copying a file + `sed`-editing it over heredocs when a paste-mangling terminal breaks multi-line input.

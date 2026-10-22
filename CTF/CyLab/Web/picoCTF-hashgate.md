## Overview

Question:
```
You have gotten access to an organisation's portal. Submit your email and password, and it redirects you to your profile. But be careful: just because access to the admin isn’t directly exposed doesn’t mean it’s secure. Maybe someone forgot that obscurity isn’t security... Can you find your way into the admin’s profile for this organisation and capture the flag?
```

## Initial Recon

As usual, I poked around the site. I started off by interacting with the site normally, like submitting random inputs in the input fields and checking the network requests. From there, I checked the source code, any additional sources in the head, and if any stores cookies existed. 

I found some credentials in the heading.

Plugged them in, and observed the HTTP Response header + body. I noticed that the value after /user was a hash value. I wasn't sure what format it was in, so I used a hash type identifier online and found it was MD5.

I then figured out that I would have to hash the correct value (we are given 3000) to authenticate as a high-tier user. However, I was unsure what values to test, so I used the hint. 

The challenge told me that the business only has 20 employees, so I started from 3001 and would try the hashes all the way up until 3021. 

I used a simple python script to automate this, and thus, we got the flag.
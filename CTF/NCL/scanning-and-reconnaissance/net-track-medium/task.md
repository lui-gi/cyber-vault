
Cyber Command

Can you interact with the strange server at `net-track.services.cityinthe.cloud:8090` and see what information you can extract?

4:32:27 pm

|   |   |
|---|---|
|Q1 - 25 points<br><br>What is the name and version of the software?||
|Q2 - 25 points<br><br>What is the flag?||
|Q3 - 50 points<br><br>What is the size of the largest file in bytes?|

```bash
└──$ nc -v net-track.services.cityinthe.cloud 8090
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 18.232.243.186:8090.
ls
Use help to get a list of supported commands
help
Here is a list of commands
version
list
get
help
version
RadicalShell v9
list
records
secret
notes
schedule
contacts
list secret
records
secret
notes
schedule
contacts
cd secret
Use help to get a list of supported commands
list
records
secret
notes
schedule
contacts
help
Here is a list of commands
version
list
get
help
get secret
SKY-NCAT-3071
help
Here is a list of commands
version
list
get
help
help
Here is a list of commands
version
list
get
help
list
records
secret
notes
schedule
contacts
get records
No records so far
get notes
TODO: take flag off server
get schedule
Completely free and busy when convenient
get contacts
Mom : REDACTED, Dad : REDACTED
get secret
SKY-NCAT-3071

# actual math challenge
get records
No records so far # 17 bytes
get notes
TODO: take flag off server # 26 bytes
get schedule
Completely free and busy when convenient # 40 bytes
get contacts
Mom : REDACTED, Dad : REDACTED # 30 bytes
get secret
SKY-NCAT-3071 # 13 bytes

17 + 13 + 40 + 30 + 26
= 126
```

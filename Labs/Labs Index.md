# Labs

## Machines
Write-ups live in `Machines/`, sorted by difficulty; use `Active/` for boxes in progress and `Retired/` for completed ones you want to keep as reference. Create a note with the **Machine** template.

- [[Labs/Machines/Machine Index|Machine Index]]

## Other Lab Content
- `Challenges/`: Jeopardy-style challenges (Web, Crypto, Pwn, Reversing, Forensics...)
- `Sherlocks/`: DFIR / blue-team investigations
- `ProLabs/`: multi-host Pro Labs (Dante, Offshore, Zephyr, etc.)

## Dataview (optional)
If the Dataview plugin is installed:

```dataview
TABLE os, difficulty, status
FROM "Labs/Machines"
WHERE type = "machine"
SORT difficulty ASC
```

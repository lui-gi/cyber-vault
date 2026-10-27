#!/usr/bin/env python3
"""List challenges in ~/PWN that are new or changed since they were last ingested.

Usage:
  pwn_scan.py                 report new/changed challenges
  pwn_scan.py --all           report every challenge with its status
  pwn_scan.py --mark PATH...  record challenge dirs (relative to PWN) as ingested
  pwn_scan.py --mark-all      record everything currently pending as ingested

A challenge is any directory under PWN that contains task.md or notes.md.
State lives in Writeups/.ingested.json (tracked in git).
"""
import argparse, hashlib, json, os, sys
from pathlib import Path

PWN = Path(os.environ.get("PWN_DIR", Path.home() / "PWN"))
VAULT = Path(__file__).resolve().parent.parent
STATE = VAULT / "Writeups" / ".ingested.json"
SKIP_DIRS = {".git", ".obsidian", "_template", "node_modules", "__pycache__"}
TEXT_MARKERS = ("task.md", "notes.md")
BIG = 1_000_000  # bytes; larger supporting files are listed but flagged


def challenge_dirs():
    for root, dirs, files in os.walk(PWN):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.endswith(".stegray"))
        if any(m in files for m in TEXT_MARKERS):
            yield Path(root)


def digest(d: Path) -> str:
    h = hashlib.sha256()
    for m in TEXT_MARKERS:
        p = d / m
        h.update(p.read_bytes() if p.exists() else b"-")
    return h.hexdigest()[:16]


def files_in(d: Path):
    out = []
    for p in sorted(d.rglob("*")):
        if p.is_file() and not any(part.endswith(".stegray") or part in SKIP_DIRS for part in p.relative_to(d).parts):
            out.append((str(p.relative_to(d)), p.stat().st_size))
    return out


def load():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save(state):
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--mark", nargs="+")
    ap.add_argument("--mark-all", action="store_true")
    a = ap.parse_args()
    if not PWN.is_dir():
        sys.exit(f"PWN dir not found: {PWN}")
    state = load()
    found = {str(d.relative_to(PWN)): d for d in challenge_dirs()}

    if a.mark or a.mark_all:
        targets = a.mark or [k for k, d in found.items() if state.get(k) != digest(d)]
        for k in targets:
            k = k.strip("/")
            if k not in found:
                sys.exit(f"not a challenge dir: {k}")
            state[k] = digest(found[k])
        save(state)
        print(f"marked {len(targets)} as ingested")
        return

    rows = []
    for k, d in found.items():
        st = "new" if k not in state else "changed" if state[k] != digest(d) else "done"
        if st != "done" or a.all:
            rows.append((st, k, d))
    if not rows:
        print("nothing pending")
    for st, k, d in rows:
        has = ",".join(m for m in TEXT_MARKERS if (d / m).exists())
        flags = []
        if not (d / "notes.md").exists():
            flags.append("NO-NOTES")
        extra = [f"{n}({s // 1000}KB{'!' if s > BIG else ''})" for n, s in files_in(d) if n not in TEXT_MARKERS]
        print(f"[{st}] {k}  ({has}) {' '.join(flags)}")
        if extra:
            print("      files: " + " ".join(extra))
    gone = sorted(set(state) - set(found))
    if gone:
        print("\nin state but missing from PWN: " + ", ".join(gone))


if __name__ == "__main__":
    main()

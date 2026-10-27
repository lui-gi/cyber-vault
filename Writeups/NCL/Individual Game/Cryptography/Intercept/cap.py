#!/usr/bin/env python3
import socket, struct, sys, time

HOST, PORT = "services.cityinthe.cloud", 4444
FRAME = 40
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
OUT = sys.argv[2] if len(sys.argv) > 2 else "capX.bin"

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(1.0)
raw = b""
end = time.time() + SECONDS
while time.time() < end:
    try:
        c = s.recv(8192)
        if not c: break
        raw += c
    except socket.timeout:
        pass
s.close()
open(OUT, "wb").write(raw)

m = raw.find(b"--- BEGIN BINARY STREAM ---")
banner = raw[:m].decode(errors="replace")
stream = raw[m+len(b"--- BEGIN BINARY STREAM ---"):]
pos = stream.find(b"L8")
stream = stream[pos:]

frames = []
pos = 0
while pos + FRAME <= len(stream):
    f = stream[pos:pos+FRAME]
    if f[:2] != b"L8":
        nb = stream.find(b"L8", pos+1)
        if nb == -1: break
        pos = nb; continue
    typ = f[2]; seq = struct.unpack(">I", f[3:7])[0]; plen = f[7]; body = f[8:40]
    frames.append((typ, seq, plen, body))
    pos += FRAME

print(f"captured {len(raw)} bytes, {len(frames)} frames")
from collections import Counter
types = Counter(t for t,_,_,_ in frames)
print("types:", dict(types))
print("plen dist:", dict(Counter(p for _,_,p,_ in frames)))
for typ, seq, plen, body in frames:
    tag = {1:"STATUS",2:"SECURE"}.get(typ, f"?{typ}")
    print(f"{tag} seq={seq} plen={plen} body={body.hex()}")

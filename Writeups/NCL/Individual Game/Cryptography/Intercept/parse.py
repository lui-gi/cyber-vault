#!/usr/bin/env python3
import struct, sys
FRAME=40
def parse(fn):
    raw=open(fn,'rb').read()
    m=raw.find(b"--- BEGIN BINARY STREAM ---")
    stream=raw[m+len(b"--- BEGIN BINARY STREAM ---"):]
    p=stream.find(b"L8"); stream=stream[p:]
    frames={}
    pos=0
    while pos+FRAME<=len(stream):
        f=stream[pos:pos+FRAME]
        if f[:2]!=b"L8":
            nb=stream.find(b"L8",pos+1)
            if nb==-1: break
            pos=nb; continue
        typ=f[2]; seq=struct.unpack(">I",f[3:7])[0]; plen=f[7]; body=f[8:40]
        frames[seq]=(typ,plen,body)
        pos+=FRAME
    return frames
if __name__=="__main__":
    a=parse(sys.argv[1]); b=parse(sys.argv[2])
    common=sorted(set(a)&set(b))
    print(f"{sys.argv[1]}: {len(a)} frames, {sys.argv[2]}: {len(b)} frames, common seq: {len(common)}")
    same=0
    for s in common[:15]:
        eq = a[s][2]==b[s][2]
        same+=eq
        print(f"seq={s} A.plen={a[s][1]} B.plen={b[s][1]} bodies_equal={eq}")
        print(f"   A={a[s][2].hex()}")
        print(f"   B={b[s][2].hex()}")
    print("bodies equal in", same, "of", min(15,len(common)))

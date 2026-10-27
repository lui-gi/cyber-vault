#!/usr/bin/env python3
"""Compute L(seq): the 3-register state contributed by the 32 seq bits with key=0.
INIT = 'zero regs; key bits, then 32 seq bits, mixed in 1 bit/clock, all regs'.
With key=0 the key-bit phase leaves state=0 (injecting 0s, just clocking a zero reg stays 0),
so only the 32 seq bits matter. We parameterize uncertain conventions.
"""
import sys; sys.path.insert(0,'.')
from gen import LENS, TAPS

def clock(state, r):
    L=LENS[r]; fb=0
    for t in TAPS[r]:
        fb ^= (state>>t)&1
    return (state>>1)|(fb<<(L-1))

def Lseq(seq, bitorder='msb', inject='after', inj_bit=0):
    """Run the seq-bit load with key=0. Returns (s0,s1,s2).
    bitorder: order of the 32 seq bits. 'msb' = bit31 first.
    inject: 'before' = XOR bit into reg then clock; 'after' = clock then XOR bit in.
    inj_bit: which bit position the input bit is XORed into (0=LSB).
    Note: with zero key phase, state stays 0 through key bits regardless of count.
    """
    st=[0,0,0]
    seqbits=[(seq>>(31-i))&1 for i in range(32)] if bitorder=='msb' else [(seq>>i)&1 for i in range(32)]
    for b in seqbits:
        for r in (0,1,2):
            if inject=='before':
                st[r]^=(b<<inj_bit)
                st[r]=clock(st[r],r)
            else:
                st[r]=clock(st[r],r)
                st[r]^=(b<<inj_bit)
    return tuple(st)

if __name__=="__main__":
    for bo in ('msb','lsb'):
        for inj in ('before','after'):
            print(bo,inj, [hex(x) for x in Lseq(116,bo,inj)])

#!/usr/bin/env python3
"""LFSR primitives. Verify which conventions are maximal-length."""

MASKS = {0:0x20009, 1:0x80027, 2:0x800021}
LENS  = {0:17, 1:19, 2:23}

def taps_from_mask(mask, L):
    # exponents < L that are set (the feedback taps, excluding x^L)
    return [e for e in range(L) if (mask>>e)&1]

# Fibonacci: state is list of bits, index 0 = newest? Let's use integer with bit i.
# Convention A ("fib_lsb"): output = bit0; feedback = XOR of state bits at tap positions
#   where taps are exponents < L of the polynomial; then state = (state>>1) | (fb<<(L-1)).
# Convention B ("fib_msb"): output = bit (L-1); feedback = XOR of taps; state=((state<<1)|fb)&mask_L, with fb from taps.

def step_fib_lsb(state, L, taps, maskL):
    out = state & 1
    fb = 0
    for t in taps:
        fb ^= (state>>t)&1
    state = (state>>1) | (fb<<(L-1))
    return state, out

def step_fib_msb(state, L, taps, maskL):
    out = (state>>(L-1))&1
    fb = 0
    for t in taps:
        fb ^= (state>>t)&1
    state = ((state<<1)|fb) & maskL
    return state, out

def period(stepfn, L, taps):
    maskL=(1<<L)-1
    start=1
    s=start; seen=0
    for i in range(1,(1<<L)+5):
        s,_=stepfn(s,L,taps,maskL)
        if s==start:
            return i
    return -1

if __name__=="__main__":
    for r in (0,1,2):
        L=LENS[r]; taps=taps_from_mask(MASKS[r],L)
        # drop exponent 0? taps includes 0. For x^L+...+1 the '+1' is exponent0.
        pA=period(step_fib_lsb,L,taps)
        pB=period(step_fib_msb,L,taps)
        print(f"R{r} L={L} taps(exp<L)={taps} periodFibLSB={pA} FibMSB={pB} (max={(1<<L)-1})")

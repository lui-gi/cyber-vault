#!/usr/bin/env python3
"""A5/1-style majority-clocked generator: concrete + Z3 recovery.
Convention (maximal Fibonacci): b[0]=LSB..b[L-1]=MSB; out=b[0]; fb=XOR(b[taps]);
shift down: new b[i]=b[i+1], new b[L-1]=fb.  (matches gen.step)
Clocking: majority of the three clock-tap bits; each reg steps iff its tap bit==maj.
Output = XOR of the three output bits (out_pos: 'lsb'=b[0] or 'msb'=b[L-1]).
"""
import sys; sys.path.insert(0,'.')
from gen import LENS, TAPS

def int_to_bits(x,L): return [(x>>i)&1 for i in range(L)]
def bits_to_int(b):
    v=0
    for i,bit in enumerate(b): v|=(bit&1)<<i
    return v

def step_bits(b, taps):
    L=len(b); fb=0
    for t in taps: fb^=b[t]
    return b[1:]+[fb]

def ks_majority(s0,s1,s2, nbits, clk, out_pos='lsb'):
    B=[int_to_bits(s0,LENS[0]),int_to_bits(s1,LENS[1]),int_to_bits(s2,LENS[2])]
    c=clk; ks=[]
    for _ in range(nbits):
        taps_bits=[B[r][c[r]] for r in (0,1,2)]
        maj=1 if sum(taps_bits)>=2 else 0
        if out_pos=='lsb':
            o=B[0][0]^B[1][0]^B[2][0]
        else:
            o=B[0][LENS[0]-1]^B[1][LENS[1]-1]^B[2][LENS[2]-1]
        ks.append(o)
        for r in (0,1,2):
            if taps_bits[r]==maj:
                B[r]=step_bits(B[r],TAPS[r])
    return ks

# ---------------- Z3 ----------------
def solve_z3(ksbits, clk, out_pos='lsb', build=256, timeout_ms=60000):
    import z3
    s=z3.Solver()
    s.set("timeout",timeout_ms)
    B=[]
    for r in (0,1,2):
        B.append([z3.Bool(f"r{r}_{i}") for i in range(LENS[r])])
    def xor(*a):
        e=a[0]
        for x in a[1:]: e=z3.Xor(e,x)
        return e
    def maj3(a,b,c):
        return z3.Or(z3.And(a,b),z3.And(a,c),z3.And(b,c))
    cur=[list(B[r]) for r in (0,1,2)]
    for i in range(build):
        tb=[cur[r][clk[r]] for r in (0,1,2)]
        m=maj3(tb[0],tb[1],tb[2])
        if out_pos=='lsb':
            o=xor(cur[0][0],cur[1][0],cur[2][0])
        else:
            o=xor(cur[0][LENS[0]-1],cur[1][LENS[1]-1],cur[2][LENS[2]-1])
        s.add(o== (ksbits[i]==1))
        newcur=[]
        for r in (0,1,2):
            L=LENS[r]; fb=cur[r][TAPS[r][0]]
            for t in TAPS[r][1:]: fb=z3.Xor(fb,cur[r][t])
            stepped=cur[r][1:]+[fb]
            doclk=(tb[r]==m)
            nb=[z3.If(doclk, stepped[j], cur[r][j]) for j in range(L)]
            newcur.append(nb)
        cur=newcur
    r=s.check()
    if r!=z3.sat: return None
    mdl=s.model()
    out=[]
    for r_ in (0,1,2):
        v=0
        for i in range(LENS[r_]):
            if z3.is_true(mdl[B[r_][i]]): v|=1<<i
        out.append(v)
    return tuple(out)

if __name__=="__main__":
    import random,time
    random.seed(3)
    clk=(8,9,11); outp='lsb'
    s0=random.getrandbits(17)|1; s1=random.getrandbits(19)|1; s2=random.getrandbits(23)|1
    ks=ks_majority(s0,s1,s2,256,clk,outp)
    print("synthetic states",s0,s1,s2)
    t=time.time()
    sol=solve_z3(ks,clk,outp,build=120)
    print("z3 sol",sol,"time %.1fs"%(time.time()-t))
    if sol:
        chk=ks_majority(sol[0],sol[1],sol[2],256,clk,outp)
        print("reproduces full 256:",chk==ks)

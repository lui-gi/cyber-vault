#!/usr/bin/env python3
"""Test REGULAR-clock LINEAR model: keystream_t = XOR of 3 register output bits.
Solve for 59-bit key contribution C from STATUS tails (zero-pad assumption) via GF(2).
Sweep INIT conventions + bit packing + output bit position.
"""
import sys; sys.path.insert(0,'.')
from gen import LENS, TAPS
import initmap
from parse import parse

def out_functionals(outbit='lsb', T=256):
    """Return U[t] = concat row (59 bits) mapping initial 59-bit state -> output bit t,
    for regular clocking, output = XOR of the three registers' outbit."""
    off={0:0,1:LENS[0],2:LENS[0]+LENS[1]}
    U=[]
    # symbolic state per reg: list of masks over 59 unknowns
    sym={r:[1<<(off[r]+i) for i in range(LENS[r])] for r in (0,1,2)}
    def sstep(ss,r):
        fb=0
        for t in TAPS[r]: fb^=ss[t]
        return ss[1:]+[fb]
    for t in range(T):
        if outbit=='lsb':
            m=sym[0][0]^sym[1][0]^sym[2][0]
        else:
            m=sym[0][LENS[0]-1]^sym[1][LENS[1]-1]^sym[2][LENS[2]-1]
        U.append(m)
        for r in (0,1,2): sym[r]=sstep(sym[r],r)
    return U

def Lstate_to_vec(Ltuple):
    off={0:0,1:LENS[0],2:LENS[0]+LENS[1]}
    v=0
    for r in (0,1,2):
        v ^= Ltuple[r]<<off[r]
    return v

def dot(mask, vec):
    return bin(mask & vec).count("1") & 1

def solve_gf2(eqs, n=59):
    pivots={}
    for m,v in eqs:
        cm,cv=m,v
        for p in list(pivots):
            if (cm>>p)&1:
                bm,bv=pivots[p]; cm^=bm; cv^=bv
        if cm==0:
            if cv: return None
            continue
        p=(cm&-cm).bit_length()-1
        pivots[p]=(cm,cv)
    sol=0
    for p in sorted(pivots,reverse=True):
        bm,bv=pivots[p]; val=bv; mm=bm&~(1<<p); j=0;x=mm
        while x:
            if x&1 and (sol>>j)&1: val^=1
            x>>=1;j+=1
        if val: sol|=1<<p
    return sol, len(pivots)

def run(frames, bo, inj, outbit, pack):
    U=out_functionals(outbit)
    eqs=[]; checks=[]
    for seq,(typ,plen,body) in frames.items():
        if typ!=1: continue
        Lt=initmap.Lseq(seq,bo,inj)
        Lvec=Lstate_to_vec(Lt)
        # keystream bits known for byte positions plen..31
        for byi in range(plen,32):
            byte=body[byi]
            for bit in range(8):
                if pack=='msb':
                    ksbit=(byte>>(7-bit))&1; t=byi*8+bit
                else:
                    ksbit=(byte>>bit)&1; t=byi*8+bit
                m=U[t]; const=dot(m,Lvec)
                eqs.append((m, ksbit^const))
    res=solve_gf2(eqs)
    if res is None: return ('INCONSISTENT',)
    C,rank=res
    # verify: regenerate all tails and compare
    good=tot=0
    for seq,(typ,plen,body) in frames.items():
        if typ!=1: continue
        Lt=initmap.Lseq(seq,bo,inj); Lvec=Lstate_to_vec(Lt)
        for byi in range(plen,32):
            byte=body[byi]
            for bit in range(8):
                if pack=='msb':
                    ksbit=(byte>>(7-bit))&1; t=byi*8+bit
                else:
                    ksbit=(byte>>bit)&1; t=byi*8+bit
                pred=dot(U[t], C^Lvec)
                tot+=1; good+= (pred==ksbit)
    return ('ok', rank, good, tot, C)

if __name__=="__main__":
    fn=sys.argv[1] if len(sys.argv)>1 else "caplong.bin"
    frames=parse(fn)
    nst=sum(1 for _,(t,_,_) in frames.items() if t==1)
    print(f"{fn}: {len(frames)} frames, {nst} STATUS")
    for bo in ('msb','lsb'):
      for inj in ('before','after'):
        for outbit in ('lsb','msb'):
          for pack in ('msb','lsb'):
            r=run(frames,bo,inj,outbit,pack)
            if r[0]=='ok':
                _,rank,good,tot,C=r
                flag = "  <-- FITS!" if good==tot else ""
                print(f"bo={bo} inj={inj} out={outbit} pack={pack}: rank={rank} match={good}/{tot}{flag}")
            else:
                print(f"bo={bo} inj={inj} out={outbit} pack={pack}: INCONSISTENT")

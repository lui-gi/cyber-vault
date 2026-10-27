#!/usr/bin/env python3
"""Generator simulator + symbolic single-frame model identification.

LFSR convention (verified maximal): state integer, bit i.
 step: out = state&1 ; fb = XOR of bits at tap exps ; state=(state>>1)|(fb<<(L-1)).
"""
MASKS = {0:0x20009, 1:0x80027, 2:0x800021}
LENS  = {0:17, 1:19, 2:23}
TAPS  = {r:[e for e in range(LENS[r]) if (MASKS[r]>>e)&1] for r in (0,1,2)}

def step(state, r):
    L=LENS[r]; fb=0
    for t in TAPS[r]:
        fb ^= (state>>t)&1
    out = state & 1
    return (state>>1)|(fb<<(L-1)), out

# ---- concrete generator (for synthetic validation) ----
def keystream_concrete(s0, s1, s2, nbits, model):
    """model: dict(control, rule, out). Returns list of output bits."""
    ctrl=model['control']; rule=model['rule']; outf=model['out']
    st=[s0,s1,s2]
    data=[r for r in (0,1,2) if r!=ctrl]
    ks=[]
    for _ in range(nbits):
        # peek control output = st[ctrl]&1
        cbit = st[ctrl]&1
        # decide stepping BEFORE or AFTER output? We'll do: compute output from current tops, then step.
        # output
        bits=[st[r]&1 for r in (0,1,2)]
        if outf=='xor3':
            o=bits[0]^bits[1]^bits[2]
        elif outf=='xor_data':
            o=bits[data[0]]^bits[data[1]]
        ks.append(o)
        # step per rule
        if rule=='ctrl_always_stopgo1':   # data regs step iff cbit==1; ctrl always steps
            st[ctrl],_=step(st[ctrl],ctrl)
            if cbit==1:
                for r in data: st[r],_=step(st[r],r)
        elif rule=='ctrl_always_stopgo0':
            st[ctrl],_=step(st[ctrl],ctrl)
            if cbit==0:
                for r in data: st[r],_=step(st[r],r)
        elif rule=='alt':   # cbit picks which data reg steps; ctrl always steps
            st[ctrl],_=step(st[ctrl],ctrl)
            tgt=data[0] if cbit==1 else data[1]
            st[tgt],_=step(st[tgt],tgt)
    return ks

# ---- symbolic engine for single-frame G&D ----
# Control register concrete (guessed). Data regs symbolic: each state bit is a linear
# combination (bitmask) over n unknowns (= L_d0 + L_d1 initial bits).
def symbolic_test(ks_known, model, ctrl_state0, maxbits):
    """Given a guessed control reg initial state, build linear eqns for data regs' init bits
    from the known keystream bits (list of (idx,bit)); return solution dict or None."""
    ctrl=model['control']; rule=model['rule']; outf=model['out']
    data=[r for r in (0,1,2) if r!=ctrl]
    Ld=[LENS[d] for d in data]
    n=sum(Ld)
    # symbolic initial states: data[0] bits -> unknowns 0..Ld0-1 ; data[1] -> Ld0..n-1
    # represent each reg's symbolic state as list of bitmasks length L
    sym={}
    off=0
    for d in data:
        sym[d]=[1<<(off+i) for i in range(LENS[d])]
        off+=LENS[d]
    cst=ctrl_state0
    def sstep(symstate, r):
        L=LENS[r]; fb=0
        for t in TAPS[r]:
            fb ^= symstate[t]
        out=symstate[0]
        return [symstate[i+1] for i in range(L-1)]+[fb], out
    # collect equations: each known ks bit -> linear combo (mask) == value
    eqs=[]   # (mask, val)
    for i in range(maxbits):
        cbit=cst&1
        # output symbolic
        obits=[]
        for r in (0,1,2):
            if r==ctrl:
                obits.append(('c',cst&1))
            else:
                obits.append(('s',sym[r][0]))
        if outf=='xor3':
            mask=0;val=0
            for kind,v in obits:
                if kind=='c': val^=v
                else: mask^=v
        elif outf=='xor_data':
            mask=0;val=0
            for r in data:
                mask^=sym[r][0]
        if i in ks_known:
            eqs.append((mask, val ^ ks_known[i]))
        # step
        if rule in ('ctrl_always_stopgo1','ctrl_always_stopgo0'):
            cst,_=step(cst,ctrl)
            go = (cbit==1) if rule.endswith('1') else (cbit==0)
            if go:
                for r in data:
                    sym[r],_=sstep(sym[r],r)
        elif rule=='alt':
            cst,_=step(cst,ctrl)
            tgt=data[0] if cbit==1 else data[1]
            sym[tgt],_=sstep(sym[tgt],tgt)
    # Gaussian elimination over GF(2)
    return solve_gf2(eqs,n), data, Ld

def solve_gf2(eqs, n):
    rows=[ (m,v) for m,v in eqs ]
    pivots={}
    basis=[]
    for m,v in rows:
        cm,cv=m,v
        for pm,(bm,bv) in pivots.items():
            if (cm>>pm)&1:
                cm^=bm; cv^=bv
        if cm==0:
            if cv!=0:
                return None  # inconsistent
            continue
        p=(cm & -cm).bit_length()-1
        pivots[p]=(cm,cv)
    # back-substitute: set free vars=0
    sol=0
    for p,(bm,bv) in pivots.items():
        val=bv
        mm=bm & ~(1<<p)
        # free vars assumed 0
        if mm==0:
            if val: sol|=(1<<p)
        else:
            # depends on other pivots/free; set free=0, and pivots resolved later
            pass
    # proper solve: order pivots desc
    order=sorted(pivots.keys(), reverse=True)
    sol=0
    for p in order:
        bm,bv=pivots[p]
        val=bv
        mm=bm & ~(1<<p)
        j=0
        x=mm
        while x:
            if x&1:
                if (sol>>j)&1: val^=1
            x>>=1; j+=1
        if val: sol|=(1<<p)
    return sol

if __name__=="__main__":
    # synthetic self-test
    import random
    random.seed(1)
    model=dict(control=0, rule='ctrl_always_stopgo1', out='xor_data')
    s0=random.getrandbits(17)|1; s1=random.getrandbits(19)|1; s2=random.getrandbits(23)|1
    ks=keystream_concrete(s0,s1,s2,256,model)
    ks_known={i:ks[i] for i in range(256)}
    # brute the control reg (17 bits) -> should find s0 and solve data regs
    import itertools
    found=0
    for guess in range(1,1<<17):
        res=symbolic_test(ks_known, model, guess, 256)
        sol,data,Ld=res
        if sol is not None:
            # verify
            d0=sol & ((1<<Ld[0])-1)
            d1=(sol>>Ld[0]) & ((1<<Ld[1])-1)
            st={0:None,1:None,2:None}
            st[model['control']]=guess
            st[data[0]]=d0; st[data[1]]=d1
            cand=keystream_concrete(st[0],st[1],st[2],256,model)
            if cand==ks:
                print("HIT guess=%d s0=%d match=%s"%(guess,s0,guess==s0))
                found+=1
                if guess==s0: break
    print("done, hits=",found)

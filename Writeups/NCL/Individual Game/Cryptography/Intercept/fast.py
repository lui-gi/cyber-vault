#!/usr/bin/env python3
"""Fast single-control G&D, generic over LFSR convention & output/control taps."""
import sys; sys.path.insert(0,'.')
MASKS={0:0x20009,1:0x80027,2:0x800021}; LENS={0:17,1:19,2:23}
TAPS={r:[e for e in range(LENS[r]) if (MASKS[r]>>e)&1] for r in (0,1,2)}

# ---- concrete step functions per convention ----
def mk_step(conv, r):
    L=LENS[r]; maskL=(1<<L)-1; taps=TAPS[r]; m=MASKS[r]
    if conv=='fib':   # out=bit0, fb=xor taps, shift down
        def st(s):
            fb=0
            for t in taps: fb^=(s>>t)&1
            return (s>>1)|(fb<<(L-1))
    elif conv=='gr':  # galois right_B: lsb out; s>>=1; if lsb: s^=(m>>1)
        def st(s):
            lsb=s&1; s>>=1
            if lsb: s^=(m>>1)
            return s & maskL
    elif conv=='gl':  # galois left: top out; s<<=1; if top: s^=(m&maskL)
        def st(s):
            top=(s>>(L-1))&1; s=(s<<1)&maskL
            if top: s^=(m&maskL)
            return s
    return st

def transition_rows(stepfn, L):
    """rows[j] = mask over input bits i such that new_bit_j = XOR_{i in rows[j]} old_i."""
    cols=[stepfn(1<<i) for i in range(L)]  # col_i = step(e_i)
    rows=[0]*L
    for i in range(L):
        c=cols[i]
        for j in range(L):
            if (c>>j)&1: rows[j]|=(1<<i)
    return rows

def sym_step(S, rows, L):
    new=[0]*L
    for j in range(L):
        acc=0; rm=rows[j]
        while rm:
            i=(rm & -rm).bit_length()-1
            acc^=S[i]; rm&=rm-1
        new[j]=acc
    return new

def func_table(conv, r, outbit, nsteps):
    """func[k] = mask (over this reg's L local unknowns) of output bit after k steps."""
    L=LENS[r]; stepfn=mk_step(conv,r); rows=transition_rows(stepfn,L)
    S=[1<<i for i in range(L)]
    oidx = 0 if outbit=='lsb' else L-1
    out=[]
    for k in range(nsteps+1):
        out.append(S[oidx])
        S=sym_step(S,rows,L)
    return out

def solve_gf2(eqs):
    piv={}
    for m,v in eqs:
        cm,cv=m,v
        for p in list(piv):
            if (cm>>p)&1:
                bm,bv=piv[p]; cm^=bm; cv^=bv
        if cm==0:
            if cv: return None
            continue
        p=(cm&-cm).bit_length()-1; piv[p]=(cm,cv)
    sol=0
    for p in sorted(piv,reverse=True):
        bm,bv=piv[p]; val=bv; mm=bm&~(1<<p); x=mm;j=0
        while x:
            if x&1 and (sol>>j)&1: val^=1
            x>>=1;j+=1
        if val: sol|=1<<p
    return sol

def ks_concrete(st, conv, model, n, outbit, cbit):
    stepf={r:mk_step(conv,r) for r in (0,1,2)}
    ctrl=model['control']; rule=model['rule']; outf=model['out']
    data=[r for r in (0,1,2) if r!=ctrl]
    oidx={r:(0 if outbit=='lsb' else LENS[r]-1) for r in (0,1,2)}
    S=dict(st); ks=[]
    for _ in range(n):
        cv=(S[ctrl]>>cbit)&1
        bits={r:(S[r]>>oidx[r])&1 for r in (0,1,2)}
        o=bits[0]^bits[1]^bits[2] if outf=='xor3' else bits[data[0]]^bits[data[1]]
        ks.append(o)
        S[ctrl]=stepf[ctrl](S[ctrl])
        if rule=='stopgo1':
            if cv==1:
                for r in data: S[r]=stepf[r](S[r])
        elif rule=='stopgo0':
            if cv==0:
                for r in data: S[r]=stepf[r](S[r])
        elif rule=='alt':
            tgt=data[0] if cv==1 else data[1]
            S[tgt]=stepf[tgt](S[tgt])
        elif rule=='geffe':
            for r in data: S[r]=stepf[r](S[r])
    return ks

def ks_concrete_geffe(st,conv,ctrl,data,n,outbit,cbit):
    stepf={r:mk_step(conv,r) for r in (0,1,2)}
    oidx={r:(0 if outbit=='lsb' else LENS[r]-1) for r in (0,1,2)}
    S=dict(st); ks=[]
    for _ in range(n):
        cv=(S[ctrl]>>cbit)&1
        tgt=data[0] if cv==1 else data[1]
        ks.append((S[tgt]>>oidx[tgt])&1)
        for r in (0,1,2): S[r]=stepf[r](S[r])
    return ks

def brute(ks_full, known_pos, conv, model, outbit, cbit):
    ctrl=model['control']; rule=model['rule']; outf=model['out']
    data=[r for r in (0,1,2) if r!=ctrl]
    T=max(known_pos)+1
    ft={d:func_table(conv,d,outbit,T+2) for d in data}
    Lc=LENS[ctrl]; stepf=mk_step(conv,ctrl)
    oidxc = 0 if outbit=='lsb' else Lc-1
    Ld0,Ld1=LENS[data[0]],LENS[data[1]]
    build=known_pos[:160]
    for g in range(1,1<<Lc):
        s=g; sched={data[0]:0,data[1]:0}
        # precompute per-step schedule and ctrl output bit up to T
        sch0=[];sch1=[];cout=[]
        s=g
        for t in range(T):
            cv=(s>>cbit)&1
            cout.append((s>>oidxc)&1)
            sch0.append(sched[data[0]]); sch1.append(sched[data[1]])
            s=stepf(s)
            if rule=='stopgo1':
                if cv==1: sched[data[0]]+=1; sched[data[1]]+=1
            elif rule=='stopgo0':
                if cv==0: sched[data[0]]+=1; sched[data[1]]+=1
            elif rule=='alt':
                if cv==1: sched[data[0]]+=1
                else: sched[data[1]]+=1
        eqs=[]
        ok=True
        for t in build:
            m0=ft[data[0]][sch0[t]]
            m1=ft[data[1]][sch1[t]] << Ld0
            mask=m0^m1
            const = cout[t] if outf=='xor3' else 0
            eqs.append((mask, ks_full[t]^const))
        sol=solve_gf2(eqs)
        if sol is None: continue
        d0=sol&((1<<Ld0)-1); d1=(sol>>Ld0)&((1<<Ld1)-1)
        st={ctrl:g, data[0]:d0, data[1]:d1}
        cand=ks_concrete(st,conv,model,T,outbit,cbit)
        if all(cand[t]==ks_full[t] for t in known_pos):
            return st
    return None

def stepcount(s, scheme, cbit, Lc):
    """Return data-register step count for this output, given control state s."""
    b0=(s>>cbit)&1
    b1=(s>>((cbit+1)%Lc))&1
    if scheme=='s12':   return 1+b0          # 1 or 2
    if scheme=='s01':   return b0            # 0 or 1 (==stopgo)
    if scheme=='s03':   return b0 | (b1<<1)  # 0..3
    if scheme=='s14':   return 1+(b0 | (b1<<1)) # 1..4
    return 1

def ks_concrete_multi(st, conv, ctrl, data, n, outbit, cbit, scheme, outf):
    stepf={r:mk_step(conv,r) for r in (0,1,2)}
    oidx={r:(0 if outbit=='lsb' else LENS[r]-1) for r in (0,1,2)}
    Lc=LENS[ctrl]; S=dict(st); ks=[]
    for _ in range(n):
        bits={r:(S[r]>>oidx[r])&1 for r in (0,1,2)}
        ks.append(bits[0]^bits[1]^bits[2] if outf=='xor3' else bits[data[0]]^bits[data[1]])
        sc=stepcount(S[ctrl],scheme,cbit,Lc)
        S[ctrl]=stepf[ctrl](S[ctrl])
        for r in data:
            for _ in range(sc): S[r]=stepf[r](S[r])
    return ks

def brute_multi(ks_full, known_pos, conv, ctrl, outbit, cbit, scheme, outf):
    data=[r for r in (0,1,2) if r!=ctrl]
    T=max(known_pos)+1
    maxsched=T*4+8
    ft={d:func_table(conv,d,outbit,maxsched) for d in data}
    Lc=LENS[ctrl]; stepf=mk_step(ctrl and 0 or 0,0) if False else mk_step(conv,ctrl)
    oidxc=0 if outbit=='lsb' else Lc-1
    Ld0,Ld1=LENS[data[0]],LENS[data[1]]
    build=known_pos[:160]
    for g in range(1,1<<Lc):
        s=g; sched={data[0]:0,data[1]:0}; sch0=[];sch1=[];cout=[]
        for t in range(T):
            cout.append((s>>oidxc)&1); sch0.append(sched[data[0]]); sch1.append(sched[data[1]])
            sc=stepcount(s,scheme,cbit,Lc)
            s=stepf(s)
            sched[data[0]]+=sc; sched[data[1]]+=sc
        eqs=[]
        for t in build:
            mask=ft[data[0]][sch0[t]]^(ft[data[1]][sch1[t]]<<Ld0)
            const=cout[t] if outf=='xor3' else 0
            eqs.append((mask, ks_full[t]^const))
        sol=solve_gf2(eqs)
        if sol is None: continue
        d0=sol&((1<<Ld0)-1); d1=(sol>>Ld0)&((1<<Ld1)-1)
        st={ctrl:g,data[0]:d0,data[1]:d1}
        cand=ks_concrete_multi(st,conv,ctrl,data,T,outbit,cbit,scheme,outf)
        if all(cand[t]==ks_full[t] for t in known_pos):
            return st
    return None

def brute_geffe(ks_full, known_pos, conv, ctrl, outbit, cbit):
    data=[r for r in (0,1,2) if r!=ctrl]
    T=max(known_pos)+1
    ft={d:func_table(conv,d,outbit,T+2) for d in data}
    Lc=LENS[ctrl]; stepf=mk_step(conv,ctrl)
    Ld0,Ld1=LENS[data[0]],LENS[data[1]]
    build=known_pos[:160]
    for g in range(1,1<<Lc):
        s=g; cv=[]
        for t in range(T):
            cv.append((s>>cbit)&1); s=stepf(s)
        eqs=[]
        for t in build:
            mask = ft[data[0]][t] if cv[t]==1 else (ft[data[1]][t]<<Ld0)
            eqs.append((mask, ks_full[t]))
        sol=solve_gf2(eqs)
        if sol is None: continue
        d0=sol&((1<<Ld0)-1); d1=(sol>>Ld0)&((1<<Ld1)-1)
        st={ctrl:g, data[0]:d0, data[1]:d1}
        cand=ks_concrete_geffe(st,conv,ctrl,data,T,outbit,cbit)
        if all(cand[t]==ks_full[t] for t in known_pos):
            return st
    return None

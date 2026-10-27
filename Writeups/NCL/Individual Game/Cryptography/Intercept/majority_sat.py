#!/usr/bin/env python3
import sys; sys.path.insert(0,'.')
from pysat.formula import IDPool
from pysat.solvers import Solver
from majority import ks_majority, LENS, TAPS

def build_and_solve(ksbits, clk, out_pos='lsb', T=160, solver='cadical153', timeout=None):
    vp=IDPool(); cls=[]
    def nv(): return vp._next()
    def equiv(a,b): cls.append([-a,b]); cls.append([a,-b])
    def xor2(a,b):  # returns var = a xor b
        z=nv(); cls.extend([[-z,-a,-b],[-z,a,b],[z,-a,b],[z,a,-b]]); return z
    def xorlist(vs):
        acc=vs[0]
        for v in vs[1:]: acc=xor2(acc,v)
        return acc
    def maj3(a,b,c):
        z=nv()
        cls.extend([[-a,-b,z],[-a,-c,z],[-b,-c,z],[a,b,-z],[a,c,-z],[b,c,-z]])
        return z
    def xnor(a,b):  # var = (a==b)
        z=nv(); cls.extend([[-z,-a,b],[-z,a,-b],[z,a,b],[z,-a,-b]]); return z
    def ite(cond,x,y): # var = cond? x : y
        z=nv(); cls.extend([[-cond,-x,z],[-cond,x,-z],[cond,-y,z],[cond,y,-z]]); return z

    cur=[[nv() for _ in range(LENS[r])] for r in (0,1,2)]
    init=[list(cur[r]) for r in (0,1,2)]
    for t in range(T):
        clkb=[cur[r][clk[r]] for r in (0,1,2)]
        m=maj3(clkb[0],clkb[1],clkb[2])
        if out_pos=='lsb':
            ob=[cur[r][0] for r in (0,1,2)]
        else:
            ob=[cur[r][LENS[r]-1] for r in (0,1,2)]
        o=xorlist(ob)
        cls.append([o] if ksbits[t]==1 else [-o])
        nxt=[]
        for r in (0,1,2):
            L=LENS[r]
            fb=xorlist([cur[r][tp] for tp in TAPS[r]])
            step=xnor(clkb[r],m)
            nb=[]
            for i in range(L):
                shifted = cur[r][i+1] if i<L-1 else fb
                nb.append(ite(step, shifted, cur[r][i]))
            nxt.append(nb)
        cur=nxt
    s=Solver(name=solver, bootstrap_with=cls)
    sat=s.solve()
    if not sat:
        s.delete(); return None
    model=s.get_model(); mset=set(v for v in model if v>0)
    out=[]
    for r in (0,1,2):
        v=0
        for i in range(LENS[r]):
            if init[r][i] in mset: v|=1<<i
        out.append(v)
    s.delete()
    return tuple(out)

if __name__=="__main__":
    import random,time
    random.seed(3); clk=(8,9,11); outp='lsb'
    s0=random.getrandbits(17)|1;s1=random.getrandbits(19)|1;s2=random.getrandbits(23)|1
    ks=ks_majority(s0,s1,s2,300,clk,outp)
    for solver in ['cadical153','glucose42','kissat404']:
        t=time.time()
        try:
            sol=build_and_solve(ks,clk,outp,T=160,solver=solver)
        except Exception as e:
            print(solver,'ERR',e); continue
        ok= sol and ks_majority(sol[0],sol[1],sol[2],300,clk,outp)==ks
        print(f"{solver}: sol={sol} reproduces={ok} time={time.time()-t:.1f}s",flush=True)

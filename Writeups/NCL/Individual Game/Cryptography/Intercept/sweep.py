#!/usr/bin/env python3
import sys,time; sys.path.insert(0,'.')
import fast

def bits_msb(b): return [ (byte>>(7-i))&1 for byte in b for i in range(8)]
def bits_lsb(b): return [ (byte>>i)&1 for byte in b for i in range(8)]

# target: SECURE frame body (pure keystream under zero-pad), or a status tail
body=bytes.fromhex(sys.argv[1]); plen=int(sys.argv[2])
controls=[int(x) for x in sys.argv[3].split(',')] if len(sys.argv)>3 else [0]
known_pos=list(range(plen*8,256))
orders={'msb':bits_msb(body),'lsb':bits_lsb(body)}
convs=['fib','gr','gl']; rules=['stopgo1','stopgo0','alt']; outs=['xor_data','xor3']
tapbits={'lsb':0,'msb':None}  # None -> use L-1 for that register

for ctrl in controls:
    Lc=fast.LENS[ctrl]
    for conv in convs:
        for pack,ks in orders.items():
            for bitpos in ('lsb','msb'):
                outbit=bitpos; cbit = 0 if bitpos=='lsb' else Lc-1
                for rule in rules:
                    for out in outs:
                        model=dict(control=ctrl,rule=rule,out=out)
                        t=time.time()
                        st=fast.brute(ks,known_pos,conv,model,outbit,cbit)
                        dt=time.time()-t
                        tag=f"R{ctrl} {conv} pack={pack} bit={bitpos} {rule:8} {out:9}"
                        if st:
                            print(f"*** HIT *** {tag} -> {st}  ({dt:.1f}s)",flush=True)
                        else:
                            print(f"    miss    {tag}  ({dt:.1f}s)",flush=True)
print("SWEEP DONE",flush=True)

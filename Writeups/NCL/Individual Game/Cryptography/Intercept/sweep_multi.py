#!/usr/bin/env python3
import sys,time; sys.path.insert(0,'.')
import fast
def bits_msb(b): return [ (byte>>(7-i))&1 for byte in b for i in range(8)]
def bits_lsb(b): return [ (byte>>i)&1 for byte in b for i in range(8)]
body=bytes.fromhex(sys.argv[1]); plen=int(sys.argv[2])
controls=[int(x) for x in sys.argv[3].split(',')] if len(sys.argv)>3 else [0]
schemes=sys.argv[4].split(',') if len(sys.argv)>4 else ['s12','s03','s14']
known_pos=list(range(plen*8,256))
orders={'msb':bits_msb(body),'lsb':bits_lsb(body)}
for ctrl in controls:
  Lc=fast.LENS[ctrl]
  for conv in ('fib','gr','gl'):
    for pack,ks in orders.items():
      for bitpos in ('lsb','msb'):
        outbit=bitpos; cbit=0 if bitpos=='lsb' else Lc-1
        for scheme in schemes:
          for outf in ('xor_data','xor3'):
            t=time.time()
            st=fast.brute_multi(ks,known_pos,conv,ctrl,outbit,cbit,scheme,outf)
            dt=time.time()-t
            tag=f"MULTI R{ctrl} {conv} pk={pack} bit={bitpos} {scheme} {outf}"
            print((f"*** HIT *** {tag} -> {st}" if st else f"    miss    {tag}")+f" ({dt:.1f}s)",flush=True)
print("MULTI SWEEP DONE",flush=True)

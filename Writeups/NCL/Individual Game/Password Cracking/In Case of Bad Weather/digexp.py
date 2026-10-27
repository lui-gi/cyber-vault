import crypt
hashes = {
 'dev2': '$y$j9T$5i3tI8p2ldz9pNiaVtWEG1$ADPHhA8dzOoyZgAoJYbW7H4OCeK94b0.FCoe/.AnKeD',
 'dev6': '$y$j9T$J3mwU6fFkbp1paEEgWHvh1$1pqH3AvhEjCziTNTvaS1fl2AWhVL/8Hi9ibORCsxqyB',
 'web1': '$y$j9T$GRYd5AWw62y332m/.4Ael1$OOOWGeAVoy/le9Qxwsyl/emi38EJgZ.4lG51MIm/bJ5',
}
sheet = {'dev2':'It3granckug;','dev6':'tiHiWrin#in5','web1':'ImNif.abEip3'}
def salt_of(h): return '$'.join(h.split('$')[:4])+'$'
def check(host, pw): return crypt.crypt(pw, salt_of(hashes[host]))==hashes[host]
def collatz(n):
    s=[n]
    while n!=1:
        n=n//2 if n%2==0 else 3*n+1;s.append(n)
    return s
def filt(seq): return ''.join(str(x) for x in seq if '0' not in str(x) and '1' not in str(x))
for host,pw in sheet.items():
    di=[i for i,c in enumerate(pw) if c.isdigit()][0]
    d=int(pw[di]); pre,post=pw[:di],pw[di+1:]
    cands=set()
    for seq in [collatz(d),collatz(6)]:
        f=filt(seq); full=''.join(str(x) for x in seq)
        for n in [f, full, str(len(collatz(d))-1), str(len(collatz(6))-1)]:
            cands.add(pre+n+post)      # replace
            cands.add(pw+n)            # append
            cands.add(n+pw)            # prepend
    hit=[c for c in cands if check(host,c)]
    print(host,sorted(cands),hit)
print('done')

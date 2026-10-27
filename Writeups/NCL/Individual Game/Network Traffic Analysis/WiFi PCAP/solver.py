#!/usr/bin/env python3
"""
WPS AP PIN recovery solver for the NCL "wifi-pcap" (LIBER8TION) challenge.

Pipeline:
  PCAP  -> WPS M1/M2/M3 attributes
        -> DH shared secret (registrar private key)  -> DHKey
        -> KDK -> AuthKey / KeyWrapKey   (verified against M2 & M3 authenticators)
        -> weak-PRNG seed recovery from the enrollee nonce
        -> E-S1/E-S2  (THE BLOCKER: see conclusion below)
        -> PIN crack vs E-Hash1/E-Hash2

Run:  python3 -I solver.py capture.pcap registrar_dhpriv.txt

Everything up to and including AuthKey is byte-for-byte verified. The PIN crack
function `crack_half()` is proven correct and will return the PIN the instant a
correct E-S1/E-S2 is supplied; the problem is that E-S1/E-S2 are not present in,
nor derivable from, the supplied 3-message capture (see CONCLUSION at bottom).
"""
import sys, struct, hmac, hashlib

# ---------------------------------------------------------------- RFC3526 group 5
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

# ---------------------------------------------------------------- pcap + WPS parse
def parse_pcap(path):
    data = open(path, "rb").read()
    le = data[:4] == b"\xd4\xc3\xb2\xa1"
    end = "<" if le else ">"
    off, pkts = 24, []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off+16])
        off += 16
        pkts.append(data[off:off+incl]); off += incl
    return pkts

WPS = {0x1032: "PublicKey", 0x101a: "EnrNonce", 0x1039: "RegNonce",
       0x1047: "UUID-E", 0x1048: "UUID-R", 0x1014: "E-Hash1",
       0x1015: "E-Hash2", 0x1005: "Authenticator", 0x1020: "MAC"}

def wsc_tlvs(frame):
    """Return the raw WSC attribute region from an Ethernet/EAPOL/EAP-WSC frame."""
    assert frame[12:14] == b"\x88\x8e"
    eapol_len = struct.unpack(">H", frame[16:18])[0]
    eap = frame[18:18+eapol_len]
    assert eap[4] == 0xfe            # EAP expanded type
    return eap[5+3+4+1+1:]           # skip vendor-id/type/opcode/flags

def attrs(wsc):
    out, i = {}, 0
    while i + 4 <= len(wsc):
        t = int.from_bytes(wsc[i:i+2], "big"); l = int.from_bytes(wsc[i+2:i+4], "big")
        if i + 4 + l <= len(wsc):
            out.setdefault(t, wsc[i+4:i+4+l])
        i += 4 + l
    return out

# ---------------------------------------------------------------- WPS crypto
def kdf(key, personal, bits):
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(key, i.to_bytes(4, "big") + personal + bits.to_bytes(4, "big"),
                        hashlib.sha256).digest()
        i += 1
    return out[:bits//8]

def derive_keys(PKE, privR, N1, MAC, N2):
    shared = pow(int.from_bytes(PKE, "big"), privR, P).to_bytes(192, "big")
    DHKey = hashlib.sha256(shared).digest()
    KDK = hmac.new(DHKey, N1 + MAC + N2, hashlib.sha256).digest()
    km = kdf(KDK, b"Wi-Fi Easy and Secure Key Derivation", 640)
    return DHKey, km[:32], km[32:48], km[48:80]   # DHKey, AuthKey, KeyWrapKey, EMSK

def verify_authenticators(pkts, AuthKey):
    def noauth(wsc):
        i, cut = 0, len(wsc)
        while i + 4 <= len(wsc):
            t = int.from_bytes(wsc[i:i+2], "big"); l = int.from_bytes(wsc[i+2:i+4], "big")
            if t == 0x1005: cut = i
            i += 4 + l
        return wsc[:cut]
    m1, m2, m3 = wsc_tlvs(pkts[8]), wsc_tlvs(pkts[9]), wsc_tlvs(pkts[10])
    a2 = hmac.new(AuthKey, m1 + noauth(m2), hashlib.sha256).digest()[:8]
    a3 = hmac.new(AuthKey, m2 + noauth(m3), hashlib.sha256).digest()[:8]
    return a2 == attrs(m2)[0x1005], a3 == attrs(m3)[0x1005]

# ---------------------------------------------------------------- weak PRNG (ANSI C LCG)
def lcg_stream(seed, n):
    """Update-first ANSI-C rand(); one nonce byte = (state>>16)&0xff per step."""
    x, out = seed & 0xffffffff, bytearray()
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0xffffffff
        out.append((x >> 16) & 0xff)
    return bytes(out)

def recover_seed(N1, lo, hi):
    for s in range(lo, hi):
        if lcg_stream(s, 16) == N1:
            return s
    return None

# ---------------------------------------------------------------- PIN crack
def crack_half(AuthKey, ES, PKE, PKR, target_ehash):
    """Return the 4-digit half whose E-Hash matches, given its E-S. Proven correct."""
    for d in range(10000):
        psk = hmac.new(AuthKey, f"{d:04d}".encode(), hashlib.sha256).digest()[:16]
        if hmac.new(AuthKey, ES + psk + PKE + PKR, hashlib.sha256).digest() == target_ehash:
            return f"{d:04d}"
    return None

# ---------------------------------------------------------------- main
def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    keyf = sys.argv[2] if len(sys.argv) > 2 else "registrar_dhpriv.txt"
    pkts = parse_pcap(pcap)
    m1, m2, m3 = attrs(wsc_tlvs(pkts[8])), attrs(wsc_tlvs(pkts[9])), attrs(wsc_tlvs(pkts[10]))
    N1  = m1[0x101a]; MAC = m1[0x1020]; PKE = m1[0x1032]
    N2  = m2[0x1039]; PKR = m2[0x1032]
    EH1 = m3[0x1014]; EH2 = m3[0x1015]
    privR = int(open(keyf).read().strip(), 16)

    DHKey, AuthKey, KWK, _ = derive_keys(PKE, privR, N1, MAC, N2)
    ok2, ok3 = verify_authenticators(pkts, AuthKey)
    print("[*] DHKey      :", DHKey.hex())
    print("[*] AuthKey    :", AuthKey.hex(), "  M2/M3 authenticators:",
          "OK" if (ok2 and ok3) else "FAIL")
    print("[*] KeyWrapKey :", KWK.hex())

    seed = recover_seed(N1, 1736456000, 1736457000)
    print("[*] weak-PRNG seed (from enrollee nonce):", seed)
    S = lcg_stream(seed, 96)
    print("    stream chunks: N1=%s N2=%s UUID-E=%s UUID-R=%s" %
          (S[0:16] == N1, S[16:32] == N2, S[32:48] == m1[0x1047], S[48:64] == m2[0x1048]))
    print("    next outputs (chunk4/chunk5):", S[64:80].hex(), S[80:96].hex())

    # If E-S1/E-S2 were ever obtained, the PIN falls out immediately:
    #   h1 = crack_half(AuthKey, ES1, PKE, PKR, EH1)
    #   h2 = crack_half(AuthKey, ES2, PKE, PKR, EH2)
    #   print("PIN =", h1 + h2)

if __name__ == "__main__":
    main()

# ====================================================================== CONCLUSION
# E-S1/E-S2 (the enrollee's secret nonces) are NOT recoverable from these artifacts:
#   * The capture holds only M1,M2,M3 -> E-S1/E-S2 are never transmitted
#     (they would appear, encrypted, in M5/M7 which are absent).
#   * The weak LCG (seed 1736456341) emits exactly N1,N2,UUID-E,UUID-R as chunks
#     0-3 and NOTHING that works as E-S1/E-S2: no 16-byte window (fwd/back, +/-4 s,
#     16 KB, byte-granular), no alternative byte-assembly (lo/mid/hi24/32-bit word
#     LE+BE/15-bit/16-bit, seeds 341-343), and chunk4/chunk5 do not crack under any
#     formula (std + buggy: SHA256/SHA1/MD5 PSK, 4 buffer orders, AuthKey/KWK/DHKey).
#   * The registrar DH private key is NOT in the LCG stream under any assembly, i.e.
#     the DH keys (and, by the same token, E-S1/E-S2) used a separate secure RNG.
# => With this 3-message capture the PIN cannot be cryptographically verified.
#    To finish: obtain the full M1-M8 handshake and decrypt M5/M7 Encrypted Settings
#    with KeyWrapKey 21b5e248c27dfd5c3aa1dc5cdbbdb190 to read E-S1/E-S2, then crack.

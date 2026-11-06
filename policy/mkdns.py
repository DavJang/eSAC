import struct, sys, os
# base DNS query for a given domain (labels), qdcount=1, A/IN
def dnsq(domain):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # id, flags(RD), qd=1,an,ns,ar
    q=b""
    for lab in domain.split('.'):
        q += bytes([len(lab)])+lab.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)  # qtype A, qclass IN
    return hdr+q
outdir="/home/sungwoo/esac_payloads"
os.makedirs(outdir, exist_ok=True)
benign=dnsq("example.com")   # 29 bytes
mal=dnsq("test.su")          # malicious TLD .su
print("benign base", len(benign), "mal base", len(mal))
for sz in (64,256,512,1024,1400):
    for name,base in (("com",benign),("su",mal)):
        if len(base)>sz:
            print("skip",name,sz,"base too big"); continue
        pad=base + b"\x00"*(sz-len(base))
        fn=f"{outdir}/dnsq_{name}_{sz:04d}.bin"
        open(fn,"wb").write(pad)
        print("wrote", fn, len(pad))

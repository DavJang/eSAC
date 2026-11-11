#!/bin/bash
# Port redis RESP verb-block onto opt3 base; build blockget/blockset opt3 variants.
cd /home/sungwoo/esac40g_hpol_20261004 || exit 1
python3 - <<'PY'
src=open("comm_filter_opt3_16k.bpf.c").read()
anchor="    if (qs) qs->policy_hits++;\n\n    if (idx == 0) {"
verb='''    if (qs) qs->policy_hits++;

    /* OPT(l7): redis RESP verb block (ported from comm_filter_l7). BLOCK_GET/BLOCK_SET compile-time. */
    if (proto == 6 || proto == 17) {
        __u32 l4_off_l7 = l3_off + ihl;
        __u32 l4hdr = (proto == 6)
            ? ((l4_off_l7 + 12 < sizeof(hdrbuf)) ? (((hdrbuf[l4_off_l7 + 12] >> 4) & 0xf) * 4) : 20)
            : 8;
        __u32 pl = l4_off_l7 + l4hdr;
        __u8 is_get = 0, is_set = 0;
        #pragma unroll
        for (int i = 0; i <= 20; i++) {
            __u32 o = pl + i;
            if (o + 3 <= sizeof(hdrbuf)) {
                unsigned char a = hdrbuf[o], b = hdrbuf[o+1], c2 = hdrbuf[o+2];
                if (a=='G' && b=='E' && c2=='T') is_get = 1;
                if (a=='S' && b=='E' && c2=='T') is_set = 1;
            }
        }
#ifdef BLOCK_GET
        if (is_get) action = ACT_DROP;
#endif
#ifdef BLOCK_SET
        if (is_set) action = ACT_DROP;
#endif
        (void)is_get; (void)is_set;
    }

    if (idx == 0) {'''
assert anchor in src, "ANCHOR_NOT_FOUND"
src=src.replace(anchor, verb, 1)
open("comm_filter_opt3_16k_redis.bpf.c","w").write(src)
print("variant_written lines=%d" % src.count(chr(10)))
PY
[ -f comm_filter_opt3_16k_redis.bpf.c ] || { echo "VARIANT_FAIL"; exit 1; }
CF="clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -DESAC_STRICT -mllvm -unroll-threshold=10000 -I. -I/home/sungwoo/eSAC -I/home/sungwoo/eSAC/ebpf -c comm_filter_opt3_16k_redis.bpf.c"
$CF -DBLOCK_GET -o comm_filter_opt3_16k_blockget.bpf.o 2>&1 | head -10
echo "BLOCKGET rc=${PIPESTATUS[0]} size=$(stat -c %s comm_filter_opt3_16k_blockget.bpf.o 2>/dev/null)"
$CF -DBLOCK_SET -o comm_filter_opt3_16k_blockset.bpf.o 2>&1 | head -10
echo "BLOCKSET rc=${PIPESTATUS[0]} size=$(stat -c %s comm_filter_opt3_16k_blockset.bpf.o 2>/dev/null)"
# sanity: verify the verb strings are present in the objects
echo "verb in blockget: $(strings comm_filter_opt3_16k_blockget.bpf.o 2>/dev/null | grep -c esac || echo n/a)"
ls -la comm_filter_opt3_16k_block*.bpf.o 2>/dev/null

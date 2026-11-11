/*
 * comm_filter.bpf.c  ── NO-BTF edition
 * Phase 2 - 통신 접근 제어 (Layer 2: rxburst / txburst 후킹)
 *
 * libbpf 0.5.0 + kernel 6.8 호환
 *   · bpf_core_read.h 제거 (CO-RE 없음)
 *   · F-6 수정: #define 상수 → const volatile struct runtime_config RCFG
 *               로더가 .rodata 에 mbuf 오프셋 등을 런타임 주입
 *   · __type() 전부 → __uint(key_size/value_size, sizeof(...))
 *   · RINGBUF → PERF_EVENT_ARRAY
 *   · emit_comm() → bpf_perf_event_output
 *   · cgroup mode: host-injected ID is selected outside the packet path
 */
#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "ufunc.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * F-6: Runtime config (.rodata 섹션, 로더가 로드 전에 값 주입)
 *   mbuf_off_* : tools/discover_offsets 가 실측한 rte_mbuf 필드 오프셋
 *   default 값은 일반 DPDK 빌드 기준 (로더 미연결 시 fallback)
 */
const volatile struct runtime_config RCFG = {
    .mbuf_off_buf_addr = 0,    /* 실제 오프셋은 로더가 주입          */
    .mbuf_off_data_off = 16,
    .mbuf_off_pkt_len  = 36,
    .mbuf_off_data_len = 40,
    .max_burst_inspect = 128,   /* F-1 수정: burst 32개 전부 검사      */
    .kill_signal       = 9,
    .enabled           = 1,
    .generation        = 0,
    .features          = FEAT_ENFORCEMENT | FEAT_LATENCY_SAMPLE,  /* 기본: 강제집행 활성화 */
    .tenant_cgroup_id  = 0,    /* loader must inject a nonzero host ID */
};

/* ── Maps (BTF 없이 raw size) ─────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(key_size,   sizeof(struct comm_policy_key));
    __uint(value_size, sizeof(struct comm_policy_value));
} comm_policy SEC(".maps");

/* OPT(flowcache): per-CPU direct-mapped 5-tuple decision cache.
 * Collapses up to ~20 comm_policy hash lookups/packet to a single
 * PERCPU_ARRAY access on a hit. Valid because comm_policy is read-only
 * during a run (agent reload resets the per-CPU array). Mirrors the
 * flow/conntrack caching real datapaths use for traffic locality. */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} comm_events SEC(".maps");

/* uprobe→uretprobe 인자 보관 (API-level RX), key = tid */
struct rxburst_args {
    __u64 rx_pkts_ptr;
    __u64 ts_entry;
    __u16 port_id;
    __u16 queue_id;
    __u16 nb_pkts;
    __u16 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct rxburst_args));
} rxburst_pending SEC(".maps");

/* uprobe→uretprobe 인자 보관 (Driver-level RX).
 * OPT(mcopt): was BPF_MAP_TYPE_HASH keyed by tid, which serialized every
 * per-burst access on the map's exclusive spinlock across all lcore worker
 * threads. Since each thread only touches its own entry (enter→leave paired,
 * non-nested), a PERCPU_ARRAY[1] gives per-CPU lock-free storage. A `valid`
 * flag replaces the old delete() to keep the "no matching enter" guard. */
struct rxburst_drv_args {
    __u64 rx_pkts_ptr;
    __u64 ts_entry;
    __u16 nb_pkts;
    __u8  valid;
    __u8  _pad[5];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct rxburst_drv_args));
} rxburst_drv_pending SEC(".maps");

/* Isolated candidate: active driver hooks use qkey(0, 0) only. A per-CPU
 * array preserves the same per-CPU counters without hash lookup/locking. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct queue_stats));
} queue_stats SEC(".maps");

/* RX 지연 히스토그램 (PERCPU) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct latency_hist));
} lat_hist SEC(".maps");

/* TX 지연 히스토그램 (PERCPU) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct latency_hist));
} lat_hist_tx SEC(".maps");

/* 취약성 이벤트 (RX starvation, TX drop, malformed mbuf) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} vuln_events SEC(".maps");

/* TX burst 인자 보관 (uretprobe에서 drop 탐지).
 * OPT(mcopt): HASH(key=tid) → PERCPU_ARRAY[1], same rationale as
 * rxburst_drv_pending — removes the per-burst exclusive-spinlock contention. */
struct txburst_drv_args {
    __u16 nb_pkts;
    __u8  valid;
    __u8  _pad[5];
    __u64 ts_entry;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct txburst_drv_args));
} txburst_drv_pending SEC(".maps");


/* ── Protocol constants ──────────────────────────────────────────── */
#define ETH_HLEN        14
#define VLAN_HLEN        4
#define IP_HLEN_MIN     20
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_VLAN  0x8100
#define IPV4_FRAG_MF    0x2000
#define IPV4_FRAG_MASK  0x1fff

/* ── Helpers ─────────────────────────────────────────────────────── */
static __always_inline int
read_user(void *dst, const void *src, __u32 sz)
{
    return bpf_probe_read_user(dst, sz, src);
}

static __always_inline __u32
qkey(__u16 port, __u16 q)
{
    return ((__u32)port << 16) | (__u32)q;
}

static __always_inline struct queue_stats *
qstats(__u16 port, __u16 q)
{
    __u32 k = qkey(port, q);
    return bpf_map_lookup_elem(&queue_stats, &k);
}

static __always_inline __u32
ilog2_64(__u64 v)
{
    __u32 r = 0;
    if (v == 0) return 0;
    /* Binary search for the highest set bit: at most six tests instead of
     * scanning all 64 bit positions on each latency sample. */
    if (v >> 32) { v >>= 32; r += 32; }
    if (v >> 16) { v >>= 16; r += 16; }
    if (v >>  8) { v >>=  8; r +=  8; }
    if (v >>  4) { v >>=  4; r +=  4; }
    if (v >>  2) { v >>=  2; r +=  2; }
    if (v >>  1) {           r +=  1; }
    if (r >= LAT_BUCKETS) r = LAT_BUCKETS - 1;
    return r;
}

static __always_inline void
record_latency(__u64 ns)
{
    if (!(RCFG.features & FEAT_LATENCY_SAMPLE)) return;
    __u32 k = 0;
    struct latency_hist *h = bpf_map_lookup_elem(&lat_hist, &k);
    if (!h) return;
    __u32 b = ilog2_64(ns);
    h->buckets[b]++;
    h->sum += ns;
    h->count++;
    if (ns > h->max) h->max = ns;
}

static __always_inline void
record_tx_latency(__u64 ns)
{
    if (!(RCFG.features & FEAT_LATENCY_SAMPLE)) return;
    __u32 k = 0;
    struct latency_hist *h = bpf_map_lookup_elem(&lat_hist_tx, &k);
    if (!h) return;
    __u32 b = ilog2_64(ns);
    h->buckets[b]++;
    h->sum += ns;
    h->count++;
    if (ns > h->max) h->max = ns;
}

struct policy_lookup_args {
    __u64 tenant_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

/* Return UINT32_MAX when this specificity class has no match. */
/* opt3: probe only slots whose bit is set in the mask (base = class*5).
 * Key mutations run unconditionally so later probes see the right key state;
 * only the map lookup is gated. */
static __noinline __u32 lookup_one_class(const struct policy_lookup_args *a,
                                         __u32 mask, __u32 base)
{
    struct comm_policy_key k = {};
    struct comm_policy_value *v;
    k.layer = 2;
    k.cgroup_id = a->tenant_id;
    k.protocol = a->proto;
    k.src_port = a->src_port;
    k.dst_port = a->dst_port;
    k.src_ip = a->src_ip;
    k.dst_ip = a->dst_ip;
    if (mask & (1u << (base + 0))) {
        v = bpf_map_lookup_elem(&comm_policy, &k);
        if (v) { return v->action; }
    }
    k.src_ip = 0;
    if (mask & (1u << (base + 1))) {
        v = bpf_map_lookup_elem(&comm_policy, &k);
        if (v) { return v->action; }
    }
    k.dst_ip = 0;
    if (mask & (1u << (base + 2))) {
        v = bpf_map_lookup_elem(&comm_policy, &k);
        if (v) { return v->action; }
    }
    k.dst_port = 0; k.dst_ip = a->dst_ip;
    if (mask & (1u << (base + 3))) {
        v = bpf_map_lookup_elem(&comm_policy, &k);
        if (v) { return v->action; }
    }
    k.dst_ip = 0;
    if (mask & (1u << (base + 4))) {
        v = bpf_map_lookup_elem(&comm_policy, &k);
        if (v) { return v->action; }
    }
    return 0xffffffffU;
}

/* The packed source tuple preserves the eBPF subprogram five-arg limit. */
static __noinline __u32
lookup_action_slow(__u64 tenant_id, __u8 proto, __u16 dst_port,
              __u64 packed_src, __u32 dst_ip)
{
    /* A missing host-injected identity must never select wildcard ALLOW. */
    if (tenant_id == 0) return ACT_KILL;
    struct policy_lookup_args a = {};
    __u32 action;
    a.tenant_id = tenant_id;
    a.src_ip = (__u32)packed_src;
    a.src_port = (__u16)(packed_src >> 32);
    a.dst_ip = dst_ip;
    a.dst_port = dst_port;
    a.proto = proto;

    /* opt3: probe mask packed in RCFG.features bits 8..27 (20 bits). */
    __u32 mask = (RCFG.features >> 8) & 0xFFFFFu;
    /* base: (tenant=0 / global=10) + (src_port exact=0 / wildcard=5) */
    if (mask & (0x1Fu << 0)) {               /* tenant, src_port exact */
        action = lookup_one_class(&a, mask, 0);
        if (action != 0xffffffffU) return action;
    }
    if (mask & (0x1Fu << 5)) {               /* tenant, src_port wildcard */
        a.src_port = 0;
        action = lookup_one_class(&a, mask, 5);
        if (action != 0xffffffffU) return action;
    }
    a.tenant_id = 0;
    a.src_port = (__u16)(packed_src >> 32);
    if (mask & (0x1Fu << 10)) {              /* global, src_port exact */
        action = lookup_one_class(&a, mask, 10);
        if (action != 0xffffffffU) return action;
    }
    if (mask & (0x1Fu << 15)) {              /* global, src_port wildcard */
        a.src_port = 0;
        action = lookup_one_class(&a, mask, 15);
        if (action != 0xffffffffU) return action;
    }
    /* A parsed IPv4 packet without an explicit policy is denied immediately. */
    return ACT_DROP;
}

/* L4 policy decision: direct read-only comm_policy lookup (no per-flow cache). */
static __always_inline __u32
lookup_action(__u64 tenant_id, __u8 proto, __u16 dst_port,
              __u64 packed_src, __u32 dst_ip)
{
    return lookup_action_slow(tenant_id, proto, dst_port, packed_src, dst_ip);
}

static __always_inline void
emit_comm(void *ctx,
          __u32 pid, __u32 tgid, __u64 cgroup_id,
          __u16 port, __u16 queue,
          __u16 nb_ret, __u16 nb_drop,
          __u32 sip, __u32 dip, __u16 sp, __u16 dp,
          __u8 proto, __u8 action, __u16 hook_dir)
{
    struct comm_event e = {};
    e.ts_ns            = bpf_ktime_get_ns();
    /* Refresh after packet parsing: cached PID was corrupted across nested
     * BPF subprogram calls in the bpftime JIT. */
    e.pid              = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e.tgid             = tgid;
    e.cgroup_id        = cgroup_id;
    e.port_id          = port;
    e.queue_id         = queue;
    e.nb_pkts_returned = nb_ret;
    e.nb_pkts_dropped  = nb_drop;
    e.src_ip           = sip;
    e.dst_ip           = dip;
    e.src_port         = sp;
    e.dst_port         = dp;
    e.protocol         = proto;
    e.action_taken     = action;
    e.hook_dir         = hook_dir;
    bpf_ringbuf_output(&comm_events, &e, sizeof(e), 0);
}

/* mbuf pkt_len/data_len → 0 (enforcement 비활성 시 no-op) */
static __always_inline void
emit_vuln(void *ctx,
          __u32 pid, __u32 tgid, __u64 cgroup_id,
          __u16 port, __u16 queue,
          __u8 vuln_type, __u32 detail)
{
    struct vuln_event e = {};
    e.ts_ns      = bpf_ktime_get_ns();
    e.pid        = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e.tgid       = tgid;
    e.cgroup_id  = cgroup_id;
    e.port_id    = port;
    e.queue_id   = queue;
    e.vuln_type  = vuln_type;
    e.detail     = detail;
    bpf_ringbuf_output(&vuln_events, &e, sizeof(e), 0);
}

static __always_inline void
nullify_mbuf(__u64 mbuf_ptr)
{
    if (!(RCFG.features & FEAT_ENFORCEMENT)) return;
    __u32 z32 = 0;
    __u16 z16 = 0;
    bpf_probe_write_user(
        (void *)(unsigned long)(mbuf_ptr + RCFG.mbuf_off_pkt_len),  &z32, sizeof(z32));
    bpf_probe_write_user(
        (void *)(unsigned long)(mbuf_ptr + RCFG.mbuf_off_data_len), &z16, sizeof(z16));
}


/* ── bpf_loop: per-packet context & callback ────────────────────── */
/*
 * VERIFIER FIX: counter fields removed from pkt_iter_ctx.
 * Accumulating packet counters on the BPF stack
 * across bpf_loop iterations creates distinct concrete register-state
 * variants that the verifier must re-explore for each iteration, causing
 * state explosion (>1M insns).  Instead, each pkt_cb invocation does its
 * own bpf_map_lookup_elem(&queue_stats, &c->qstats_key) and writes
 * counters directly to the resulting map_value.  Map-value writes produce
 * only "unknown" (mmmm) verifier states that dedup immediately, so the
 * loop converges in O(#distinct actions) ≈ 2 iterations.
 */
struct pkt_scratch {
    /* Batched pre-fetch of one burst's mbuf pointer array. Lives in a
     * per-thread map slot (NOT on the stack) because embedding a 256-byte
     * array directly in struct pkt_iter_ctx overflows the eBPF ISA's
     * 512-byte stack-frame limit once combined with the other per-packet
     * scratch buffers in the (force-inlined) pkt_cb()/parse_and_apply()
     * frame. Keyed by thread id so concurrent lcore worker threads never
     * share a slot (each DPDK poll thread only ever touches its own key). */
    __u64 mbuf_ptrs[128];
    __u64 dropped_ptrs[128];
};

/* OPT(mcopt): HASH(key=tid) → PERCPU_ARRAY[1]. Each lcore thread only ever
 * touched its own tid slot (see comment above), so per-CPU storage is exact
 * and removes the exclusive-spinlock acquisition on every burst. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_scratch);
} pkt_scratch_map SEC(".maps");

/* Read-only zero template used to lazily create a thread's scratch slot
 * without needing a 256-byte zero-initializer on the stack. */
static const struct pkt_scratch g_zero_scratch;

/* --- L7 BATCH (완성형): per-burst HS scratch; pkt_prescan content-gates then fills it --- */
struct hs_batch_item { __u64 pl_ptr; __u32 pl_len; __u32 act; };
struct hs_batch { struct hs_batch_item item[128]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct hs_batch));
} hs_batch_map SEC(".maps");

struct pkt_iter_ctx {
    /* constant inputs */
    __u64  ptr_base;
    __u64  cgroup_id;
    __u32  qstats_key;   /* key passed to bpf_map_lookup_elem(&queue_stats) */
    __u16  n;
    __u8   _pad0[2];
    /* pointer into this thread's pkt_scratch_map slot (see pkt_scratch
     * above); NULL means the batched pre-fetch could not be set up for
     * this burst (pkt_cb() then falls back to a direct per-packet read). */
    struct pkt_scratch *mbuf_scratch;
    /* queue_stats pointer already looked up once in parse_and_apply()
     * (it needs it anyway for the drop_before/after snapshot) -- reused
     * here so pkt_cb() doesn't repeat the same bpf_map_lookup_elem() on
     * every packet in the burst (was up to 32 redundant lookups per
     * burst). NULL only if the queue_stats map lookup itself failed. */
    struct queue_stats *qs;
    struct hs_batch *batch;
    __u32 l7_cand;
    /* per-burst outputs (written ≤1 time each; out_worst converges in 2) */
    __u32  out_sip;
    __u32  out_dip;
    __u32  out_worst;
    __u16  out_sp;
    __u16  out_dp;
    __u8   out_proto;
    __u8   _pad1[3];
    __u8   is_rx;
    __u8   failed;
    __u16  kept;
    __u16  dropped;
};

static __noinline int pkt_prescan(__u32 idx, void *arg)
{
    struct pkt_iter_ctx *c = arg;
    if (idx >= (__u32)c->n) return 1;
    if (idx >= 128) return 1;
    struct hs_batch *b = c->batch;
    if (!b) return 0;
    b->item[idx].pl_ptr = 0; b->item[idx].pl_len = 0; b->item[idx].act = 255u;

    __u64 mbuf_ptr = 0;
    if (c->mbuf_scratch) mbuf_ptr = c->mbuf_scratch->mbuf_ptrs[idx];
    else if (read_user(&mbuf_ptr, (void *)(unsigned long)(c->ptr_base + (__u64)idx * 8), 8) < 0) return 0;
    if (!mbuf_ptr) return 0;

    unsigned char meta[48];
    if (read_user(meta, (void *)(unsigned long)mbuf_ptr, sizeof(meta)) < 0) return 0;
    __u32 off_ba = RCFG.mbuf_off_buf_addr, off_do = RCFG.mbuf_off_data_off, off_pl = RCFG.mbuf_off_pkt_len;
    if (off_ba > sizeof(meta) - 8) off_ba = 0;
    if (off_do > sizeof(meta) - 2) off_do = 16;
    if (off_pl > sizeof(meta) - 4) off_pl = 36;
    __u64 buf_addr = 0; __u16 data_off = 0; __u32 pkt_len = 0;
    __builtin_memcpy(&buf_addr, meta + off_ba, 8);
    __builtin_memcpy(&data_off, meta + off_do, 2);
    __builtin_memcpy(&pkt_len,  meta + off_pl, 4);
    if (!buf_addr || pkt_len < ETH_HLEN) return 0;

    __u64 data_ptr = buf_addr + data_off;
    unsigned char hdrbuf[96];
    if (read_user(hdrbuf, (void *)(unsigned long)data_ptr, sizeof(hdrbuf)) < 0) return 0;

    __u16 ether_type = ((__u16)hdrbuf[12] << 8) | hdrbuf[13];
    __u32 l3_off = ETH_HLEN;
    if (ether_type == ETHERTYPE_VLAN) {
        if (pkt_len < l3_off + VLAN_HLEN) return 0;
        ether_type = ((__u16)hdrbuf[l3_off + 2] << 8) | hdrbuf[l3_off + 3];
        l3_off += VLAN_HLEN;
    }
    if (ether_type != ETHERTYPE_IPV4) return 0;
    if (pkt_len < l3_off + IP_HLEN_MIN || l3_off + IP_HLEN_MIN > sizeof(hdrbuf)) return 0;
    unsigned char *ip = hdrbuf + l3_off;
    if ((ip[0] >> 4) != 4) return 0;
    __u8 ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IP_HLEN_MIN) return 0;
    __u16 frag = ((__u16)ip[6] << 8) | ip[7];
    if ((frag & IPV4_FRAG_MF) || (frag & IPV4_FRAG_MASK)) return 0;
    __u8 proto = ip[9];
    if (proto == 6 || proto == 17) {
        __u32 l4_off = l3_off + ihl;
        __u32 l4hdr = 8;
        if (proto == 6) {
            if (l4_off + 13 <= sizeof(hdrbuf)) l4hdr = ((hdrbuf[l4_off + 12] >> 4) & 0xf) * 4;
            else l4hdr = 20;
            if (l4hdr < 20) l4hdr = 20;
        }
        __u32 payload_off = l4_off + l4hdr;
        if (payload_off < pkt_len) {
            __u64 pl_ptr = data_ptr + payload_off;
            __u32 pl_len = pkt_len - payload_off;
            if (pl_len > 1460) pl_len = 1460;
            /* 완성형 CONTENT CANDIDATE GATE: only DNS(qd==1)/TLS-CH/HTTP shapes go to the provider. */
            unsigned char pl12[12];
            int cand = 0;
            if (pl_len >= 12 && read_user(pl12, (void *)(unsigned long)pl_ptr, 12) == 0) {
                __u16 qd = ((__u16)pl12[4] << 8) | pl12[5];
                if (proto == 17 && qd == 1) cand = 1;                  /* DNS-ish */
                else if (pl12[0] == 0x16 && pl12[5] == 0x01) cand = 1;  /* TLS ClientHello */
                else if (pl12[0] >= 'A' && pl12[0] <= 'Z') cand = 1;    /* HTTP request line */
            }
            if (cand) {
                b->item[idx].pl_ptr = pl_ptr;
                b->item[idx].pl_len = pl_len;
                c->l7_cand++;
            }
        }
    }
    return 0;
}

static __noinline int pkt_cb(__u32 idx, void *arg)
{
    struct pkt_iter_ctx *c = arg;
    if (idx >= (__u32)c->n) return 1;   /* stop */
    if (c->failed) return 1;
    if (idx >= 32) return 1;   /* compile-time-provable bound for the
                                 * c->mbuf_scratch->mbuf_ptrs[idx] access */

    /* Look up queue_stats locally so counter writes go to a map_value
     * (not the ctx stack).  The verifier marks map_value bytes "unknown"
     * after the first write and deduplicates state immediately, eliminating
     * per-iteration state explosion.  NULL check below guards every use. */
    /* queue_stats pointer is now hoisted to parse_and_apply() (done
     * ONCE per burst there, since c->qstats_key is constant across all
     * packets in the burst) and passed through via c->qs -- this
     * eliminates up to 32 redundant bpf_map_lookup_elem() calls per
     * burst that used to happen here (one per packet, always returning
     * the exact same map_value pointer). NULL check below still guards
     * every use, same as before. */
    struct queue_stats *qs = c->qs;

    __u64 mbuf_ptr = 0;
    if (c->mbuf_scratch) {
        /* batched fast path: pointer array was already pre-fetched once
         * in parse_and_apply() -- no read_user() call needed here. */
        mbuf_ptr = c->mbuf_scratch->mbuf_ptrs[idx];
    } else {
        /* rare fallback: per-thread scratch slot couldn't be allocated
         * (map full) -- read this one pointer directly, same as before
         * the batching optimization. */
        if (read_user(&mbuf_ptr,
                      (void *)(unsigned long)(c->ptr_base + (__u64)idx * 8), 8) < 0) {
            c->failed = 1; return 0;
        }
    }
    if (!mbuf_ptr) { c->failed = 1; return 0; }
    int drop_this = 0;

    /* Batch-read buf_addr/data_off/pkt_len: 3 separate read_user() calls
     * collapsed into 1. mbuf_off_* are runtime-injected (RCFG), so each is
     * clamped to a compile-time-provable bound before indexing the local
     * buffer. */
    unsigned char meta[48];
    if (read_user(meta, (void *)(unsigned long)mbuf_ptr, sizeof(meta)) < 0) {
        c->failed = 1; goto packet_done;
    }

    __u32 off_ba = RCFG.mbuf_off_buf_addr;
    __u32 off_do = RCFG.mbuf_off_data_off;
    __u32 off_pl = RCFG.mbuf_off_pkt_len;
    if (off_ba > sizeof(meta) - 8) off_ba = 0;
    if (off_do > sizeof(meta) - 2) off_do = 16;
    if (off_pl > sizeof(meta) - 4) off_pl = 36;

    __u64 buf_addr = 0;
    __u16 data_off = 0;
    __u32 pkt_len  = 0;
    __builtin_memcpy(&buf_addr, meta + off_ba, 8);
    __builtin_memcpy(&data_off, meta + off_do, 2);
    __builtin_memcpy(&pkt_len,  meta + off_pl, 4);

    if (!buf_addr || pkt_len < ETH_HLEN) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        goto packet_done;
    }

    /* Batch-read ethernet+VLAN+IP+L4 header region in ONE read_user() call
     * (was up to 4 separate reads). Sized to cover the worst case: 18B
     * (eth+vlan) + 60B (max IHL) + 4B (L4 ports) = 82B, plus margin. */
    __u64 data_ptr = buf_addr + data_off;
    unsigned char hdrbuf[96];
    if (read_user(hdrbuf, (void *)(unsigned long)data_ptr, sizeof(hdrbuf)) < 0) {
        if (qs) qs->parse_fail++;
        goto packet_done;
    }

    __u16 ether_type = ((__u16)hdrbuf[12] << 8) | hdrbuf[13];
    __u32 l3_off = ETH_HLEN;
    if (ether_type == ETHERTYPE_VLAN) {
        if ((RCFG.features & FEAT_VLAN_COUNT) && qs) qs->vlan_seen++;
        if (pkt_len < l3_off + VLAN_HLEN) {
            if (RCFG.features & FEAT_MALFORMED_DROP) {
                if (qs) { qs->malformed_drop++; qs->drop++; }
                if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
                if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
            }
            goto packet_done;
        }
        ether_type = ((__u16)hdrbuf[l3_off + 2] << 8) | hdrbuf[l3_off + 3];
        l3_off += VLAN_HLEN;
    }
    if (ether_type != ETHERTYPE_IPV4) goto packet_done;

    if (pkt_len < l3_off + IP_HLEN_MIN || l3_off + IP_HLEN_MIN > sizeof(hdrbuf)) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        goto packet_done;
    }

    unsigned char *ip = hdrbuf + l3_off;

    if ((ip[0] >> 4) != 4) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        goto packet_done;
    }

    __u8 ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IP_HLEN_MIN) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        goto packet_done;
    }

    __u16 frag = ((__u16)ip[6] << 8) | ip[7];
    if ((frag & IPV4_FRAG_MF) || (frag & IPV4_FRAG_MASK)) {
        if (RCFG.features & FEAT_FRAGMENT_DROP) {
            if (qs) { qs->frag_drop++; qs->drop++; }
            if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        goto packet_done;
    }

    __u8  proto = ip[9];
    /* network byte order (matches loader's inet_pton storage) */
    __u32 sip = 0, dip = 0;
    __builtin_memcpy(&sip, ip + 12, 4);
    __builtin_memcpy(&dip, ip + 16, 4);
    __u16 sport = 0, dport = 0;
    if (proto == 6 || proto == 17) {
        __u32 l4_off = l3_off + ihl;
        if (l4_off + 4 <= sizeof(hdrbuf)) {
            unsigned char *l4 = hdrbuf + l4_off;
            sport = ((__u16)l4[0] << 8) | l4[1];
            dport = ((__u16)l4[2] << 8) | l4[3];
        }
    }

    __u32 action = lookup_action(c->cgroup_id, proto, dport,
                                 ((__u64)sport << 32) | sip, dip);
    if (qs) qs->policy_hits++;

    /* --- L7 payload inspection via Hyperscan ufunc (batch read) --- */
    if ((proto == 6 || proto == 17) && action != ACT_KILL) {
        __u32 l4_off = l3_off + ihl;
        __u32 l4hdr = 8;
        if (proto == 6) {
            if (l4_off + 13 <= sizeof(hdrbuf)) l4hdr = ((hdrbuf[l4_off + 12] >> 4) & 0xf) * 4;
            else l4hdr = 20;
            if (l4hdr < 20) l4hdr = 20;
        }
        __u32 payload_off = l4_off + l4hdr;
        if (payload_off < pkt_len) {
            __u32 m = (c->batch && idx < 128) ? (__u32)c->batch->item[idx].act : 255u;
            if (m != 255u) { action = (__u32)m; if ((m==2||m==3) && qs) qs->drop++; }
        }
    }

    if (idx == 0) {
        c->out_sip   = sip;
        c->out_dip   = dip;
        c->out_sp    = sport;
        c->out_dp    = dport;
        c->out_proto = proto;
    }

    if (action == ACT_KILL) {
        if (RCFG.features & FEAT_ENFORCEMENT) {
            /* bpftime has no in-VM signal helper (bpf_send_signal is a
             * kernel-only helper); comm_loader performs the actual
             * kill(pid, SIGKILL) in userspace when it receives this
             * event via comm_events (see handle_event() in
             * comm_loader.c). */
            if (c->out_worst < ACT_KILL) c->out_worst = ACT_KILL;
        }
    } else if (action == ACT_DROP) {
        if (c->is_rx) drop_this = !!(RCFG.features & FEAT_ENFORCEMENT); else nullify_mbuf(mbuf_ptr);
        if (qs) qs->drop++;
        if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
    } else {
        if (qs) qs->allow++;
    }

packet_done:
    if (c->is_rx && c->mbuf_scratch && !c->failed) {
        if (drop_this) {
            if (c->dropped < 32)
                c->mbuf_scratch->dropped_ptrs[c->dropped++] = mbuf_ptr;
            else c->failed = 1;
        } else {
            __u64 dst = c->ptr_base + (__u64)c->kept * 8;
            if (c->kept != idx &&
                bpf_probe_write_user((void *)(unsigned long)dst,
                                     &mbuf_ptr, sizeof(mbuf_ptr)) < 0)
                c->failed = 1;
            else c->kept++;
        }
    }
    return 0;
}

/* 출력 인자를 구조체로 묶어 BPF __noinline 5-arg 제한 우회 */
struct parse_result {
    __u32 sip;
    __u32 dip;
    __u32 worst;
    __u16 sp;
    __u16 dp;
    __u8  proto;
    __u8  failed;
    __u16 kept;
    __u16 dropped;
};

static __always_inline __u16
parse_and_apply(__u64 ptr_base, __u16 n, __u64 cgroup_id,
                __u32 qs_key, struct parse_result *res, __u8 is_rx)
{
    struct pkt_iter_ctx ctx = {};
    ctx.ptr_base   = ptr_base;
    ctx.n          = n;
    ctx.cgroup_id  = cgroup_id;
    ctx.qstats_key = qs_key;
    ctx.out_worst  = ACT_ALLOW;
    ctx.is_rx = is_rx;

    /* Batch-fetch the burst's mbuf pointer array in ONE read_user() call
     * instead of one 8-byte read per packet inside pkt_cb() (was up to 32
     * separate process_vm_readv syscalls per burst; now exactly 1). The
     * 256-byte array lives in this thread's pkt_scratch_map slot, not on
     * the stack (see struct pkt_scratch above). */
    __u32 z = 0;                       /* OPT(mcopt): PERCPU_ARRAY slot 0 */
    struct pkt_scratch *scratch = bpf_map_lookup_elem(&pkt_scratch_map, &z);
    if (!scratch) {
        bpf_map_update_elem(&pkt_scratch_map, &z, &g_zero_scratch, BPF_ANY);
        scratch = bpf_map_lookup_elem(&pkt_scratch_map, &z);
    }
    if (scratch) {
        __u32 fetch_n = (__u32)n;
        if (fetch_n > 128) fetch_n = 128;
        if (fetch_n)
            if (read_user(scratch->mbuf_ptrs, (void *)(unsigned long)ptr_base,
                          fetch_n * 8) < 0) ctx.failed = 1;
    }
    if (is_rx && (!scratch || n > 128)) ctx.failed = 1;
    ctx.mbuf_scratch = scratch;   /* NULL only if the map slot couldn't be
                                    * allocated -- pkt_cb() then falls back
                                    * to a direct per-packet read_user() */

    /* Snapshot qs->drop before the loop; per-burst drop count is the
     * delta after bpf_loop (pkt_cb writes directly to the map_value). */
    struct queue_stats *qs = bpf_map_lookup_elem(&queue_stats, &qs_key);
    __u64 drop_before = qs ? qs->drop : 0;
    ctx.qs = qs;  /* let pkt_cb() reuse this instead of re-looking-up */

    /* bpftime has no bpf_loop() helper -- unroll a bounded loop instead.
     * pkt_cb()'s own `if (idx >= c->n) return 1;` guard makes this safe
     * for any n <= 32 (matches the kernel path's bpf_loop(32, pkt_cb, ...)
     * cap, so both paths inspect the same up-to-32 packets per burst). */
    /* Manually unrolled -- #pragma unroll / #pragma clang loop
     * unroll(full) both failed to actually unroll this loop on
     * this toolchain (build warning: loop not unrolled), leaving
     * a real backward-branch loop that bpftime's verifier could
     * not load. A literal unrolled sequence has no backward
     * branch at all, sidestepping the issue entirely. */
    {
        /* L7 BATCH (완성형): content-gate prescan; call ufunc ONLY if a candidate exists */
        {
            __u32 bz = 0;
            struct hs_batch *hb = bpf_map_lookup_elem(&hs_batch_map, &bz);
            ctx.batch = hb;
            ctx.l7_cand = 0;
            if (hb) {
                pkt_prescan(0,&ctx);pkt_prescan(1,&ctx);pkt_prescan(2,&ctx);pkt_prescan(3,&ctx);pkt_prescan(4,&ctx);pkt_prescan(5,&ctx);pkt_prescan(6,&ctx);pkt_prescan(7,&ctx);pkt_prescan(8,&ctx);pkt_prescan(9,&ctx);pkt_prescan(10,&ctx);pkt_prescan(11,&ctx);pkt_prescan(12,&ctx);pkt_prescan(13,&ctx);pkt_prescan(14,&ctx);pkt_prescan(15,&ctx);pkt_prescan(16,&ctx);pkt_prescan(17,&ctx);pkt_prescan(18,&ctx);pkt_prescan(19,&ctx);pkt_prescan(20,&ctx);pkt_prescan(21,&ctx);pkt_prescan(22,&ctx);pkt_prescan(23,&ctx);pkt_prescan(24,&ctx);pkt_prescan(25,&ctx);pkt_prescan(26,&ctx);pkt_prescan(27,&ctx);pkt_prescan(28,&ctx);pkt_prescan(29,&ctx);pkt_prescan(30,&ctx);pkt_prescan(31,&ctx);pkt_prescan(32,&ctx);pkt_prescan(33,&ctx);pkt_prescan(34,&ctx);pkt_prescan(35,&ctx);pkt_prescan(36,&ctx);pkt_prescan(37,&ctx);pkt_prescan(38,&ctx);pkt_prescan(39,&ctx);pkt_prescan(40,&ctx);pkt_prescan(41,&ctx);pkt_prescan(42,&ctx);pkt_prescan(43,&ctx);pkt_prescan(44,&ctx);pkt_prescan(45,&ctx);pkt_prescan(46,&ctx);pkt_prescan(47,&ctx);pkt_prescan(48,&ctx);pkt_prescan(49,&ctx);pkt_prescan(50,&ctx);pkt_prescan(51,&ctx);pkt_prescan(52,&ctx);pkt_prescan(53,&ctx);pkt_prescan(54,&ctx);pkt_prescan(55,&ctx);pkt_prescan(56,&ctx);pkt_prescan(57,&ctx);pkt_prescan(58,&ctx);pkt_prescan(59,&ctx);pkt_prescan(60,&ctx);pkt_prescan(61,&ctx);pkt_prescan(62,&ctx);pkt_prescan(63,&ctx);pkt_prescan(64,&ctx);pkt_prescan(65,&ctx);pkt_prescan(66,&ctx);pkt_prescan(67,&ctx);pkt_prescan(68,&ctx);pkt_prescan(69,&ctx);pkt_prescan(70,&ctx);pkt_prescan(71,&ctx);pkt_prescan(72,&ctx);pkt_prescan(73,&ctx);pkt_prescan(74,&ctx);pkt_prescan(75,&ctx);pkt_prescan(76,&ctx);pkt_prescan(77,&ctx);pkt_prescan(78,&ctx);pkt_prescan(79,&ctx);pkt_prescan(80,&ctx);pkt_prescan(81,&ctx);pkt_prescan(82,&ctx);pkt_prescan(83,&ctx);pkt_prescan(84,&ctx);pkt_prescan(85,&ctx);pkt_prescan(86,&ctx);pkt_prescan(87,&ctx);pkt_prescan(88,&ctx);pkt_prescan(89,&ctx);pkt_prescan(90,&ctx);pkt_prescan(91,&ctx);pkt_prescan(92,&ctx);pkt_prescan(93,&ctx);pkt_prescan(94,&ctx);pkt_prescan(95,&ctx);pkt_prescan(96,&ctx);pkt_prescan(97,&ctx);pkt_prescan(98,&ctx);pkt_prescan(99,&ctx);pkt_prescan(100,&ctx);pkt_prescan(101,&ctx);pkt_prescan(102,&ctx);pkt_prescan(103,&ctx);pkt_prescan(104,&ctx);pkt_prescan(105,&ctx);pkt_prescan(106,&ctx);pkt_prescan(107,&ctx);pkt_prescan(108,&ctx);pkt_prescan(109,&ctx);pkt_prescan(110,&ctx);pkt_prescan(111,&ctx);pkt_prescan(112,&ctx);pkt_prescan(113,&ctx);pkt_prescan(114,&ctx);pkt_prescan(115,&ctx);pkt_prescan(116,&ctx);pkt_prescan(117,&ctx);pkt_prescan(118,&ctx);pkt_prescan(119,&ctx);pkt_prescan(120,&ctx);pkt_prescan(121,&ctx);pkt_prescan(122,&ctx);pkt_prescan(123,&ctx);pkt_prescan(124,&ctx);pkt_prescan(125,&ctx);pkt_prescan(126,&ctx);pkt_prescan(127,&ctx);
                if (ctx.l7_cand > 0) {
                    volatile char bn[13];
                    bn[0]='g';bn[1]='o';bn[2]='w';bn[3]='n';bn[4]='_';bn[5]='h';bn[6]='s';bn[7]='_';bn[8]='s';bn[9]='c';bn[10]='a';bn[11]='n';bn[12]=0;
                    long bhid = ufunc_find_func_id((const char *)bn);
                    if (bhid >= 0) UFUNC_CALL_2(bhid, (__u64)(unsigned long)&hb->item[0], (__u64)(n < 128 ? n : 128));
                }
            }
        }
        if (pkt_cb(0, &ctx)) goto pkt_loop_done;
        if (pkt_cb(1, &ctx)) goto pkt_loop_done;
        if (pkt_cb(2, &ctx)) goto pkt_loop_done;
        if (pkt_cb(3, &ctx)) goto pkt_loop_done;
        if (pkt_cb(4, &ctx)) goto pkt_loop_done;
        if (pkt_cb(5, &ctx)) goto pkt_loop_done;
        if (pkt_cb(6, &ctx)) goto pkt_loop_done;
        if (pkt_cb(7, &ctx)) goto pkt_loop_done;
        if (pkt_cb(8, &ctx)) goto pkt_loop_done;
        if (pkt_cb(9, &ctx)) goto pkt_loop_done;
        if (pkt_cb(10, &ctx)) goto pkt_loop_done;
        if (pkt_cb(11, &ctx)) goto pkt_loop_done;
        if (pkt_cb(12, &ctx)) goto pkt_loop_done;
        if (pkt_cb(13, &ctx)) goto pkt_loop_done;
        if (pkt_cb(14, &ctx)) goto pkt_loop_done;
        if (pkt_cb(15, &ctx)) goto pkt_loop_done;
        if (pkt_cb(16, &ctx)) goto pkt_loop_done;
        if (pkt_cb(17, &ctx)) goto pkt_loop_done;
        if (pkt_cb(18, &ctx)) goto pkt_loop_done;
        if (pkt_cb(19, &ctx)) goto pkt_loop_done;
        if (pkt_cb(20, &ctx)) goto pkt_loop_done;
        if (pkt_cb(21, &ctx)) goto pkt_loop_done;
        if (pkt_cb(22, &ctx)) goto pkt_loop_done;
        if (pkt_cb(23, &ctx)) goto pkt_loop_done;
        if (pkt_cb(24, &ctx)) goto pkt_loop_done;
        if (pkt_cb(25, &ctx)) goto pkt_loop_done;
        if (pkt_cb(26, &ctx)) goto pkt_loop_done;
        if (pkt_cb(27, &ctx)) goto pkt_loop_done;
        if (pkt_cb(28, &ctx)) goto pkt_loop_done;
        if (pkt_cb(29, &ctx)) goto pkt_loop_done;
        if (pkt_cb(30, &ctx)) goto pkt_loop_done;
        if (pkt_cb(31, &ctx)) goto pkt_loop_done;
        if (pkt_cb(32, &ctx)) goto pkt_loop_done;
        if (pkt_cb(33, &ctx)) goto pkt_loop_done;
        if (pkt_cb(34, &ctx)) goto pkt_loop_done;
        if (pkt_cb(35, &ctx)) goto pkt_loop_done;
        if (pkt_cb(36, &ctx)) goto pkt_loop_done;
        if (pkt_cb(37, &ctx)) goto pkt_loop_done;
        if (pkt_cb(38, &ctx)) goto pkt_loop_done;
        if (pkt_cb(39, &ctx)) goto pkt_loop_done;
        if (pkt_cb(40, &ctx)) goto pkt_loop_done;
        if (pkt_cb(41, &ctx)) goto pkt_loop_done;
        if (pkt_cb(42, &ctx)) goto pkt_loop_done;
        if (pkt_cb(43, &ctx)) goto pkt_loop_done;
        if (pkt_cb(44, &ctx)) goto pkt_loop_done;
        if (pkt_cb(45, &ctx)) goto pkt_loop_done;
        if (pkt_cb(46, &ctx)) goto pkt_loop_done;
        if (pkt_cb(47, &ctx)) goto pkt_loop_done;
        if (pkt_cb(48, &ctx)) goto pkt_loop_done;
        if (pkt_cb(49, &ctx)) goto pkt_loop_done;
        if (pkt_cb(50, &ctx)) goto pkt_loop_done;
        if (pkt_cb(51, &ctx)) goto pkt_loop_done;
        if (pkt_cb(52, &ctx)) goto pkt_loop_done;
        if (pkt_cb(53, &ctx)) goto pkt_loop_done;
        if (pkt_cb(54, &ctx)) goto pkt_loop_done;
        if (pkt_cb(55, &ctx)) goto pkt_loop_done;
        if (pkt_cb(56, &ctx)) goto pkt_loop_done;
        if (pkt_cb(57, &ctx)) goto pkt_loop_done;
        if (pkt_cb(58, &ctx)) goto pkt_loop_done;
        if (pkt_cb(59, &ctx)) goto pkt_loop_done;
        if (pkt_cb(60, &ctx)) goto pkt_loop_done;
        if (pkt_cb(61, &ctx)) goto pkt_loop_done;
        if (pkt_cb(62, &ctx)) goto pkt_loop_done;
        if (pkt_cb(63, &ctx)) goto pkt_loop_done;
        if (pkt_cb(64, &ctx)) goto pkt_loop_done;
        if (pkt_cb(65, &ctx)) goto pkt_loop_done;
        if (pkt_cb(66, &ctx)) goto pkt_loop_done;
        if (pkt_cb(67, &ctx)) goto pkt_loop_done;
        if (pkt_cb(68, &ctx)) goto pkt_loop_done;
        if (pkt_cb(69, &ctx)) goto pkt_loop_done;
        if (pkt_cb(70, &ctx)) goto pkt_loop_done;
        if (pkt_cb(71, &ctx)) goto pkt_loop_done;
        if (pkt_cb(72, &ctx)) goto pkt_loop_done;
        if (pkt_cb(73, &ctx)) goto pkt_loop_done;
        if (pkt_cb(74, &ctx)) goto pkt_loop_done;
        if (pkt_cb(75, &ctx)) goto pkt_loop_done;
        if (pkt_cb(76, &ctx)) goto pkt_loop_done;
        if (pkt_cb(77, &ctx)) goto pkt_loop_done;
        if (pkt_cb(78, &ctx)) goto pkt_loop_done;
        if (pkt_cb(79, &ctx)) goto pkt_loop_done;
        if (pkt_cb(80, &ctx)) goto pkt_loop_done;
        if (pkt_cb(81, &ctx)) goto pkt_loop_done;
        if (pkt_cb(82, &ctx)) goto pkt_loop_done;
        if (pkt_cb(83, &ctx)) goto pkt_loop_done;
        if (pkt_cb(84, &ctx)) goto pkt_loop_done;
        if (pkt_cb(85, &ctx)) goto pkt_loop_done;
        if (pkt_cb(86, &ctx)) goto pkt_loop_done;
        if (pkt_cb(87, &ctx)) goto pkt_loop_done;
        if (pkt_cb(88, &ctx)) goto pkt_loop_done;
        if (pkt_cb(89, &ctx)) goto pkt_loop_done;
        if (pkt_cb(90, &ctx)) goto pkt_loop_done;
        if (pkt_cb(91, &ctx)) goto pkt_loop_done;
        if (pkt_cb(92, &ctx)) goto pkt_loop_done;
        if (pkt_cb(93, &ctx)) goto pkt_loop_done;
        if (pkt_cb(94, &ctx)) goto pkt_loop_done;
        if (pkt_cb(95, &ctx)) goto pkt_loop_done;
        if (pkt_cb(96, &ctx)) goto pkt_loop_done;
        if (pkt_cb(97, &ctx)) goto pkt_loop_done;
        if (pkt_cb(98, &ctx)) goto pkt_loop_done;
        if (pkt_cb(99, &ctx)) goto pkt_loop_done;
        if (pkt_cb(100, &ctx)) goto pkt_loop_done;
        if (pkt_cb(101, &ctx)) goto pkt_loop_done;
        if (pkt_cb(102, &ctx)) goto pkt_loop_done;
        if (pkt_cb(103, &ctx)) goto pkt_loop_done;
        if (pkt_cb(104, &ctx)) goto pkt_loop_done;
        if (pkt_cb(105, &ctx)) goto pkt_loop_done;
        if (pkt_cb(106, &ctx)) goto pkt_loop_done;
        if (pkt_cb(107, &ctx)) goto pkt_loop_done;
        if (pkt_cb(108, &ctx)) goto pkt_loop_done;
        if (pkt_cb(109, &ctx)) goto pkt_loop_done;
        if (pkt_cb(110, &ctx)) goto pkt_loop_done;
        if (pkt_cb(111, &ctx)) goto pkt_loop_done;
        if (pkt_cb(112, &ctx)) goto pkt_loop_done;
        if (pkt_cb(113, &ctx)) goto pkt_loop_done;
        if (pkt_cb(114, &ctx)) goto pkt_loop_done;
        if (pkt_cb(115, &ctx)) goto pkt_loop_done;
        if (pkt_cb(116, &ctx)) goto pkt_loop_done;
        if (pkt_cb(117, &ctx)) goto pkt_loop_done;
        if (pkt_cb(118, &ctx)) goto pkt_loop_done;
        if (pkt_cb(119, &ctx)) goto pkt_loop_done;
        if (pkt_cb(120, &ctx)) goto pkt_loop_done;
        if (pkt_cb(121, &ctx)) goto pkt_loop_done;
        if (pkt_cb(122, &ctx)) goto pkt_loop_done;
        if (pkt_cb(123, &ctx)) goto pkt_loop_done;
        if (pkt_cb(124, &ctx)) goto pkt_loop_done;
        if (pkt_cb(125, &ctx)) goto pkt_loop_done;
        if (pkt_cb(126, &ctx)) goto pkt_loop_done;
        if (pkt_cb(127, &ctx)) goto pkt_loop_done;
    }
    pkt_loop_done: ;

    /* pkt_cb already wrote all counters to qs — no flush needed */

    res->sip   = ctx.out_sip;
    res->dip   = ctx.out_dip;
    res->sp    = ctx.out_sp;
    res->dp    = ctx.out_dp;
    res->proto = ctx.out_proto;
    res->worst = ctx.out_worst;
    res->failed = ctx.failed;
    res->kept = ctx.kept;
    res->dropped = ctx.dropped;

    return qs ? (__u16)(qs->drop - drop_before) : 0;
}


/* ── [API level] RX programs removed ────────────────────────────────
 * rte_eth_rx_burst() is always static inline → never emits a symbol →
 * uprobe never fires in practice. Driver-level hooks cover all cases.
 * Removed to stay within BPF verifier 1M-instruction limit.
 * ─────────────────────────────────────────────────────────────────── */
#if 0
/* ── [API level] uprobe: rte_eth_rx_burst (entry) ───────────────── */
SEC("uprobe/rte_eth_rx_burst")
int BPF_UPROBE(uprobe_rx_burst,
               unsigned short port_id,
               unsigned short queue_id,
               void **rx_pkts,
               unsigned short nb_pkts)
{
    if (!RCFG.enabled) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rxburst_args a = {};
    a.rx_pkts_ptr = (__u64)(unsigned long)rx_pkts;
    a.ts_entry    = bpf_ktime_get_ns();
    a.port_id     = port_id;
    a.queue_id    = queue_id;
    a.nb_pkts     = nb_pkts;
    bpf_map_update_elem(&rxburst_pending, &tid, &a, BPF_ANY);
    return 0;
}

/* ── [API level] uretprobe: rte_eth_rx_burst (exit) ─────────────── */
SEC("uretprobe/rte_eth_rx_burst")
int BPF_URETPROBE(uretprobe_rx_burst, unsigned short ret)
{
    if (!RCFG.enabled) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rxburst_args *a = bpf_map_lookup_elem(&rxburst_pending, &tid);
    if (!a) return 0;

    __u16 n = ret;
    struct queue_stats *qs = qstats(a->port_id, a->queue_id);
    if (qs) qs->rx += n;

    if (n == 0) {
        record_latency(bpf_ktime_get_ns() - a->ts_entry);
        bpf_map_delete_elem(&rxburst_pending, &tid);
        return 0;
    }

    __u16 cap = RCFG.max_burst_inspect;
    if (cap > 128) cap = 128;
    if (n > cap) n = cap;

    __u32 pid_hi = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 cg_id  = RCFG.tenant_cgroup_id;
    struct parse_result pr = {};

    __u16 drops = parse_and_apply(a->rx_pkts_ptr, n, cg_id, qs, &pr);

    /* NOTE (fixed): this used to double-count into qs->tx, which the
     * TX driver uprobe (uprobe_tx_burst_drv) already increments for
     * real outgoing bursts (qs->tx += nb_pkts). RX-side packets that
     * pass inspection are not re-added here anymore -- qs->tx now
     * reflects only actual TX-hook traffic, no RX contribution. */

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, a->port_id, a->queue_id,
                  ret, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                   pr.proto, (__u8)pr.worst, 1);

    record_latency(bpf_ktime_get_ns() - a->ts_entry);
    bpf_map_delete_elem(&rxburst_pending, &tid);
    return 0;
}
#endif  /* API-level RX disabled */

/* ── [Driver level] uprobe: RX driver (entry) ───────────────────── */
#if 1  /* RX driver-level uprobe enabled. Historical disable note follows.
 * DPDK busy-polls rx_burst at ~300k+ calls/sec even with zero traffic (empty
 * polls). Under sustained load this uprobe/uretprobe pair fires millions of
 * times, and bpftime/Frida's userspace interception cannot sustain this
 * invocation rate without crashing deep in its own runtime (confirmed via
 * gdb core analysis: SIGSEGV in anonymous JIT-generated memory, independent
 * of target binary, independent of core count, independent of ringbuf
 * pressure -- narrowed down to raw uprobe call frequency itself). TX-side
 * enforcement (below) is kept active since TX is called far less often
 * (roughly once per actual outgoing burst, not per idle poll). */
SEC("uprobe/rx_burst_drv")
int BPF_UPROBE(uprobe_rx_burst_drv,
               void *rxq,
               void **rx_pkts,
               unsigned short nb_pkts)
{
    if (!RCFG.enabled) return 0;
    __u32 z = 0;                       /* OPT(mcopt): PERCPU_ARRAY slot 0 */
    struct rxburst_drv_args a = {};
    a.rx_pkts_ptr = (__u64)(unsigned long)rx_pkts;
    a.ts_entry    = bpf_ktime_get_ns();
    a.nb_pkts     = nb_pkts;
    a.valid       = 1;
    bpf_map_update_elem(&rxburst_drv_pending, &z, &a, BPF_ANY);
    return 0;
}

/* ── [Driver level] uretprobe: RX driver (exit) ─────────────────── */
SEC("uretprobe/rx_burst_drv")
int BPF_URETPROBE(uretprobe_rx_burst_drv, unsigned short ret)
{
    if (!RCFG.enabled) return 0;
    __u32 z = 0;                       /* OPT(mcopt): PERCPU_ARRAY slot 0 */
    struct rxburst_drv_args *a = bpf_map_lookup_elem(&rxburst_drv_pending, &z);
    if (!a || !a->valid) return 0;     /* no matching enter on this CPU */

    __u16 n = ret;
    struct queue_stats *qs = qstats(0, 0);
    if (qs) qs->rx += n;

    __u32 pid_hi = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 cg_id  = RCFG.tenant_cgroup_id;
    struct parse_result pr = {};

    if (n == 0) {
        /* RX starvation 감지: zero-return burst */
        if (qs) {
            qs->rx_zero_burst++;
            /* 연속 100회 이상이면 vuln_event 방출 */
            if ((qs->rx_zero_burst % 10000000) == 0)
                emit_vuln(ctx, pid_hi, 0, cg_id, 0, 0,
                          VULN_RX_STARVATION, (__u32)qs->rx_zero_burst);
        }
        record_latency(bpf_ktime_get_ns() - a->ts_entry);
        a->valid = 0;                  /* OPT(mcopt): PERCPU_ARRAY has no delete */
        return 0;
    }

    __u16 cap = RCFG.max_burst_inspect;
    if (cap > 128) cap = 128;
    if (n > cap) n = cap;

    __u32 qsk = qkey(0, 0);
    __u16 drops = parse_and_apply(a->rx_pkts_ptr, n, cg_id, qsk, &pr, 1);
    if (ret > n) pr.failed = 1;
    if (pr.failed && (RCFG.features & FEAT_ENFORCEMENT)) {
        bpf_set_retval(0);
        pr.worst = ACT_KILL;
    }
    if (!pr.failed && pr.dropped) {
        struct pkt_scratch *scratch = bpf_map_lookup_elem(&pkt_scratch_map, &z);
        if (scratch) {
            volatile char free_name[22];
            free_name[0]='r'; free_name[1]='t'; free_name[2]='e';
            free_name[3]='_'; free_name[4]='p'; free_name[5]='k';
            free_name[6]='t'; free_name[7]='m'; free_name[8]='b';
            free_name[9]='u'; free_name[10]='f'; free_name[11]='_';
            free_name[12]='f'; free_name[13]='r'; free_name[14]='e';
            free_name[15]='e'; free_name[16]='_'; free_name[17]='b';
            free_name[18]='u'; free_name[19]='l'; free_name[20]='k';
            free_name[21]=0;
            long id = ufunc_find_func_id((const char *)free_name);
            if (id >= 0) {
                if (bpf_set_retval(pr.kept) == 0)
                    UFUNC_CALL_2(id, scratch->dropped_ptrs, pr.dropped);
                else pr.worst = ACT_KILL;
            } else {
                bpf_set_retval(0);
                pr.worst = ACT_KILL;
            }
        }
    }


    /* NOTE (fixed): this used to double-count into qs->tx, which the
     * TX driver uprobe (uprobe_tx_burst_drv) already increments for
     * real outgoing bursts (qs->tx += nb_pkts). RX-side packets that
     * pass inspection are not re-added here anymore -- qs->tx now
     * reflects only actual TX-hook traffic, no RX contribution. */

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, 0, 0,
                  ret, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                   pr.proto, (__u8)pr.worst, 1);

    record_latency(bpf_ktime_get_ns() - a->ts_entry);
    a->valid = 0;                      /* OPT(mcopt): PERCPU_ARRAY has no delete */
    return 0;
}

/* ── [Driver level] uprobe: TX driver (entry) ───────────────────── */
#endif  /* RX driver-level uprobe disabled -- see note above */

SEC("uprobe/tx_burst_drv")
int BPF_UPROBE(uprobe_tx_burst,
               void *txq,
               void **tx_pkts,
               unsigned short nb_pkts)
{
    if (!RCFG.enabled) return 0;

    __u64 ptr_base = (__u64)(unsigned long)tx_pkts;
    __u16 n = nb_pkts;
    __u16 cap = RCFG.max_burst_inspect;
    if (cap > 128) cap = 128;
    if (n > cap) n = cap;

    __u32 pid_hi = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 cg_id  = RCFG.tenant_cgroup_id;
    struct queue_stats *qs = qstats(0, 0);
    if (qs) qs->tx += nb_pkts;

    struct parse_result pr = {};
    __u32 qsk = qkey(0, 0);
    __u16 drops = parse_and_apply(ptr_base, n, cg_id, qsk, &pr, 0);

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, 0, 0,
                  nb_pkts, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                   pr.proto, (__u8)pr.worst, 2);

    /* TX pending 저장: uretprobe에서 drop 탐지에 사용 */
    __u32 z2 = 0;                      /* OPT(mcopt): PERCPU_ARRAY slot 0 */
    struct txburst_drv_args ta = {};
    ta.nb_pkts  = nb_pkts;
    ta.ts_entry = bpf_ktime_get_ns();
    ta.valid    = 1;
    bpf_map_update_elem(&txburst_drv_pending, &z2, &ta, BPF_ANY);

    return 0;
}

/* ── [Driver level] uretprobe: TX driver (exit) — TX drop 탐지 ──── */
SEC("uretprobe/tx_burst_drv")
int BPF_URETPROBE(uretprobe_tx_burst, unsigned short ret)
{
    if (!RCFG.enabled) return 0;
    __u32 z = 0;                       /* OPT(mcopt): PERCPU_ARRAY slot 0 */
    struct txburst_drv_args *a = bpf_map_lookup_elem(&txburst_drv_pending, &z);
    if (!a || !a->valid) return 0;     /* no matching enter on this CPU */

    __u16 nb_requested = a->nb_pkts;
    record_tx_latency(bpf_ktime_get_ns() - a->ts_entry);
    a->valid = 0;                      /* OPT(mcopt): PERCPU_ARRAY has no delete */

    if (ret < nb_requested) {
        /* TX drop: sent < requested */
        __u16 dropped = nb_requested - ret;
        __u32 pid_hi  = (__u32)(bpf_get_current_pid_tgid() >> 32);
        __u64 cg_id   = RCFG.tenant_cgroup_id;
        struct queue_stats *qs = qstats(0, 0);
        if (qs) qs->tx_drop += dropped;
        emit_vuln(ctx, pid_hi, 0, cg_id, 0, 0,
                  VULN_TX_DROP, (__u32)dropped);
    }
    return 0;
}

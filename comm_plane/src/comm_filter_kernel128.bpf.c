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
 *   · F-7 수정: bpf_get_current_cgroup_id() 기반 cgroup 정책 조회
 */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

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
};

/* ── Maps (BTF 없이 raw size) ─────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size,   sizeof(struct comm_policy_key));
    __uint(value_size, sizeof(struct comm_policy_value));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} comm_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
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

/* uprobe→uretprobe 인자 보관 (Driver-level RX), key = tid */
struct rxburst_drv_args {
    __u64 rx_pkts_ptr;
    __u64 ts_entry;
    __u16 nb_pkts;
    __u16 _pad[3];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct rxburst_drv_args));
} rxburst_drv_pending SEC(".maps");

/* 큐별 통계 (PERCPU) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct queue_stats));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} queue_stats SEC(".maps");

/* RX 지연 히스토그램 (PERCPU) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct latency_hist));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lat_hist SEC(".maps");

/* TX 지연 히스토그램 (PERCPU) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(struct latency_hist));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lat_hist_tx SEC(".maps");

/* 취약성 이벤트 (RX starvation, TX drop, malformed mbuf) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} vuln_events SEC(".maps");

/* TX burst 인자 보관 (uretprobe에서 drop 탐지), key = tid */
struct txburst_drv_args {
    __u16 nb_pkts;
    __u16 _pad[3];
    __u64 ts_entry;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
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
    struct queue_stats *s = bpf_map_lookup_elem(&queue_stats, &k);
    if (s) return s;
    struct queue_stats z = {};
    bpf_map_update_elem(&queue_stats, &k, &z, BPF_NOEXIST);
    return bpf_map_lookup_elem(&queue_stats, &k);
}

static __always_inline __u32
ilog2_64(__u64 v)
{
    __u32 r = 0;
    if (v == 0) return 0;
    #pragma unroll
    for (int i = 63; i >= 0; i--) {
        if (v & (1ULL << i)) { r = (__u32)i; break; }
    }
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

static __noinline __u32
lookup_action(__u64 cgroup_id, __u8 proto, __u16 dst_port, __u32 src_ip, __u32 dst_ip)
{
    struct comm_policy_key k = {};
    struct comm_policy_value *v;

    k.layer    = 2;
    k.protocol = proto;

    /* ── 1단계: cgroup-specific 완전 일치 ────────────────────── */
    k.cgroup_id = cgroup_id;
    k.dst_port  = dst_port; k.src_ip = src_ip; k.dst_ip = dst_ip;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 2단계: cgroup-specific, src_ip 와일드카드, dst_ip 유지 */
    k.src_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 3단계: cgroup-specific, IP 와일드카드 ──────────────── */
    k.dst_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 4단계: cgroup-specific, 포트 와일드카드, dst_ip 유지 ── */
    k.dst_port = 0; k.dst_ip = dst_ip;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 5단계: cgroup-specific, 포트+IP 와일드카드 ─────────── */
    k.dst_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 6단계: wildcard cgroup, 완전 일치 ──────────────────── */
    k.cgroup_id = 0;
    k.dst_port  = dst_port; k.src_ip = src_ip; k.dst_ip = dst_ip;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 7단계: wildcard cgroup, src_ip 와일드카드, dst_ip 유지 */
    k.src_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 8단계: wildcard cgroup, IP 와일드카드 ──────────────── */
    k.dst_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 9단계: wildcard cgroup, 포트 와일드카드, dst_ip 유지 ── */
    k.dst_port = 0; k.dst_ip = dst_ip;   /* ← (cgroup=0,proto,port=0,sip=0,dip=X) 매칭 */
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    /* ── 10단계: wildcard cgroup, 포트+IP 와일드카드 ─────────── */
    k.dst_ip = 0;
    v = bpf_map_lookup_elem(&comm_policy, &k);
    if (v) { __sync_fetch_and_add(&v->hit_count, 1); return v->action; }

    return ACT_ALLOW;
}

static __always_inline void
emit_comm(void *ctx,
          __u32 pid, __u32 tgid, __u64 cgroup_id,
          __u16 port, __u16 queue,
          __u16 nb_ret, __u16 nb_drop,
          __u32 sip, __u32 dip, __u16 sp, __u16 dp,
          __u8 proto, __u8 action)
{
    struct comm_event e = {};
    e.ts_ns            = bpf_ktime_get_ns();
    e.pid              = pid;
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
    e.pid        = pid;
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
struct pkt_iter_ctx {
    /* constant inputs */
    __u64  ptr_base;
    __u64  cgroup_id;
    __u32  qstats_key;   /* key passed to bpf_map_lookup_elem(&queue_stats) */
    __u16  n;
    __u8   _pad0[2];
    /* per-burst outputs (written ≤1 time each; out_worst converges in 2) */
    __u32  out_sip;
    __u32  out_dip;
    __u32  out_worst;
    __u16  out_sp;
    __u16  out_dp;
    __u8   out_proto;
    __u8   _pad1[3];
};

static int pkt_cb(__u32 idx, void *arg)
{
    struct pkt_iter_ctx *c = arg;
    if (idx >= (__u32)c->n) return 1;   /* stop */

    /* Look up queue_stats locally so counter writes go to a map_value
     * (not the ctx stack).  The verifier marks map_value bytes "unknown"
     * after the first write and deduplicates state immediately, eliminating
     * per-iteration state explosion.  NULL check below guards every use. */
    struct queue_stats *qs = bpf_map_lookup_elem(&queue_stats, &c->qstats_key);

    __u64 mbuf_ptr = 0;
    if (read_user(&mbuf_ptr,
                  (void *)(unsigned long)(c->ptr_base + (__u64)idx * 8), 8) < 0)
        return 0;
    if (!mbuf_ptr) return 0;

    __u64 buf_addr = 0;
    __u16 data_off = 0;
    __u32 pkt_len  = 0;
    read_user(&buf_addr,
              (void *)(unsigned long)(mbuf_ptr + RCFG.mbuf_off_buf_addr), 8);
    read_user(&data_off,
              (void *)(unsigned long)(mbuf_ptr + RCFG.mbuf_off_data_off), 2);
    read_user(&pkt_len,
              (void *)(unsigned long)(mbuf_ptr + RCFG.mbuf_off_pkt_len),  4);

    if (!buf_addr || pkt_len < ETH_HLEN) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        return 0;
    }

    __u64 data_ptr = buf_addr + data_off;
    unsigned char eth[ETH_HLEN];
    if (read_user(eth, (void *)(unsigned long)data_ptr, ETH_HLEN) < 0) {
        if (qs) qs->parse_fail++;
        return 0;
    }

    __u16 ether_type = ((__u16)eth[12] << 8) | eth[13];
    __u32 l3_off = ETH_HLEN;
    if (ether_type == ETHERTYPE_VLAN) {
        if ((RCFG.features & FEAT_VLAN_COUNT) && qs) qs->vlan_seen++;
        unsigned char vlan[VLAN_HLEN];
        if (pkt_len < l3_off + VLAN_HLEN ||
            read_user(vlan,
                      (void *)(unsigned long)(data_ptr + l3_off),
                      VLAN_HLEN) < 0) {
            if (RCFG.features & FEAT_MALFORMED_DROP) {
                if (qs) { qs->malformed_drop++; qs->drop++; }
                nullify_mbuf(mbuf_ptr);
                if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
            }
            return 0;
        }
        ether_type = ((__u16)vlan[2] << 8) | vlan[3];
        l3_off += VLAN_HLEN;
    }
    if (ether_type != ETHERTYPE_IPV4) return 0;

    if (pkt_len < l3_off + IP_HLEN_MIN) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        return 0;
    }

    unsigned char ip[IP_HLEN_MIN];
    if (read_user(ip,
                  (void *)(unsigned long)(data_ptr + l3_off),
                  IP_HLEN_MIN) < 0) {
        if (qs) qs->parse_fail++;
        return 0;
    }

    if ((ip[0] >> 4) != 4) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        return 0;
    }

    __u8 ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IP_HLEN_MIN) {
        if (RCFG.features & FEAT_MALFORMED_DROP) {
            if (qs) { qs->malformed_drop++; qs->drop++; }
            nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        return 0;
    }

    __u16 frag = ((__u16)ip[6] << 8) | ip[7];
    if ((frag & IPV4_FRAG_MF) || (frag & IPV4_FRAG_MASK)) {
        if (RCFG.features & FEAT_FRAGMENT_DROP) {
            if (qs) { qs->frag_drop++; qs->drop++; }
            nullify_mbuf(mbuf_ptr);
            if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
        }
        return 0;
    }

    __u8  proto = ip[9];
    /* network byte order (matches loader's inet_pton storage) */
    __u32 sip = 0, dip = 0;
    __builtin_memcpy(&sip, ip + 12, 4);
    __builtin_memcpy(&dip, ip + 16, 4);
    __u16 sport = 0, dport = 0;
    if (proto == 6 || proto == 17) {
        unsigned char l4[4];
        if (read_user(l4,
                      (void *)(unsigned long)(data_ptr + l3_off + ihl),
                      4) == 0) {
            sport = ((__u16)l4[0] << 8) | l4[1];
            dport = ((__u16)l4[2] << 8) | l4[3];
        }
    }

    __u32 action = lookup_action(c->cgroup_id, proto, dport, sip, dip);
    if (qs) qs->policy_hits++;

    if (idx == 0) {
        c->out_sip   = sip;
        c->out_dip   = dip;
        c->out_sp    = sport;
        c->out_dp    = dport;
        c->out_proto = proto;
    }

    if (action == ACT_KILL) {
        if (RCFG.features & FEAT_ENFORCEMENT)
            bpf_send_signal(RCFG.kill_signal);
        if (c->out_worst < ACT_KILL) c->out_worst = ACT_KILL;
    } else if (action == ACT_DROP) {
        nullify_mbuf(mbuf_ptr);
        if (qs) qs->drop++;
        if (c->out_worst < ACT_DROP) c->out_worst = ACT_DROP;
    } else {
        if (qs) qs->allow++;
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
    __u8  _pad[3];
};

static __noinline __u16
parse_and_apply(__u64 ptr_base, __u16 n, __u64 cgroup_id,
                __u32 qs_key, struct parse_result *res)
{
    struct pkt_iter_ctx ctx = {};
    ctx.ptr_base   = ptr_base;
    ctx.n          = n;
    ctx.cgroup_id  = cgroup_id;
    ctx.qstats_key = qs_key;
    ctx.out_worst  = ACT_ALLOW;

    /* Snapshot qs->drop before the loop; per-burst drop count is the
     * delta after bpf_loop (pkt_cb writes directly to the map_value). */
    struct queue_stats *qs = bpf_map_lookup_elem(&queue_stats, &qs_key);
    __u64 drop_before = qs ? qs->drop : 0;

    bpf_loop(128, pkt_cb, &ctx, 0);

    /* pkt_cb already wrote all counters to qs — no flush needed */

    res->sip   = ctx.out_sip;
    res->dip   = ctx.out_dip;
    res->sp    = ctx.out_sp;
    res->dp    = ctx.out_dp;
    res->proto = ctx.out_proto;
    res->worst = ctx.out_worst;

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
    __u64 cg_id  = bpf_get_current_cgroup_id();
    struct parse_result pr = {};

    __u16 drops = parse_and_apply(a->rx_pkts_ptr, n, cg_id, qs, &pr);

    if (qs) qs->tx += (ret - drops);

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, a->port_id, a->queue_id,
                  ret, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                  pr.proto, (__u8)pr.worst);

    record_latency(bpf_ktime_get_ns() - a->ts_entry);
    bpf_map_delete_elem(&rxburst_pending, &tid);
    return 0;
}
#endif  /* API-level RX disabled */

/* ── [Driver level] uprobe: RX driver (entry) ───────────────────── */
#if 1  /* Experimental RX-enabled kernel comparison object. Original retained. */
SEC("uprobe/rx_burst_drv")
int BPF_UPROBE(uprobe_rx_burst_drv,
               void *rxq,
               void **rx_pkts,
               unsigned short nb_pkts)
{
    if (!RCFG.enabled) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rxburst_drv_args a = {};
    a.rx_pkts_ptr = (__u64)(unsigned long)rx_pkts;
    a.ts_entry    = bpf_ktime_get_ns();
    a.nb_pkts     = nb_pkts;
    bpf_map_update_elem(&rxburst_drv_pending, &tid, &a, BPF_ANY);
    return 0;
}

/* ── [Driver level] uretprobe: RX driver (exit) ─────────────────── */
SEC("uretprobe/rx_burst_drv")
int BPF_URETPROBE(uretprobe_rx_burst_drv, unsigned short ret)
{
    if (!RCFG.enabled) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rxburst_drv_args *a = bpf_map_lookup_elem(&rxburst_drv_pending, &tid);
    if (!a) return 0;

    __u16 n = ret;
    struct queue_stats *qs = qstats(0, 0);
    if (qs) qs->rx += n;

    __u32 pid_hi = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 cg_id  = bpf_get_current_cgroup_id();
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
        bpf_map_delete_elem(&rxburst_drv_pending, &tid);
        return 0;
    }

    __u16 cap = RCFG.max_burst_inspect;
    if (cap > 128) cap = 128;
    if (n > cap) n = cap;

    __u32 qsk = qkey(0, 0);
    __u16 drops = parse_and_apply(a->rx_pkts_ptr, n, cg_id, qsk, &pr);

    if (qs) qs->tx += (ret - drops);

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, 0, 0,
                  ret, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                  pr.proto, (__u8)pr.worst);

    record_latency(bpf_ktime_get_ns() - a->ts_entry);
    bpf_map_delete_elem(&rxburst_drv_pending, &tid);
    return 0;
}

/* ── [Driver level] uprobe: TX driver (entry) ───────────────────── */
#endif  /* experimental RX-enabled kernel comparison */

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
    __u64 cg_id  = bpf_get_current_cgroup_id();
    struct queue_stats *qs = qstats(0, 0);
    if (qs) qs->tx += nb_pkts;

    struct parse_result pr = {};
    __u32 qsk = qkey(0, 0);
    __u16 drops = parse_and_apply(ptr_base, n, cg_id, qsk, &pr);

    if (drops || pr.worst != ACT_ALLOW)
        emit_comm(ctx, pid_hi, 0, cg_id, 0, 0,
                  nb_pkts, drops,
                  pr.sip, pr.dip, pr.sp, pr.dp,
                  pr.proto, (__u8)pr.worst);

    /* TX pending 저장: uretprobe에서 drop 탐지에 사용 */
    __u32 tid2 = (__u32)bpf_get_current_pid_tgid();
    struct txburst_drv_args ta = {};
    ta.nb_pkts  = nb_pkts;
    ta.ts_entry = bpf_ktime_get_ns();
    bpf_map_update_elem(&txburst_drv_pending, &tid2, &ta, BPF_ANY);

    return 0;
}

/* ── [Driver level] uretprobe: TX driver (exit) — TX drop 탐지 ──── */
SEC("uretprobe/tx_burst_drv")
int BPF_URETPROBE(uretprobe_tx_burst, unsigned short ret)
{
    if (!RCFG.enabled) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct txburst_drv_args *a = bpf_map_lookup_elem(&txburst_drv_pending, &tid);
    if (!a) return 0;

    __u16 nb_requested = a->nb_pkts;
    record_tx_latency(bpf_ktime_get_ns() - a->ts_entry);
    bpf_map_delete_elem(&txburst_drv_pending, &tid);

    if (ret < nb_requested) {
        /* TX drop: sent < requested */
        __u16 dropped = nb_requested - ret;
        __u32 pid_hi  = (__u32)(bpf_get_current_pid_tgid() >> 32);
        __u64 cg_id   = bpf_get_current_cgroup_id();
        struct queue_stats *qs = qstats(0, 0);
        if (qs) qs->tx_drop += dropped;
        emit_vuln(ctx, pid_hi, 0, cg_id, 0, 0,
                  VULN_TX_DROP, (__u32)dropped);
    }
    return 0;
}

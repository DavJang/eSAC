// eSAC control-plane RATE limiter (THROTTLE): per-tenant token bucket on
// rte_flow_create/destroy/flush; over-rate -> bpf_override_return(NULL) so the
// expensive NIC control op is denied (not run). Includes res_policy/res_events/
// pid_res_stats maps so resource_loader enters its event loop and STAYS ALIVE
// (keeps the bpftime shm so the in-process agent can attach + run this BPF).
#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* policy (tunable) */
const volatile __u64 RATE_PER_SEC = 2;    /* sustained flow-ops/sec per tenant */
const volatile __u64 BURST        = 4;    /* bucket depth */

/* ---- maps resource_loader expects (presence keeps the loader alive) ---- */
struct rp_blob { __u8 b[256]; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct rp_blob); } pid_res_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, __u32); __type(value, struct rp_blob); } res_policy SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } res_events SEC(".maps");

/* ---- our per-tenant rate state ---- */
struct rl_state { __u64 last_ns; __s64 tokens_milli; __u64 allowed; __u64 denied; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct rl_state); } flow_rl SEC(".maps");

static __always_inline int rate_gate(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();
    __u64 cap_milli = BURST * 1000;
    struct rl_state *s = bpf_map_lookup_elem(&flow_rl, &pid);
    if (!s) {
        struct rl_state init = {};
        init.last_ns = now; init.tokens_milli = (__s64)cap_milli - 1000; init.allowed = 1;
        bpf_map_update_elem(&flow_rl, &pid, &init, BPF_ANY);
        bpf_printk("FLOWRL ALLOW pid=%u first", pid);
        return 0;
    }
    __u64 dt_ns = now - s->last_ns;
    s->last_ns = now;
    s->tokens_milli += (__s64)((dt_ns * RATE_PER_SEC) / 1000000ULL);
    if (s->tokens_milli > (__s64)cap_milli) s->tokens_milli = (__s64)cap_milli;
    if (s->tokens_milli >= 1000) {
        s->tokens_milli -= 1000; s->allowed++;
        bpf_printk("FLOWRL ALLOW pid=%u allowed=%llu", pid, s->allowed);
        return 0;
    }
    s->denied++;
    bpf_printk("FLOWRL DENY pid=%u denied=%llu (rate-limit)", pid, s->denied);
    bpf_override_return(ctx, 0);   /* deny: rte_flow_create -> NULL */
    return 1;
}

SEC("uprobe/rte_flow_create")  int BPF_UPROBE(rl_flow_create)  { return rate_gate(ctx); }
SEC("uprobe/rte_flow_destroy") int BPF_UPROBE(rl_flow_destroy) { return rate_gate(ctx); }
SEC("uprobe/rte_flow_flush")   int BPF_UPROBE(rl_flow_flush)   { return rate_gate(ctx); }

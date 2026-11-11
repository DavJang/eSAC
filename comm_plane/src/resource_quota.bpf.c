// eSAC resource loader QUOTA-override BPF: per-call byte ceiling on the allocating EAL APIs
// (rte_malloc/rte_zmalloc/rte_memzone_reserve). A request above the ceiling is denied by
// bpf_override_return(NULL) so the real allocation never happens -- runtime BLOCK, not kill.
// Complements the launcher admission gate (which blocks over-sized requests visible at launch);
// this catches DYNAMIC over-allocation a running tenant issues after it was admitted.
// Includes the res_policy/res_events/pid_res_stats maps so resource_loader stays alive.
#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* policy (tunable at load; default 1 MiB per-call ceiling) */
const volatile __u64 MAX_ALLOC_BYTES = 1048576;

/* ---- maps resource_loader expects (presence keeps the loader alive) ---- */
struct rp_blob { __u8 b[256]; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct rp_blob); } pid_res_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, __u32); __type(value, struct rp_blob); } res_policy SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } res_events SEC(".maps");

/* ---- per-tenant allow/deny accounting ---- */
struct q_state { __u64 allowed; __u64 denied; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct q_state); } quota_stats SEC(".maps");

static __always_inline int quota_gate(void *ctx, __u64 size)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct q_state *s = bpf_map_lookup_elem(&quota_stats, &pid);
    if (MAX_ALLOC_BYTES && size > MAX_ALLOC_BYTES) {
        if (s) { s->denied++; }
        else { struct q_state i = {}; i.denied = 1; bpf_map_update_elem(&quota_stats, &pid, &i, BPF_ANY); }
        bpf_override_return(ctx, 0);   /* return NULL: the allocation is blocked */
        return 1;
    }
    if (s) { s->allowed++; }
    else { struct q_state i = {}; i.allowed = 1; bpf_map_update_elem(&quota_stats, &pid, &i, BPF_ANY); }
    return 0;
}

/* rte_malloc(type, size, align) / rte_zmalloc(type, size, align): size is the 2nd arg */
SEC("uprobe/rte_malloc")  int BPF_UPROBE(q_rte_malloc,  const char *type, __u64 size, __u32 align) { return quota_gate(ctx, size); }
SEC("uprobe/rte_zmalloc") int BPF_UPROBE(q_rte_zmalloc, const char *type, __u64 size, __u32 align) { return quota_gate(ctx, size); }
/* rte_memzone_reserve(name, len, socket_id, flags): len is the 2nd arg */
SEC("uprobe/rte_memzone_reserve") int BPF_UPROBE(q_memzone_reserve, const char *name, __u64 len, int socket_id, unsigned int flags) { return quota_gate(ctx, len); }

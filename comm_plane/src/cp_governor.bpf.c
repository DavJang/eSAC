// eSAC control-plane GOVERNOR (throttle), ONE-SHOT variant.
// Per (tenant pid, hooked API address): the FIRST call is ALLOWED (the legit
// setup call), every subsequent call is DENIED via bpf_override_return -> the
// control API becomes set-once from the tenant; afterwards only the host can
// change it (host paths are not hooked). mem_quota_ptr keeps the count quota.
#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 MEM_QUOTA = 8;   /* max shared-mem allocations per tenant */

/* per-(pid, api-ip) one-shot: value = times seen */
struct osk { __u32 pid; __u32 _pad; __u64 ip; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
         __type(key, struct osk); __type(value, __u64); } one_shot SEC(".maps");

struct mq { __u64 count; __u64 denied; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct mq); } mem_state SEC(".maps");

/* returns 1 if this (pid,ip) was already used (caller overrides), 0 if first */
static __always_inline int used_already(__u64 ip)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct osk k = {}; k.pid = pid; k.ip = ip;
    __u64 *seen = bpf_map_lookup_elem(&one_shot, &k);
    if (!seen) {
        __u64 one = 1; bpf_map_update_elem(&one_shot, &k, &one, BPF_ANY);
        bpf_printk("CPGOV ALLOW(first) pid=%u ip=%llx", pid, ip);
        return 0;
    }
    (*seen)++;
    bpf_printk("CPGOV DENY(oneshot) pid=%u ip=%llx seen=%llu", pid, ip, *seen);
    return 1;
}

SEC("uprobe/cp_rate_ptr")
int BPF_UPROBE(cp_rate_ptr) { if (used_already(PT_REGS_IP(ctx))) bpf_override_return(ctx, 0); return 0; }

SEC("uprobe/cp_rate_int")
int BPF_UPROBE(cp_rate_int) { if (used_already(PT_REGS_IP(ctx))) bpf_override_return(ctx, (__u64)(-11)); return 0; } /* -EAGAIN */

SEC("uprobe/mem_quota_ptr")
int BPF_UPROBE(mem_quota_ptr)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct mq *m = bpf_map_lookup_elem(&mem_state, &pid);
    if (!m) { struct mq i = {}; i.count = 1; bpf_map_update_elem(&mem_state, &pid, &i, BPF_ANY);
              bpf_printk("MEMGOV ALLOW pid=%u count=1", pid); return 0; }
    if (m->count >= MEM_QUOTA) { m->denied++;
        bpf_printk("MEMGOV DENY(quota) pid=%u over=%llu", pid, MEM_QUOTA);
        bpf_override_return(ctx, 0); return 0; }
    m->count++;
    bpf_printk("MEMGOV ALLOW pid=%u count=%llu", pid, m->count);
    return 0;
}

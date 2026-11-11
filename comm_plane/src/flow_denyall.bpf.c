#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";
SEC("uprobe/rte_flow_create")
int BPF_UPROBE(rl_flow_create) { bpf_printk("FLOWRL DENYALL fired\n"); bpf_override_return(ctx, 0); return 0; }

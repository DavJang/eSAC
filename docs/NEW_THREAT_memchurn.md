# eSAC threat model: prof's NIC-resource churn + NEW host-hugepage churn (both measured)

Two distinct cross-tenant threats where a tenant holding NET-ZERO extra resource degrades
co-located tenants by *how often it drives a shared resource* — invisible to per-VF caps and to
HOLD/quota→SIGKILL gates. Both blocked by the in-process governor (bpftime uprobe + bpf_override_return).

| | ① Prof's part — shared NIC firmware/steering churn | ② NEW — shared host hugepage-pool churn |
|---|---|---|
| **시나리오** | Under saturation (~14.4 Mpps), attacker repeatedly calls a port-config API on its OWN VF. Each call makes the NIC firmware rebuild steering/flow-tables that the packet pipeline consults for ALL VFs → co-located victim's datapath stalls while victim cores stay idle. Attacker holds net-zero (add+del / on+off / restart). | Attacker loops `rte_malloc(64MB)`+touch+`rte_free` on its own VF/process. Large blocks grow/shrink the DPDK heap → kernel mmap/munmap of hugepages on the SHARED node0 pool (page zeroing + `hugetlb_lock`). A co-located victim doing its own hugepage allocation (startup / pool growth) stalls. Attacker holds net-zero (frees every iter). |
| **API** | `rte_flow_create` / `rte_flow_destroy`; `rte_eth_dev_stop` / `rte_eth_dev_start` (port restart); `rte_eth_promiscuous_enable` / `_disable`; `rte_eth_dev_set_mc_addr_list` | `rte_malloc` / `rte_free` (same path: `rte_zmalloc`, `rte_memzone_reserve`, `rte_pktmbuf_pool_create`) |
| **피해 수치** (mlx5 ConnectX-6) | victim RTT baseline p50 32 / p99 39 µs → **port restart @10/s: p50 95 / p99 102 (2.6×, p50 3.0×)**; **mcast @2/s: p99 115 (2.9×)**; flow/promisc @10/s ≈1.3×. Victim cores idle (contention inside NIC). | victim hugepage-alloc baseline p50 101.5 / p99 143 / p999 181 µs → **attack: p50 115 / p99 290 (2.03×) / p999 433 (2.40×) / max 606 (2.5×)**. node0 free oscillates 26–32 pages (=52–64 MB) = kernel-level churn proof; attacker ~31 alloc/s, net-zero held. |
| **막는 매커니즘** | Governor one-shot / token-bucket rate-limit on the control API (bpftime uprobe + `bpf_override_return`): denies BEFORE reaching shared firmware. **Verified:** `thr2` flow_churn OK=6/NULL=14 @2/s; `gov_oneshot` all 4 APIs → -11/NULL, init survives (first dev_start allowed). | Governor token-bucket rate-limit on `rte_malloc` (bpftime uprobe + `bpf_override_return`=NULL). **Verified:** attacker burst 4 ALLOW → 14,015,144 DENY → node0 oscillation **0** → victim p99 **146 µs (1.02× baseline = fully recovered)**. |

Why HOLD/quota→SIGKILL (the already-used resource-plane threat) does NOT cover either: both
attackers hold net-zero at all times, so a quota/count gate sees nothing to cap or kill. The harm
is RATE (how often the shared resource is driven), not QUANTITY — only a rate governor stops it.

Evidence dirs (on nss-worker):
- ① FINAL/results/motiv_sat_1794239713/ (harm), thr2_1793985680/ + gov_oneshot_1794224417/ (defense)
- ② FINAL/results/memchurn_1794289132/ (harm+defense, this run); harness FINAL/harness/resource/memthreat.sh + hp_probe.c + mem_churn.c

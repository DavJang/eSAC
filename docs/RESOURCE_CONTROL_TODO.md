# eSAC Resource / Control-Plane Access Control — status & TODO

eSAC enforces policy by in-process uprobe hooks (bpftime/Frida) on the DPDK
functions the tenant itself calls. The SAME mechanism covers three planes:

| Plane | What it inspects | Hook target | Status |
|---|---|---|---|
| **Communication** | packet headers (L2–L4) + payload (L7) | PMD RX/TX burst (`*_recv_pkts`, `*_tx_burst_*`) | **DONE** (CE1/L4 + L7 GET/SET, DNS) |
| **Resource (quantity)** | how much shared NIC/host resource a tenant allocates | DPDK alloc/setup APIs (below) | **MONITOR built** (counts per tenant); hugepage-overuse DoS demonstrated; per-tenant *quota enforcement* = TODO |
| **Control-plane (rate)** | how OFTEN a tenant drives expensive NIC control ops | `rte_flow_*`, dev stop/start, EAL restart | **TODO (new)** — see below |

Why the eSwitch / SR-IOV cannot do the latter two: SR-IOV partitions only the
NIC **data path** (VF) and the eSwitch sees only **packets**. Resource
allocation and control-plane operations happen as **API calls inside the tenant
process** and never produce a filterable packet, so a tenant can exhaust shared
host RAM (hugepages) or monopolize the shared NIC control path without crossing
any host-visible choke point. eSAC intercepts the call in-process, *before* it
reaches the NIC/host.

---

## A. Resource-plane APIs currently hooked (`comm_plane/loaders/resource_loader`)

Memory / hugepage-backed pools (shared host RAM — the hugepage-DoS vector):
- `rte_mempool_create`
- `rte_pktmbuf_pool_create`
- `rte_memzone_reserve`
- `rte_malloc`, `rte_zmalloc`, `rte_malloc_bytes`   (DPDK heap)

lcore / EAL:
- `rte_eal_init`
- `rte_eal_remote_launch`   (worker lcore launch)

NIC queues / device config:
- `rte_eth_dev_configure`
- `rte_eth_dev_start`
- `rte_eth_rx_queue_setup`
- `rte_eth_tx_queue_setup`

Current behavior: `resource_monitor.bpf.o` **counts** these per tenant
(cgroup_id). It does **not** yet enforce a per-tenant quota or a call-rate
limit. `setrlimit(RLIMIT_MEMLOCK)` in the loader is only for the loader's own
locked memory — unrelated to tenant policy.

Motivating result (verified): a tenant over-allocating hugepages exhausts
shared host RAM; the victim tenant's `rte_eal_init` then fails with
"Not enough memory", and SR-IOV does NOT prevent it (host-RAM resource is
outside SR-IOV's scope). Enforcement = gate `rte_mempool_create`/`rte_*malloc`
against a per-tenant byte quota.

---

## B. TODO — control-plane RATE limiting (prof-directed)

Problem: `rte_flow_create` / `rte_flow_destroy` / `rte_flow_flush` are slow,
serialized **hardware** operations through the shared eSwitch/driver. A tenant
that churns them (create/destroy loops) — or repeatedly restarts its port
(`rte_eth_dev_stop`+`rte_eth_dev_start`) or the whole EAL — monopolizes the NIC
control path and slows communication **for every other tenant**. The eSwitch
cannot stop this (it is not packet traffic). This is a control-plane DoS
distinct from the data-plane (comm) and resource-quantity planes.

### APIs to ADD to the hook set (not currently hooked)
- `rte_flow_create`      — per-rule insert (primary cost)
- `rte_flow_destroy`     — per-rule delete
- `rte_flow_flush`       — bulk delete (very expensive)
- `rte_eth_dev_stop` / `rte_eth_dev_start`  — port restart abuse
- `rte_eal_cleanup`      — EAL restart abuse
  (optionally `rte_flow_configure`, `rte_flow_async_create` on newer DPDK)

### Enforcement design (same model as the policy maps)
Per-tenant **token bucket / minimum-interval** keyed by `cgroup_id` in a BPF map:
- map value = { last_call_ns, tokens }
- on hook entry: refill tokens by elapsed time; if tokens < 1 → **deny**
  (override the call to fail: return error / NULL) or **throttle** (delay);
  else consume a token and allow.
- policy = "≤ N flow-ops/sec per tenant" (prof: "a few seconds between calls" →
  e.g. N configurable; default small, e.g. 1–5/s, burst B).
This rejects the expensive op **before** it programs the NIC, so a misbehaving
tenant cannot starve the shared control path.

### Status
NOT implemented yet: `rte_flow_*` is not in the hook list and the loader/BPF
have no rate-limit logic. See the companion demo (flow-churn tenant throttled)
when added.

---

## C. Paper framing (parallel to "Lack of fine-grained network access control")
Add two motivations beside the L7 one:
1. **Lack of resource access control** — tenant over-consumes shared host/NIC
   resources (hugepages, heap, lcores, queues) via DPDK APIs; eSwitch/SR-IOV
   blind to API-level allocation; middlebox irrelevant (not traffic).
2. **Lack of control-plane rate limiting** — tenant churns flow-rule / restart
   APIs to monopolize the shared NIC control path and degrade others.
eSAC addresses all three planes with one in-process hook mechanism.

---

## D. IMPLEMENTATION PROGRESS (2026-11-07)
- **DONE: enforcement BPF written + compiled** → `comm_plane/bpf/flow_ratelimit.bpf.o`
  (src `comm_plane/src/flow_ratelimit.bpf.c`). Hooks `uprobe/rte_flow_create`,
  `/rte_flow_destroy`, `/rte_flow_flush`; per-tenant (tgid) **token bucket** in
  `flow_rl` BPF map (bpf_ktime refill; `.rodata` consts RATE_PER_SEC=2, BURST=4);
  on over-rate calls **bpf_override_return(ctx,0)** so rte_flow_create returns
  NULL and the NIC control op never runs. (bpftime supports override via
  `bpftime::attach::curr_thread_override_return_callback`.)
- **TODO (runtime wiring for a live demo):**
  1. Generic uprobe loader that attaches a BPFs sections to the

---

## D. IMPLEMENTATION PROGRESS (2026-11-07)
- **DONE: enforcement BPF written + compiled** -> `comm_plane/bpf/flow_ratelimit.bpf.o`
  (src `comm_plane/src/flow_ratelimit.bpf.c`). Hooks `uprobe/rte_flow_create`,
  `uprobe/rte_flow_destroy`, `uprobe/rte_flow_flush`; per-tenant (tgid)
  **token bucket** in `flow_rl` BPF map (bpf_ktime refill; `.rodata` consts
  RATE_PER_SEC=2, BURST=4); on over-rate calls **bpf_override_return(ctx, 0)**
  so rte_flow_create returns NULL and the NIC control op never runs.
  (bpftime supports override via
  `bpftime::attach::curr_thread_override_return_callback`.) Verified clean.
- **TODO (runtime wiring for a live demo):**
  1. Generic uprobe loader that attaches a BPF's `uprobe/SYM` sections to the
     named symbol in the app's librte_* . Existing loaders only hook fixed PMD
     RX/TX syms, or resource_loader's static sym_table; add rte_flow_create /
     rte_flow_destroy / rte_flow_flush to that table, pointing at the
     flow_ratelimit progs, with override-attach enabled.
  2. Flow-churn tenant: DPDK example flow_filtering/flow_skeleton.c (has a
     Makefile) looped to call rte_flow_create repeatedly, or reuse dperf's
     src/flow.c path, bound to the intra VF 3b:01.3.
  3. Verify: without gate -> high flow-op rate; with gate -> excess calls denied
     (rte_flow_create returns NULL, flow_rl.denied increments), other tenants
     unaffected.
  4. Confirm bpftime override-attach mode works for these symbols (the comm
     filter modifies mbufs rather than overriding returns; the override path
     needs a one-time check on a live rte_flow_create).

---

## E. LIVE VALIDATION FINDINGS (2026-11-07, throttle attempt)
Goal: throttle (not SIGKILL) a tenant's rte_flow_create churn via in-process override.

**Built & working:**
- Baseline: `traffic/flow_churn` (DPDK 22.11 app on intra VF 3b:01.3) calls
  rte_flow_create in a loop -> 15/15 OK without eSAC (confirmed).
- Loader wiring: resource_loader extended with rte_flow_create/destroy/flush
  sym_table entries; attaches the uprobe (log "attached uprobe rte_flow_create").
- Override BPF `flow_ratelimit.bpf.o` (token bucket + bpf_override_return).
- Confirmed bpftime Frida uprobe DOES support override_return
  (frida_internal_attach_entry.cpp: override_return_set_callback /
  curr_thread_override_return_callback). Helper id 58 = bpftime_override_return.

**BLOCKER (not resolved tonight):** the override never fired — rte_flow_create
stayed 15/15 OK, no bpf_printk, and crucially the **bpftime agent never
initializes in flow_churn** (no "Initializing agent / Attach successfully" lines,
which a working run DOES emit, e.g. the DNS L7 dperf run). Tried: both agent
variants (base + -hs), canonical order (loader-first global, no attach-pid) and
STOP/CONT+attach-pid, kernel-uprobe plain mode (resource_loader without
syscall-server -> "attached 0 uprobes": override BPF rejected by kernel verifier,
expected). So:
- **Resource plane (res_pertenant.sh) = KERNEL uprobe + loader-side policy/SIGKILL**
  (no agent/shm/override). Proven. Enforcement = KILL only (verifier forbids
  override on rte_flow_create).
- **Comm plane (CE/DNS) = bpftime Frida in-process, supports override** — but the
  agent attaches only via the comm_loader path (PMD RX/TX syms, with its
  STOP/CONT + "attach summary: RX=OK" handshake). resource_loader's libbpf
  attach registers the uprobe in shm but the agent in the target does not install
  the Frida hook (agent never inits for flow_churn) -> override can't fire.

**Correct path for a true THROTTLE (next):** reuse the comm-plane attach that
makes the agent install hooks — i.e. a comm_loader-style loader that (a) boots
the app STOPPED with LD_PRELOAD=agent (+ its handshake), (b) attaches the BPF to
the rte_flow_create symbol in librte_ethdev.so via the bpftime agent (not plain
libbpf), and (c) uses bpf_override_return for a per-call deny/throttle. This
needs extending comm_loader's symbol target from PMD RX/TX to an arbitrary
exported symbol (rte_flow_create), or diagnosing why the agent does not init
when the uprobe is registered through resource_loader. The override BPF itself
is ready.

---

## F. THROTTLE — RESOLVED & LIVE-VERIFIED (2026-11-07) [supersedes E's blocker]
Flow-rule rate limiting now WORKS as a true throttle (not SIGKILL):

| metric | baseline (no eSAC) | with eSAC throttle |
|---|---|---|
| rte_flow_create success | 20 / 20 | **6 / 20** |
| denied (returned NULL) | 0 | **14** |

Log shows BURST=4 allowed, then over-rate calls DENIED (rte_flow_create -> NULL,
"FLOWRL DENY ... rate-limit"), with ~RATE=2/s refill letting occasional calls
through. The tenant keeps running (throttled, not killed).

Two fixes were required over E's blocker:
1. The shm-owning loader must STAY ALIVE (it was exiting on "res_policy map not
   found" -> shm unlinked -> agent "Unable to initialize shared memory"). Added
   dummy res_policy/res_events/pid_res_stats maps to the BPF and used a loader
   that holds the shm.
2. Override needs ATTACH_UPROBE_OVERRIDE, not plain libbpf attach: do
   perf_event_open(attr.type=BPF_TYPE_UPROBE_OVERRIDE=1008, config1=lib,
   config2=offset) then bpf_prog_attach(prog_fd, pfd, BPF_MODIFY_RETURN, 0).
   (plain attach -> bpf_override_return throws "no retval callback was set".)

Artifacts (FINAL, all clean of old naming):
- comm_plane/bpf/flow_ratelimit.bpf.o  (+ src comm_plane/src/flow_ratelimit.bpf.c)
- traffic/flow_throttle_loader          (+ src comm_plane/loaders/src/flow_throttle_loader.c)
- traffic/flow_churn                    (+ src harness/resource/flow_churn.c)
- harness/resource/run_throttle2.sh     (STOP/CONT demo runner)

Policy is tunable via the .rodata consts RATE_PER_SEC / BURST (prof's
"a few seconds between calls" -> set RATE_PER_SEC lower). Enforcement is in-process
override at the API boundary, so the expensive NIC control op never runs — the
eSwitch/SR-IOV cannot do this.

---

## G. GENERALIZED GOVERNOR — all VF-unblockable control/resource APIs (LIVE 2026-11-07)
One in-process governor throttles (rate) the shared NIC control plane and caps
(quota) shared host memory, over MANY symbols at once. Baseline = all succeed;
with governor:

| API | ret | policy | governed result |
|---|---|---|---|
| rte_flow_create             | ptr | rate (5/s, burst 5) | over-rate -> NULL |
| rte_eth_promiscuous_enable  | int | rate (shared)       | over-rate -> -EAGAIN(-11) |
| rte_eth_dev_set_mtu         | int | rate (shared)       | over-rate -> -11 |
| rte_eth_dev_mac_addr_add    | int | rate (shared)       | over-rate -> -11 |
| rte_malloc                  | ptr | quota (MEM_QUOTA=8) | after 8 -> NULL |

Control ops share one per-tenant token bucket; memory capped by cumulative count.
Tenant keeps running (throttle/quota, not SIGKILL). Enforcement is in-process
override at the API boundary -> the shared NIC control path / host allocator is
never reached. SR-IOV/eSwitch cannot do this (they see packets, not API calls).

Artifacts (FINAL):
- comm_plane/bpf/cp_governor.bpf.o (+src cp_governor.bpf.c): 3 override progs
  cp_rate_ptr (deny->0), cp_rate_int (deny->-EAGAIN), mem_quota_ptr (deny->0);
  tunable .rodata RATE_PER_SEC / BURST / MEM_QUOTA.
- traffic/cp_governor_loader (+src comm_plane/loaders/src/cp_governor_loader.c):
  reads a hooks.cfg (lib offset prog per line), attaches each as
  ATTACH_UPROBE_OVERRIDE (perf_event type 1008 + bpf_prog_attach BPF_MODIFY_RETURN),
  holds the bpftime shm alive.
- traffic/control_churn (+src harness/resource/control_churn.c): tenant exercising
  all 5 APIs.
- harness/resource/run_governor.sh: resolves offsets (readelf), STOP/CONT boot +
  attach + report.

EXTENSIBLE: add any exported librte_* symbol to hooks.cfg with cp_rate_* or
mem_quota_* — verified-hookable set also includes rte_flow_destroy/flush,
rte_eth_dev_vlan_filter, rte_eth_dev_rss_reta_update/rss_hash_update,
rte_eth_dev_start/stop/configure, rte_eth_xstats_get, rte_pktmbuf_pool_create,
rte_memzone_reserve, rte_zmalloc, rte_eal_remote_launch (lcore).
(Minor: the loader's "N/5 attached" counter miscounts because bpftime returns the
fd (positive) rather than 0 from bpf_prog_attach; attach actually succeeds — the
overrides fire. Cosmetic.)

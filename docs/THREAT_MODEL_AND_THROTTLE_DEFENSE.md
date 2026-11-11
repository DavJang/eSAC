# eSAC — Shared-Resource Threat Model & Throttle/Governor Defense (status: VERIFIED)

Updated 2026-11-10. Supersedes the "TODO" framing in `RESOURCE_CONTROL_TODO.md`:
the control-plane **rate limiter** and the resource **quota** are now **implemented
and live-verified** (evidence pointers below).

## 0. Framing — where SR-IOV fails and eSAC's throttle applies
SR-IOV isolates a VF's **private** resources (MAC/VLAN, Tx/Rx queues, and — verified —
a per-VF ~65536-entry flow table). It does **not** isolate resources shared **above**
the VF boundary, because those are touched by **API calls inside the tenant process**,
never by a filterable packet, so the eSwitch/SR-IOV are blind to them:
- the **shared mlx5 eSwitch steering/flow tables** (consulted by every VF's packet lookups),
- the **shared host hugepage pool** (all DPDK tenants allocate from it),
- the **shared, serialized NIC firmware control path**.

eSAC's governor hooks the DPDK control-API **in-process** (bpftime/Frida uprobe) and
denies the call with `bpf_override_return` **before** it reaches shared firmware/host RAM.
Two interchangeable policies, both compiled + verified:
- **one-shot** (`cp_governor.bpf.o`, active): per `(pid, API)` the 1st call is allowed
  (legit setup), every later call is denied → each control API becomes **set-once** per tenant.
- **token-bucket rate-limit** (`flow_ratelimit.bpf.o`, `cp_governor.bpf.c.bak-rate`):
  ≤ N ops/sec/tenant (keyed by pid/cgroup_id); the natural fit for the paper's *rate* axis
  (lets a legit app update rules slowly; throttles malicious churn).

---

## 1. Throttle-relevant threats (the governor's domain) — ALL BLOCKED + VERIFIED

| ID | Threat (shared resource it abuses) | SR-IOV covers? | Harm verified | Throttle defense | Defense verified |
|----|-------------------------------------|----------------|---------------|------------------|------------------|
| **T1** | **Shared eSwitch flow-table fill** — attacker `rte_flow_create` churn/hold fills the shared mlx5 steering table; co-located victim's datapath lookups fail → victim pps → **0**. Threshold is a **COUNT** (~700–1500 resident rules), not a rate. | NO (table is above the VF) | `motiv_flow2` (N=300/700 victim OK; N≥1500 → victim 100k→0) | one-shot on `rte_flow_create` → NULL after 1st; **or** `flow_ratelimit` token bucket | **YES** — `gov_oneshot_*` (flow=NULL all iters) **and** `thr2_*` on mlx5 (`flow_churn` 20 calls → **OK=6 / NULL=14** @2/s) |
| **T2** | **Shared hugepage exhaustion** — attacker `rte_malloc`/pool-create grabs host RAM; victim's `rte_eal_init` fails "Not enough memory". | NO (host RAM, outside SR-IOV) | `hugepage-overconsumption-dos` (hp_hold starves hp_victim) | `mem_quota_ptr` on `rte_malloc` (≤8 allocs/tenant) → NULL over quota | **YES** — `gov_oneshot_*`: `malloc=NULL` from the 9th alloc (`MEMGOV DENY(quota) over=8`) |
| **T3** | **Per-op control stall** (the *mechanism* behind T4) — each control op stalls the shared firmware: flow add/del ~**0.65 ms** HW, hugepage alloc ~**410 µs** (zeroing). | NO | `motiv_flowlat` (flat 0.65ms), `motiv_hplat` (410µs alloc / 7µs free) | defended via the T1/T4 hooks (fewer ops ⇒ fewer stalls) | — (mechanism) |
| **T4** | **Control-API call-RATE under saturation** — under ~14 Mpps load, an attacker churning `restart`/`promiscuous`/`mtu`/`mcast`/`flow` at rate R inflates **every** co-located VF's packet latency. Reproduces the paper's motivation. | NO (shared firmware/pipeline) | `motiv_saturation` (restart@10/s **p99 2.6×**, mcast **1.6–2.95×** at 14.4 Mpps); `motiv_sweep3` (full rate sweep) | one-shot (set-once) **or** rate-limit (≤5/s) on each churned API → churn rate → ~0 | **YES** — `gov_oneshot_*`: promiscuous/mtu/mac/vlan → **-11 (EAGAIN)** after 1st (19/20 denied); init survives (dev_start allowed once) |

Key point for the paper: **the harm (T4) requires pipeline saturation.** Unloaded, control-API
churn is harmless (earlier false-negative was an *unloaded* artifact). Loaded to ~14 Mpps,
the shared-firmware stall shows up as a 1.6–3× latency inflation on the victim — exactly the
professor's figure.

### Defense scope (honest)
The governor defends against a malicious **in-process DPDK tenant** — the paper's
co-located-tenant model. The *motivation* experiments drive the firmware stall cheaply from
kernel `ip`/`tc` as a **proxy** to produce the stall; the *defense* targets the in-process
DPDK call path and is **NIC-agnostic** (verified on 82599 `control_churn2` **and** mlx5
`flow_churn`). A kernel-root attacker on its own netdev is out of the in-process governor's
scope (and out of the DPDK tenant model).

---

## 2. Other threats considered — settled, reducible, or out of the throttle's novel scope

| ID | Candidate | Verdict |
|----|-----------|---------|
| **N2** | Per-VF **flow-install starvation** (attacker fills → victim can't install) | **NON-threat.** Each VF has its own ~65536-entry table; victim installs 600/600 even under attacker churn (`mlx5-flow-exhaust-pervf`). Not cross-tenant. |
| **N3** | NIC **command-interface** contention for install *success* | **NON-threat for install success** (`motiv_cmdif`: victim installs all rules under churn). Its datapath-latency effect is already counted in **T4**, not a separate blocking threat. |
| **R1** | **lcore over-allocation** (paper R1) | Out of NIC-governor scope. EAL `-l` is self-scoped; cross-tenant only if CPUs are oversubscribed → host **cpuset/admission gate**, not the governor. |
| **R3** | **mbuf / RX-pool starvation** (paper R3) | **Reduces to T2.** Each tenant has a *private* `pktmbuf` pool; pool memory draws from the shared hugepages → `mem_quota` already covers it. |
| **R4 / T7** | **Raw TX line-rate flooding** (paper R4) | Out of eSAC's *novel* scope. This is a **data-plane rate**, not a control-API call → covered by existing per-VF NIC QoS (`ip link set vf N rate` / mlx5 rate). eSAC's contribution is the control-plane contention QoS misses. (Confirmable with a per-VF rate cap if desired.) |
| **T8** | mlx5 flow **counter/meter pool** exhaustion | **Subsumed by T1** — counted/metered rules go through the same `rte_flow_create` hook. |

## 3. Comm-plane threats (separate eSAC plane, NOT the throttle)
Unauthorized packet injection / PID-scoped destination policy / VF abuse / **L7 unauthorized
comm over an allowed 5-tuple** are handled by the **comm plane** (L4 maskprobe HASH16384 +
L7 Hyperscan on PMD RX/TX), documented separately (`gown-final-version`). Listed here only so
the throttle's boundary is explicit.

---

## 4. Evidence index (all under `FINAL/results/`)
- T1 count threshold: `motiv_flow2_*`     |  per-op latency: `motiv_flowlat_*`, `motiv_hplat_*`
- T2 harm: hugepage DoS demo (hp_hold/hp_victim)  |  quota block: `gov_oneshot_1794224417/`
- T4 harm: `motiv_saturation_*`  |  full sweep: `motiv_sweep3_*`
- One-shot governor block (T1+T2+T4): `gov_oneshot_1794224417/` (RESULT.txt, churn.log)
- Rate-limit governor block (mlx5): `thr2_1793985680/` (OK=6/NULL=14 @2/s)
- One-shot on real f-stack redis (init survives hooks): `gov_redis_os_*`

Harnesses: `FINAL/harness/resource/{gov_oneshot,motiv_flow2,motiv_flowlat,motiv_hplat,
motiv_saturation,motiv_sweep3,run_throttle2}.sh`.
BPF: `FINAL/comm_plane/bpf/{cp_governor,flow_ratelimit}.bpf.o`
(src `FINAL/comm_plane/src/{cp_governor.bpf.c,cp_governor.bpf.c.bak-rate,flow_ratelimit.bpf.c}`).
Loaders: `FINAL/traffic/{cp_governor_loader,flow_throttle_loader}`.

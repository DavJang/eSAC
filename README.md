# eSAC — self-contained artifact

**eSAC** (eBPF-enforced Security Access Control for multi-tenant DPDK) is an
**in-process** security layer for DPDK tenants. From inside an *unmodified* DPDK
application, and with **no kernel transition on the packet path**, it enforces three
planes:

- **Communication control** — per-tenant **L4** (5-tuple, mask-probe hash, `cgroup_id`-keyed)
  and **L7** (DNS query name, Hyperscan) policy on the driver PMD RX/TX burst. Actions are
  **ALLOW / DROP**. The filter runs in userspace via **bpftime** (Frida-installed hooks +
  LLVM-JIT), so DPDK's poll-mode hot path is never trapped into the kernel.
- **Resource control (all-block)** — per-tenant quotas on 11 EAL/resource APIs, enforced by
  *blocking* rather than killing: the host **screens the request at admission** (over-quota ⇒
  never started) and **overrides** an over-quota runtime call to a failure value (`NULL`/`-EAGAIN`)
  so the allocation never happens. A **token-bucket throttle** rate-limits the shared NIC-control
  and hugepage APIs a tenant can *churn* (net-zero) to degrade co-located tenants
  (`rte_flow_create/destroy`, port restart, promiscuous toggle, multicast-list update,
  `rte_malloc`/`rte_free`). **Termination is only a backstop.**
- **Integrity** — the Frida-patched PMD prologue, JIT pages, and the whole policy table are
  mapped **read-only** in the tenant, and a root-owned **TamperSentinel** SIGKILLs the tenant on
  the only two syscalls that can restore write access: `mprotect(PROT_WRITE)` and
  `openat(/proc/self/mem)` (**2-vector**).

Enforcement is installed while the tenant is held **stopped** before its EAL/PMD begins polling,
then released — the **STOP/CONT start-gate** — so no packet flows until every hook and integrity
mechanism is in place (fail-closed). The tenant itself runs **unprivileged**: on mlx5 it needs
only **`CAP_NET_RAW`** plus the RDMA verbs devices (not full root), confined to a network
namespace holding just its VF; on the Intel 82599 it needs a `/dev/vfio` ACL.

This directory is a **self-contained copy** (no symlinks) of everything the paper's experiments
need; the rest of the working tree can be deleted and the experiments still run. The public
GitHub repo (`DavJang/eSAC`) carries a **source-only** snapshot (prebuilt binaries & heavy
third-party libs excluded — rebuild per *Git notes*).

> **Validated** on the real rig (Mellanox ConnectX-6 Dx 40 GbE, mlx5 switchdev VF-to-VF):
> L4/L7 ALLOW/DROP (RX **and** TX), resource admission/override/throttle, and the TamperSentinel
> kill all pass end-to-end from this tree — see **Validation**.

---

## Naming convention

The codebase evolved under several names; this tree uses one consistent vocabulary.

| Canonical (prose)            | identifier / filename form | older names it replaces                     |
|------------------------------|----------------------------|---------------------------------------------|
| **eSAC**                     | `esac`                     | eSAC, esac, GOWN                            |
| **TamperSentinel**           | `tamper_sentinel`          | tamper_sentinel, policy_tamper_sentinel, wd |
| **mask-probe optimization**  | `mask_probe` / `maskprobe` | opt3, probe-mask                            |
| **resource throttle**        | `resource_loader_rate`     | governor, throttler, cp_governor            |

Upstream identifiers are left untouched on purpose (renaming them would break binaries):
e.g. the bpftime env var `BPFTIME_GLOBAL_SHM_NAME` and the dperf histogram env vars
`ESAC_HIST_FILE` / `ESAC_HIST_START_SEC` (read by the prebuilt `traffic/dperf_hist`). BPF
program/section names (`rl_flow_create`, `q_rte_malloc`, `uprobe/rte_*`) are also fixed because
the loader hook configs resolve them by name.

---

## Enforcement model (how the three planes attach)

The host (root) is the trusted orchestrator; the tenant is the untrusted DPDK app in an
assigned VF. For every tenant the host:

1. **Admission** — screens the tenant's requested EAL resources (hugepage/socket-memory, lcores)
   against its quota; an over-quota launch is **refused** (`harness/resource/esac_admit.sh`). This
   also blocks an attacker that repeatedly re-spawns to hammer the EAL — rejected before acquiring
   any resource.
2. **Start it stopped** — the DPDK target is launched paused (`kill -STOP`) **before EAL
   initialization**, so no NIC queue is taken and no packet flows.
3. **Attach + harden** — the communication loader (under `libbpftime-syscall-server.so`) loads the
   filter, policy, and L7 DB into bpftime shared memory and registers the PMD RX/TX hooks; the
   tenant's `libbpftime-agent.so` installs the Frida hooks and JIT-runs the filter. The resource
   loader attaches the 11 EAL uprobes. The host then **read-only-maps** the hook code/policy/config
   and arms the **TamperSentinel**.
4. **Grant least privilege** — drop the tenant to an unprivileged account with only the NIC access
   it needs (`CAP_NET_RAW` + RDMA verbs on mlx5, or a `/dev/vfio` ACL on 82599), confined to a
   network namespace that holds only its VF.
5. **Release** — only after every mechanism reports ready is the tenant resumed (`kill -CONT`) and
   its traffic admitted.

This STOP/CONT ordering is the general **start-gate**: a tenant can communicate only after all
enforcement and integrity are in place.

---

## Layout

```
eSAC/
├── run_validation.sh         # one-command acceptance test (CE-L4 + fstack)
├── comm_plane/               # the eSAC enforcement planes
│   ├── loaders/              #   loaders (+ src/ for the C we own)
│   │   ├── comm_loader_cgroup            # L4/L7 loader (mask-probe, per-tenant cgroup_id), ixgbe syms
│   │   ├── comm_loader_cgroup_maskprobe  # mlx5 loader used by CE & fstack (4 RX + 42 TX variants)
│   │   ├── comm_loader_kernel128         # kernel-uprobe baseline loader (read-only, cannot drop)
│   │   ├── resource_loader               # resource quota loader (11 EAL uprobes, kill backstop)
│   │   └── resource_loader_rate          # resource override/throttle loader (bpftime override)
│   ├── bpf/                  #   eBPF objects
│   │   ├── comm_filter_maskprobe_16k.bpf.o   # L4 mask-probe filter (comm_policy/RCFG maps)
│   │   ├── comm_filter_*hs*.bpf.o            # L7 content-gate + Hyperscan ufunc filters
│   │   ├── resource_monitor.bpf.o            # resource quota monitor (object-only)
│   │   ├── resource_quota.bpf.o              # runtime quota override (NULL on over-limit)
│   │   └── resource_loader.bpf.o             # token-bucket churn throttle
│   └── offsets.json          #   mbuf field offsets (buf_addr/data_off/pkt_len/data_len)
├── agent/                    # bpftime in-process agent + syscall-server (Frida + LLVM-JIT + ufunc)
├── tamper_sentinel/          # TamperSentinel scripts (event.sh = 2-vector) + src + bin
├── l7/                       # L7 DNS/Hyperscan: ctl tools (shm DB), ufuncs, patterns, DNS payloads
├── policy/                   # policy generators (gen_policy_n/kern, mkdns)
├── apps/                     # real applications: f-stack redis-server, nginx (+ ff_redis configs)
├── traffic/                  # dperf traffic generators (static; base/burst128/hist/dns/probe)
├── suricata/                 # Suricata 7.0.7 baseline (bin + libhtp + rules + ips yaml)
├── lib/                      # runtime libs (fstack-dpdk, dpdk-24.11 build) for LD_LIBRARY_PATH
├── harness/                  # all experiment harnesses (paths rewritten to this tree)
│   ├── ce_l4/   CE3–CE7 L4 sweeps (interval/cc/payload/lcore/policy)
│   ├── l7/      CE8–CE11 L7 DNS (none / eSAC / Suricata)
│   ├── ie/      IE integrity: TamperSentinel kill latency + CPU
│   ├── pps/     throughput / replicated-median campaigns
│   ├── fstack/  real-app enforcement (STOP/CONT pre-attach)
│   ├── resource/ resource-plane: admission gate, override, churn throttle, threat demos
│   └── setup/   switchdev/VF bring-up, host2 helpers
├── secrets/                  # host2 SSH key — GITIGNORED, never commit
└── results/                  # run outputs — gitignored
```

> `agent/*.so`, `tamper_sentinel/bin/`, `traffic/dperf*`, `apps/*/redis-server|nginx`,
> `suricata/bin|lib`, and `lib/` are **prebuilt binaries / heavy third-party** — present in this
> local tree, **excluded from the GitHub source-only snapshot** (rebuild per *Git notes*).

---

## Components

eSAC ships as **eight deployed components across four planes** (paper Table). Each maps to real files in this tree. Filter actions are **ALLOW/DROP**; the resource plane is **all-block** (admission gate + runtime override + churn throttle, SIGKILL only as a backstop); the tamper sentinel is **2-vector** (`mprotect`, `openat`).

| Plane | Component | Role (execution woven in) | Files |
|---|---|---|---|
| **Policy/Map** | Policy configuration | Host-defined resource quotas + communication policy; feeds both loaders | `policy/` (gen_policy_n, gen_policy_kern, mkdns) |
| | bpftime maps | Tenant-shared `comm_policy`/`RCFG` read-only (cgroup_id-keyed) + writable stats | maps defined in `comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o` (runtime shm) |
| | L7 mmap | Per-tenant, host-owned `O_RDONLY` Hyperscan/domain DB scanned by the ufunc provider | `l7/ctl/` (esac_hs_ctl_bulk, esac_dom_ctl_bulk), `l7/ctl/esac_hs_ufunc.so` |
| **Resource Control** | Resource loader | Root host; resolves 11 EAL/resource APIs, attaches uprobes, loads the resource filter; screens requests at admission (pre-exec) | `comm_plane/loaders/resource_loader` (+`src/`), `harness/resource/esac_admit.sh` |
| | Resource filter | Blocks over-quota call by override (`NULL`/`-EAGAIN`); token-bucket throttle on control-API + hugepage churn; terminate as backstop | `comm_plane/bpf/resource_monitor.bpf.o` (quota), `resource_quota.bpf.o` (runtime override), `resource_loader.bpf.o` + `comm_plane/loaders/resource_loader_rate` (churn throttle) |
| **Communication Control** | Communication loader | Root-host syscall-server; loads object/policy/L7 DB; registers PID-scoped PMD RX/TX hooks (mlx5; ixgbe on 82599) | `comm_plane/loaders/comm_loader_cgroup_maskprobe` (mlx5), `comm_loader_cgroup` (ixgbe), `comm_loader_kernel128` (kernel-uprobe baseline) |
| | bpftime agent | In-tenant runtime hosting the hooks and filter; bundles **Frida listener** (RX/TX burst intercept) + **LLVM-JIT filter** (ALLOW/DROP) + **ufunc provider** (native Hyperscan L7 on the DNS query name) | `agent/libbpftime-agent.so` (+ `libbpftime-syscall-server.so`); filter `comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o` |
| **Integrity** | Tamper sentinel | Root-host per-PID; watches `mprotect(PROT_WRITE)` and `openat(/proc/self/mem)`, SIGKILL on either; RO-map performed by the loader | `tamper_sentinel/tamper_sentinel_event.sh` (2-vector) + `tamper_sentinel/bin/` |

**Not a component (orchestration):** the host launcher drives the fail-closed lifecycle — STOP/CONT start-gate, cgroup placement, NIC access grant (`CAP_NET_RAW`+RDMA verbs on mlx5, or a `/dev/vfio` ACL on 82599), and network-namespace confinement of the tenant — and invokes the eight components above (`harness/fstack/fstack_verify_stopcont.sh`, `harness/setup/intra_switchdev_up.sh`).

**Driver hooking note:** the PMD burst routine is chosen by the driver at device start from a large templated family, so the loader registers every variant and only the selected one runs — the mlx5 build registers **4 RX** variants and **all 42 `mlx5_tx_burst_*`** variants.

---

## Prerequisites (system state — NOT copyable, reproduce with setup scripts)

These live in the kernel/devices, not in files, so they are rebuilt by scripts here:

- **Hugepages**: node0 needs free 2 MB pages (≥ 2048 MB per DPDK process; 8-core runs want more).
- **PF1 switchdev + 2 VFs + tc hairpin** (intra fabric): `harness/setup/intra_switchdev_up.sh`
  (idempotent; echoes `INTRA_SVF`/`INTRA_CVF`). Needed by CE-intra and fstack. Persists until a
  reboot / driver reload / `sriov_numvfs=0`.
- **PF0 VF 3b:00.3** (inter fabric, host2): `harness/setup/host1_vf_prepare.sh`.
- **cgroup v2** mounted at `/sys/fs/cgroup` (per-tenant `cgroup_id` keying).
- **Tenant privilege**: mlx5 DPDK needs **`CAP_NET_RAW`** (not full root) plus access to the RDMA
  verbs devices (`/dev/infiniband/uverbs*`, world-rw here); the operator may confine the tenant to
  a network namespace holding only its VF. (82599 instead needs a `/dev/vfio` ACL.) The eSAC
  loaders/agent/sentinel themselves run as **root**.
- System libraries under `/usr/local/lib` and the kernel `mlx5_core`/`vfio-pci` drivers are
  assumed present (not part of this tree; not a deletion target).

**host2** (second machine) is required only for **inter-host** experiments and cannot be bundled.
**intra-host** experiments and the **fstack** real-app enforcement are **host1-only** and need no
second host.

---

## Validation (acceptance test)

```bash
bash /home/sungwoo/FINAL/run_validation.sh
```

Runs two independent targets from this tree alone:

**(1) CE-L4 intra microbenchmark** (dperf + comm-plane, mlx5 switchdev VF-to-VF):

| mode        | result                                   |
|-------------|------------------------------------------|
| none/ALLOW  | baseline line rate                       |
| eSAC/ALLOW  | ≈ none (attach `RX=OK TX=OK`)            |
| eSAC/DROP   | packets dropped — `ACT_DROP dir=RX` **and** `dir=TX` (32/32 per burst) |

**(2) fstack real-app enforcement** (unmodified f-stack Redis):

| scenario                 | tenant action            | result                              |
|--------------------------|--------------------------|-------------------------------------|
| L4 ALLOW (flow permitted)| `redis-cli ping`         | `PONG` (served)                     |
| L4 DROP (flow denied)    | `redis-cli ping`         | empty / timeout (dropped at PMD RX) |
| Integrity (self-tamper)  | `openat(/proc/self/mem)` | tenant SIGKILLed by TamperSentinel  |

**Resource plane** (host1-only, `harness/resource/`): admission gate denies an over-quota launch
(`[ADMIT] DENY (no exec)`, no resource touched); a running tenant's over-quota `rte_malloc` is
**overridden to NULL** (blocked, not killed); net-zero `rte_malloc`/`rte_free` churn is
**rate-limited** so a co-located victim's allocation latency recovers.

### Real-app enforcement requires STOP/CONT pre-attach
The agent+loader attach **while the application is stopped, before its DPDK EAL/PMD begins
polling** (`kill -STOP` → attach loader → `kill -CONT`). If you boot the app fully and attach
afterward, the uprobe binds the symbol but the hot RX path never traverses it (loader shows
`rx=0`), so nothing is enforced — a harness timing issue, not an eSAC limitation. Use
`harness/fstack/fstack_verify_stopcont.sh` (and the switchdev non-root variant) for enforcement.

---

## Experiment map

| Experiment | Harness dir | What it shows |
|-----------|-------------|---------------|
| CE3–CE7 | `harness/ce_l4/` | L4 overhead vs none and vs **kernel-uprobe** baseline across interval/cc/payload/lcore/policy. On the RX inspection path eSAC ≈ none; the kernel-uprobe mode (read-only, pays a per-burst user→kernel trap, cannot drop) falls behind past its saturation point. |
| CE8–CE11 | `harness/l7/` | L7 DNS enforcement vs none and vs Suricata (middlebox). eSAC ≈ none for DNS; orders-of-magnitude over Suricata. |
| IE | `harness/ie/` | TamperSentinel kill latency + CPU. Sentinel is off-path (≈ 0 data-plane impact); event-driven CPU ≈ 0 vs polling. |
| Q4 | `harness/fstack/` | Enforcement on an unmodified real app (Redis): ALLOW / DROP. |
| resource | `harness/resource/` | Resource plane: admission gate (block at birth), runtime override (block over-alloc), token-bucket churn throttle, and the cross-tenant shared-resource threat demos. |
| pps | `harness/pps/` | Throughput / replicated-median campaigns. |

**Scope note for the paper**: the "eSAC ≈ none" L4 result is specific to the **RX (ingress)
inspection** path; **TX enforcement now works on mlx5** (all 42 `mlx5_tx_burst_*` variants are
hooked) but the active TX function is heavier to intercept, so TX-side inspection carries real
cost. The resource plane is all-block (admission + override + throttle), kill as backstop. State
these scopes when citing numbers.

---

## Git notes

- **GitHub** (`DavJang/eSAC`, `main`) holds a **source-only snapshot**: `comm_plane` (src + small
  `.bpf.o` + loaders), `harness`, `l7`, `policy`, `apps` configs, `suricata` rules, `tamper_sentinel`
  scripts/src, `docs`, and this README (258 files, largest ~188 KB, no file > 100 MB). Prebuilt
  binaries and heavy third-party libs are excluded — rebuild them:
  - comm-plane / resource loaders: `gcc -O2 -I comm_plane/loaders/ebpf <loader>.c -o <out> -lbpf -lelf -lz`
  - BPF objects: `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I comm_plane/src -I /usr/include -c <x>.bpf.c -o <x>.bpf.o`
  - dperf / f-stack / Suricata / bpftime from their upstreams; DPDK 24.11 for `lib/`.
- `secrets/` (host2 key), `results/`, logs, and `*.bak*` are **gitignored** — never commit the key.
- The **local** tree additionally ships ~1 GB of statically-linked binaries so it runs after
  deleting everything else. To publish those too (clone-and-run), use **git-lfs** for the five
  files > 100 MB (`agent/*.so`, `tamper_sentinel/bin/*`).
- All binaries are statically linked (only system libs); confirm with `ldd` before relocating.

_eSAC artifact — README regenerated 2026-11-11._

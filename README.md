# eSACfinal — self-contained eSAC artifact

**eSAC** (eBPF-enforced Security Access Control for multi-tenant DPDK containers) is an
in-process packet-inspection security layer. It attaches a userspace uprobe (bpftime/Frida)
to a DPDK application's PMD RX/TX path and enforces per-tenant L4/L7 communication policy,
backed by a kernel **TamperSentinel** that guarantees the agent stays attached and the
policy stays enforced.

This directory is a **self-contained copy** of everything the paper's experiments need:
every artifact is a real file here (no symlinks), so the rest of the working tree can be
deleted and the experiments still run. Built by copying the in-use originals and rewriting
all paths to point inside `eSACfinal/`.

> **Validated 2026-11-06** on the real rig (Mellanox ConnectX-6 Dx 40 GbE, mlx5 switchdev):
> both acceptance targets pass end-to-end from this tree alone — see **Validation** below.

---

## Naming convention

The codebase evolved under several names; this tree uses one consistent vocabulary.

| Canonical (prose)            | identifier / filename form | older names it replaces            |
|------------------------------|----------------------------|------------------------------------|
| **eSAC**                     | `esac`                     | GOWN, gown                         |
| **TamperSentinel**           | `tamper_sentinel`          | watchdog, policy_watchdog, wd      |
| **mask-probe optimization**  | `mask_probe` / `maskprobe` | opt3, probe-mask                   |

Upstream identifiers are left untouched on purpose (renaming them would break binaries):
e.g. the bpftime env var `BPFTIME_GLOBAL_SHM_NAME` and the dperf histogram env vars
`GOWN_HIST_FILE` / `GOWN_HIST_START_SEC` (read by the prebuilt `traffic/dperf_hist`).

---

## Layout

```
eSACfinal/
├── run_validation.sh         # one-command acceptance test (CE-L4 + fstack)
├── comm_plane/               # the eSAC enforcement plane
│   ├── loaders/              #   uprobe loaders (+ src/ for the C we own)
│   │   ├── comm_loader_cgroup            # canonical loader (mask-probe, per-tenant cgroup_id)
│   │   ├── comm_loader_cgroup_maskprobe  # burst/mask-probe loader used by CE & fstack
│   │   ├── comm_loader_kernel128         # kernel-uprobe baseline loader
│   │   └── resource_loader               # resource-plane admission gate
│   ├── bpf/                  #   eBPF filter objects (maskprobe L4/L7, kernel, strict)
│   └── offsets.json          #   mbuf field offsets (buf_addr/data_off/pkt_len/data_len)
├── agent/                    # bpftime in-process agent + syscall-server (L4 & hyperscan L7)
├── tamper_sentinel/          # TamperSentinel binaries + src + arming/verify scripts
├── traffic/                  # dperf traffic generators (static; base/burst128/hist/dns/probe)
├── apps/                     # real applications: f-stack redis-server, nginx (+ ff_redis configs)
├── l7/                       # L7 DNS/Hyperscan: ctl tools, ufuncs, patterns, DNS payloads
├── suricata/                 # Suricata 7.0.7 baseline (bin + libhtp + rules + ips yaml)
├── lib/                      # runtime libs (fstack-dpdk, dpdk-24.11 build) for LD_LIBRARY_PATH / -d
├── policy/                   # policy generators (gen_policy_n/kern, mkdns)
├── harness/                  # all experiment harnesses (paths rewritten to this tree)
│   ├── ce_l4/   CE3–CE7 L4 sweeps (interval/cc/payload/lcore/policy)
│   ├── l7/      CE8–CE11 L7 DNS (none / eSAC / Suricata)
│   ├── ie/      IE integrity: TamperSentinel kill latency + CPU
│   ├── pps/     throughput / replicated-median campaigns
│   ├── fstack/  real-app enforcement (see STOP/CONT note)
│   ├── resource/ per-tenant resource-plane (hugepage DoS gate)
│   └── setup/   switchdev/VF bring-up, host2 helpers
├── secrets/                  # host2 SSH key — GITIGNORED, never commit
└── results/                  # run outputs — gitignored
```

---

## Prerequisites (system state — NOT copyable, reproduce with setup scripts)

These live in the kernel/devices, not in files, so they are rebuilt by scripts here:

- **Hugepages**: node0 needs free 2 MB pages (≥ 2048 MB per DPDK process; 8-core runs want more).
- **PF1 switchdev + 2 VFs + tc hairpin** (intra fabric): `harness/setup/intra_switchdev_up.sh`
  (idempotent; echoes `INTRA_SVF`/`INTRA_CVF`). Needed by CE-intra and fstack.
- **PF0 VF 3b:00.3** (inter fabric, host2): `harness/setup/host1_vf_prepare.sh`.
- **cgroup v2** mounted at `/sys/fs/cgroup` (per-tenant `cgroup_id` keying).
- **root**: mlx5 VF DPDK needs root (DevX TIS allocation).
- System libraries under `/usr/local/lib` and the kernel `mlx5_core`/`vfio-pci` drivers are
  assumed present (not part of this tree; not a deletion target).

**host2** (second machine, `143.248.57.12`) is required only for **inter-host** experiments
and cannot be bundled. **intra-host** experiments and the **fstack** real-app enforcement are
**host1-only** and need no second host.

---

## Validation (acceptance test)

```bash
bash /home/sungwoo/eSACfinal/run_validation.sh
```

Runs two independent targets from this tree alone. Results from the 2026-11-06 run:

**(1) CE-L4 intra microbenchmark** (dperf + comm-plane, cc=8000, 512 B):

| mode        | pps        | note                          |
|-------------|-----------:|-------------------------------|
| none/ALLOW  | 4,834,418  | baseline                      |
| eSAC/ALLOW  | 5,676,938  | ≈ none, attach RX=OK TX=OK    |
| eSAC/DROP   | 4          | enforcement: packets dropped at RX hook |

**(2) fstack real-app enforcement** (unmodified f-stack Redis):

| scenario                 | tenant action          | result                 |
|--------------------------|------------------------|------------------------|
| L4 ALLOW (flow permitted)| `redis-cli ping`       | `PONG` (served)        |
| L4 DROP (flow denied)    | `redis-cli ping`       | empty / timeout (dropped at PMD RX) |
| Integrity (self-tamper)  | `openat(/proc/self/mem)` | tenant SIGKILLed     |

### ⚠️ Real-app enforcement requires STOP/CONT pre-attach
The agent+loader must be attached **while the application is stopped, before its DPDK EAL/PMD
begins polling** (`harness/fstack/fstack_verify_stopcont.sh` does this: `kill -STOP` → attach
loader → `kill -CONT`). If you boot the app fully and attach afterward, the uprobe binds the
symbol but the hot RX path never traverses it (loader shows `rx=0`), so nothing is enforced —
this is a harness timing issue, not an eSAC limitation. The `fstack_verify.sh` /
`fstack_drop_burst.sh` (boot-then-attach) scripts are kept for reference/throughput only and
do **not** enforce; use `fstack_verify_stopcont.sh` for enforcement.

---

## Experiment map

| Experiment | Harness dir | What it shows |
|-----------|-------------|---------------|
| CE3–CE7 | `harness/ce_l4/` | L4 overhead vs none and vs kernel-uprobe across interval/cc/payload/lcore/policy. On the RX inspection path eSAC ≈ none; kernel-uprobe falls behind past its saturation point. |
| CE8–CE11 | `harness/l7/` | L7 DNS enforcement vs none and vs Suricata (middlebox). eSAC ≈ none for DNS; orders-of-magnitude over Suricata. |
| IE | `harness/ie/` | TamperSentinel kill latency + CPU. Sentinel is off-path (≈ 0 data-plane impact); event-driven CPU ≈ 0 vs polling. |
| Q4 | `harness/fstack/` | Enforcement on an unmodified real app (Redis): ALLOW/DROP/KILL. |
| resource | `harness/resource/` | Per-tenant resource-plane admission (hugepage over-consumption DoS gate). |
| pps | `harness/pps/` | Throughput / replicated-median campaigns. |

**Scope note for the paper**: the "eSAC ≈ none" L4 result is specific to the **RX (ingress)
inspection** path; TX-side enforcement carries real cost (uretprobe-heavy). The resource-plane
gate is proven at the control plane. State these scopes when citing numbers.

---

## Git notes

- `secrets/` (host2 key), `results/`, and logs are **gitignored** — never commit the key.
- The tree ships ~1 GB of prebuilt **static** binaries so it runs after deleting everything
  else. To publish a small source-only repo instead, enable the optional block in `.gitignore`
  and rebuild from source (comm-plane loaders: `gcc -O2 -pthread -I<hdrs> loader.c -lbpf -lelf -lz`;
  BPF objects via clang; dperf/f-stack/suricata/bpftime from their upstreams). Or use git-lfs.
- All binaries are statically linked (only system libs); confirm with `ldd` before relocating.

_Generated as part of the eSACfinal consolidation, 2026-11-06._

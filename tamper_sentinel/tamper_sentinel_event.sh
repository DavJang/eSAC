#!/bin/bash
# GOWN FINAL integrity watchdog — event/syscall design (prof's proposal).
# Usage: gown_watchdog_event_final.sh <target_pid> [core]
# Watches the tenant PID for the two RO-bypass tamper vectors and SIGKILLs on hit:
#   - mprotect(..., PROT_WRITE)  (re-protect a RO-mapped hook/policy page to RW)
#   - openat("/proc/self/mem")   (write RO memory via /proc/self/mem, bypassing page perms)
# Prints "Attaching N probes..." when armed. Idle userspace CPU ~0 (no polling).
#
# COVERAGE NOTE (honest): this detects the tamper SYSCALL VECTORS only. Unlike the
# legacy polling sidecars it does NOT re-read comm_policy key/action nor snapshot the
# 22 hook prologue bytes, so it does not verify integrity STATE and cannot catch a
# tamper that avoids these two syscalls. The professor's full design pairs this with
# RO-mapping of policy/hook pages (blocks plain-store tamper in hardware) — RO-mapping
# is NOT yet implemented in the GOWN agent. For state verification, run the optional
# low-frequency polling backstop (gown_policy_watchdog_cgroup / gown_prologue_watchdog
# at a long interval). The measured "~0% CPU" is userspace bpftrace idle and EXCLUDES
# the per-syscall kernel BPF cost.
# KNOWN FALSE-POSITIVE: the mprotect(RW) probe fires on the bpftime agent's own JIT/hook
# mprotect (making code pages RW). Attach this watchdog only AFTER the target reaches steady
# state (past init/JIT), else it SIGKILLs the tenant during startup (seen at 4+ lcores).
set -u
PID=${1:?target pid}
CORE=${2:-10}
BT='tracepoint:syscalls:sys_enter_mprotect /pid=='"$PID"' && (args->prot & 2)/ { printf("[EVWD] mprotect_rw pid=%d\n",pid); signal(9); }
tracepoint:syscalls:sys_enter_openat /pid=='"$PID"'/ { $fn=str(args->filename); if($fn=="/proc/self/mem"){ printf("[EVWD] procmem pid=%d\n",pid); signal(9); } }'
exec sudo -n taskset -c "$CORE" bpftrace --unsafe -e "$BT"

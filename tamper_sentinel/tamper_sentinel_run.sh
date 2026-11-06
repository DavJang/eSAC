#!/bin/bash
# GOWN FINAL integrity watchdog — event/syscall design (prof's RO+syscall proposal), COMPLETE.
# Pairs with gown_harden.so, which maps the protected pages (code/policy/RCFG) read-only so
# that every tamper MUST go through one of the syscalls below. Idle userspace CPU ~0 (no polling).
#
# Watches the scoped target PID for ALL perm-changing / perm-bypassing write vectors and SIGKILLs:
#   - mprotect(..., PROT_WRITE)   : re-grant write to an RO-mapped hook/policy page
#   - openat("/proc/self/mem")    : write RO memory bypassing page perms
#   - ptrace(...)                 : PTRACE_POKETEXT/POKEDATA write bypassing page perms
#   - process_vm_writev(...)      : cross-/self- address-space write
# A benign DPDK target performs none of these in steady state (arm AFTER warmup; the agent's own
# JIT/hook mprotect(RW) happens during startup — see gown_harden.so timing note).
#
# Usage: gown_watchdog_final.sh <target_pid> [core]
set -u
PID=${1:?target pid}
CORE=${2:-10}
BT='tracepoint:syscalls:sys_enter_mprotect /pid=='"$PID"' && (args->prot & 2)/ { printf("[WD] mprotect_rw pid=%d\n",pid); signal(9); }
tracepoint:syscalls:sys_enter_openat /pid=='"$PID"'/ { $fn=str(args->filename); if($fn=="/proc/self/mem"){ printf("[WD] procmem pid=%d\n",pid); signal(9); } }
tracepoint:syscalls:sys_enter_ptrace /pid=='"$PID"'/ { printf("[WD] ptrace pid=%d req=%d\n",pid,args->request); signal(9); }
tracepoint:syscalls:sys_enter_process_vm_writev /pid=='"$PID"'/ { printf("[WD] vmwritev pid=%d\n",pid); signal(9); }'
exec sudo -n taskset -c "$CORE" bpftrace --unsafe -e "$BT"

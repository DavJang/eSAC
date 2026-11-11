#!/bin/bash
# eSAC FINAL integrity tamper_sentinel -- event/syscall design (RO+syscall), COMPLETE.
# Pairs with esac_harden.so, which maps the protected pages (code/policy/RCFG) read-only so
# that every tamper MUST go through one of the two syscalls below. Idle userspace CPU ~0 (no polling).
#
# Watches the scoped target PID for the TWO perm-changing / perm-bypassing write vectors and SIGKILLs:
#   - mprotect(..., PROT_WRITE)   : re-grant write to an RO-mapped hook/policy page
#   - openat("/proc/self/mem")    : write RO memory bypassing page perms (FOLL_FORCE)
# ptrace and process_vm_writev are OUT of the self-tamper model and intentionally NOT watched:
# a process cannot PTRACE_ATTACH itself, and process_vm_writev honors destination page permissions,
# so neither can write an RO-mapped page -- the two calls above are the only ways to reopen it.
# A benign DPDK target performs none of these in steady state (arm AFTER warmup; the agent's own
# JIT/hook mprotect(RW) happens during startup -- see esac_harden.so timing note).
#
# Usage: esac_tamper_sentinel_final.sh <target_pid> [core]
set -u
PID=${1:?target pid}
CORE=${2:-10}
BT='tracepoint:syscalls:sys_enter_mprotect /pid=='"$PID"' && (args->prot & 2)/ { printf("[TAMPER_SENTINEL] mprotect_rw pid=%d\n",pid); signal(9); }
tracepoint:syscalls:sys_enter_openat /pid=='"$PID"'/ { $fn=str(args->filename); if($fn=="/proc/self/mem"){ printf("[TAMPER_SENTINEL] procmem pid=%d\n",pid); signal(9); } }'
exec sudo -n taskset -c "$CORE" bpftrace --unsafe -e "$BT"

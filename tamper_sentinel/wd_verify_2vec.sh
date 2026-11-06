#!/bin/bash
# E7 — FINAL 2-VECTOR watchdog verification.
# The final GOWN watchdog monitors ONLY two tamper vectors:
#   1. mprotect(..., PROT_WRITE)   -> make a RO-mapped code/policy page writable
#   2. openat("/proc/self/mem")    -> write own RO memory bypassing page perms
# A tenant calling either -> SIGKILL. The dropped vectors (ptrace, process_vm_writev)
# are OUT of scope now, so under the 2-vector WD they must SURVIVE (proving the scope).
# wd_selftest <vec> <secs> performs the named syscall then prints SURVIVED if it lived.
set -u
cd /home/sungwoo/gown_final
OUT=/home/sungwoo/wdverify2_$(date +%s); mkdir -p "$OUT"; echo "$OUT">/home/sungwoo/.wdverify2_dir; rm -f "$OUT/.done"
R=$OUT/result.txt; : > "$R"
printf '%-10s %-5s %-7s %-9s %-10s %s\n' vector rc killed survived expect verdict >> "$R"
# vector -> expected outcome under the 2-VECTOR watchdog
declare -A EXP=( [mprotect]=KILL [procmem]=KILL [ptrace]=SURVIVE [vmwritev]=SURVIVE [none]=SURVIVE )
for vec in mprotect procmem ptrace vmwritev none; do
  sudo -n pkill -9 -x bpftrace 2>/dev/null; sleep 1
  ./wd_selftest "$vec" 6 > "$OUT/$vec.log" 2>&1 & sp=$!
  sleep 1
  # ---- the FINAL 2-vector watchdog: ONLY mprotect(RW) + openat(/proc/self/mem) ----
  setsid sudo -n bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$sp && (args->prot & 2)/ { printf(\"[EVWD] mprotect_rw\\n\"); signal(9); }
tracepoint:syscalls:sys_enter_openat /pid==$sp/ { \$fn=str(args->filename); if(\$fn==\"/proc/self/mem\"){ printf(\"[EVWD] procmem\\n\"); signal(9); } }" > "$OUT/$vec.wd.log" 2>&1 & wd=$!
  for i in $(seq 1 30); do grep -q Attaching "$OUT/$vec.wd.log" 2>/dev/null && break; sleep 0.5; done
  wait $sp 2>/dev/null; rc=$?
  sudo -n pkill -9 -x bpftrace 2>/dev/null
  killed=NO; [ $rc -ge 128 ] && killed=YES
  surv=NO; grep -q SURVIVED "$OUT/$vec.log" && surv=YES
  got=$([ "$killed" = YES ] && echo KILL || echo SURVIVE)
  exp=${EXP[$vec]}
  verdict=$([ "$got" = "$exp" ] && echo PASS || echo FAIL)
  printf '%-10s %-5s %-7s %-9s %-10s %s\n' "$vec" "$rc" "$killed" "$surv" "$exp" "$verdict" >> "$R"
done
echo "=== DONE (2-vector: mprotect+procmem KILL; ptrace/vmwritev/none SURVIVE) ===" >> "$R"
cat "$R"; touch "$OUT/.done"

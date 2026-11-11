#!/bin/bash
# Validate the FINAL tamper_sentinel detects each tamper vector: run tamper_sentinel_selftest doing the syscall,
# with the tamper_sentinel attached to its pid; a working tamper_sentinel SIGKILLs it (rc=137, no SURVIVED).
set -u
cd /home/sungwoo/esac_final
OUT=/home/sungwoo/wdverify_$(date +%s); mkdir -p "$OUT"; echo "$OUT">/home/sungwoo/.wdverify_dir; rm -f "$OUT/.done"
R=$OUT/result.txt; : > "$R"
for vec in mprotect procmem ptrace vmwritev none; do
  sudo -n pkill -9 -x bpftrace 2>/dev/null; sleep 1
  ./tamper_sentinel_selftest "$vec" 6 > "$OUT/$vec.log" 2>&1 & sp=$!
  sleep 1
  setsid sudo -n bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$sp && (args->prot & 2)/ { signal(9); }
tracepoint:syscalls:sys_enter_openat /pid==$sp/ { \$fn=str(args->filename); if(\$fn==\"/proc/self/mem\"){ signal(9); } }
tracepoint:syscalls:sys_enter_ptrace /pid==$sp/ { signal(9); }
tracepoint:syscalls:sys_enter_process_vm_writev /pid==$sp/ { signal(9); }" > "$OUT/$vec.wd.log" 2>&1 & wd=$!
  # wait for probes to attach
  for i in $(seq 1 30); do grep -q Attaching "$OUT/$vec.wd.log" 2>/dev/null && break; sleep 0.5; done
  wait $sp 2>/dev/null; rc=$?
  sudo -n pkill -9 -x bpftrace 2>/dev/null
  killed=NO; [ $rc -ge 128 ] && killed=YES
  surv=NO; grep -q SURVIVED "$OUT/$vec.log" && surv=YES
  # expectation: vectors -> killed; none -> survived
  exp=KILL; [ "$vec" = none ] && exp=SURVIVE
  got=$([ "$killed" = YES ] && echo KILL || echo SURVIVE)
  verdict=$([ "$got" = "$exp" ] && echo PASS || echo FAIL)
  printf "%-9s rc=%-4s killed=%-3s survived=%-3s expect=%-8s -> %s\n" "$vec" "$rc" "$killed" "$surv" "$exp" "$verdict" >> "$R"
done
echo "=== DONE ===" >> "$R"; cat "$R"; touch "$OUT/.done"

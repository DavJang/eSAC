#!/bin/bash
set +u
cd /home/sungwoo/FINAL/tamper_sentinel
OUT=/home/sungwoo/killlat_$(date +%s); mkdir -p "$OUT"; echo "$OUT" > /home/sungwoo/.killlat_dir
RES=$OUT/lat.txt; : > "$RES"
ITERS=${ITERS:-15}
for vec in mprotect procmem; do
  : > "$OUT/$vec.vals"
  for it in $(seq 1 $ITERS); do
    sudo -n pkill -9 -x bpftrace 2>/dev/null; sleep 0.4
    ./tamper_sentinel_selftest "$vec" 6 > "$OUT/${vec}_${it}.sel.log" 2>&1 & sp=$!
    sleep 1
    sudo -n bpftrace --unsafe -e "
tracepoint:syscalls:sys_enter_mprotect /pid==$sp && (args->prot & 2)/ { @m[pid]=nsecs; signal(9); }
tracepoint:syscalls:sys_enter_openat /pid==$sp/ { \$fn=str(args->filename); if(\$fn==\"/proc/self/mem\"){ @m[pid]=nsecs; signal(9); } }
tracepoint:sched:sched_process_exit /pid==$sp/ { if(@m[pid]){ printf(\"KILL_LATENCY_NS %lld\n\", nsecs-@m[pid]); delete(@m[pid]); } }
" > "$OUT/${vec}_${it}.wd.log" 2>&1 &
    for i in $(seq 1 30); do grep -q Attaching "$OUT/${vec}_${it}.wd.log" 2>/dev/null && break; sleep 0.2; done
    wait $sp 2>/dev/null
    sleep 0.6
    sudo -n pkill -9 -x bpftrace 2>/dev/null
    ns=$(grep -aoE "KILL_LATENCY_NS [0-9]+" "$OUT/${vec}_${it}.wd.log" | head -1 | awk "{print \$2}")
    echo "$vec it=$it ns=${ns:-NA}" >> "$RES"
    [ -n "$ns" ] && echo "$ns" >> "$OUT/$vec.vals"
  done
  sort -n "$OUT/$vec.vals" > "$OUT/$vec.sorted"
  awk -v v="$vec" "{a[NR]=\$1} END{ if(NR==0){print \"SUMMARY \"v\" n=0 FAILED\"; exit} m=a[int((NR+1)/2)]; p=a[int((NR*0.9)+0.9999)]; if(p==\"\")p=a[NR]; printf \"SUMMARY %s n=%d median_ns=%d median_us=%.2f p90_ns=%d min_ns=%d max_ns=%d\n\", v, NR, m, m/1000, p, a[1], a[NR] }" "$OUT/$vec.sorted" >> "$RES"
done
echo DONE >> "$RES"

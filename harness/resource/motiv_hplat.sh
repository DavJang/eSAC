#!/bin/bash
# EXP B (independent): hugepage ALLOC/FREE per-event latency. Allocate N 2MB hugepages one at a time
# (mmap+touch) timing each, then free one at a time timing each. Pinned to node0. Look for per-op spikes.
set +u
D=/home/sungwoo/FINAL; OUT=$D/results/hplat_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
BIN=$OUT/hp_timer
gcc -O2 -o "$BIN" "$D/harness/resource/hp_timer.c" 2>"$OUT/build.err" || { say "BUILD FAIL: $(cat "$OUT/build.err")"; echo EXP_DONE>>"$R"; exit 1; }
N=2000
say "node0 free before = $(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages); allocating N=$N 2MB hugepages one-by-one (node0-pinned)"
numactl --cpunodebind=0 --membind=0 "$BIN" $N > "$OUT/lat.txt" 2>>"$OUT/build.err"
say "node0 free after  = $(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages) (returns to baseline => all freed)"

say "===== ALLOC per-page latency (ns) ====="
awk '$1=="A" && $3 ~ /^[0-9]+$/{v[n++]=$3; s+=$3; if(min==""||$3<min)min=$3; if($3>max){max=$3;mi=$2}}
  END{if(n==0){print "  no alloc samples";exit} asort(v); printf "  n=%d min=%d median=%d p90=%d p99=%d max=%d(@idx %s) mean=%.0f\n", n, min, v[int(n*0.5)], v[int(n*0.9)], v[int(n*0.99)], max, mi, s/n}' "$OUT/lat.txt" | tee -a "$R"
say "  10 slowest ALLOCs (idx:ns) -> are spikes periodic (pool/boundary) or random?"
grep '^A ' "$OUT/lat.txt" | awk '$3~/^[0-9]+$/{print $2":"$3}' | sort -t: -k2 -nr | head -10 | tr '\n' ' ' | tee -a "$R"; echo "" | tee -a "$R"

say "===== FREE per-page latency (ns) ====="
awk '$1=="F" && $3 ~ /^[0-9]+$/{v[n++]=$3; s+=$3; if(min==""||$3<min)min=$3; if($3>max){max=$3;mi=$2}}
  END{if(n==0){print "  no free samples";exit} asort(v); printf "  n=%d min=%d median=%d p90=%d p99=%d max=%d(@idx %s) mean=%.0f\n", n, min, v[int(n*0.5)], v[int(n*0.9)], v[int(n*0.99)], max, mi, s/n}' "$OUT/lat.txt" | tee -a "$R"
say "  10 slowest FREEs (idx:ns)"
grep '^F ' "$OUT/lat.txt" | awk '$3~/^[0-9]+$/{print $2":"$3}' | sort -t: -k2 -nr | head -10 | tr '\n' ' ' | tee -a "$R"; echo "" | tee -a "$R"
say "DONE OUT=$OUT"; echo EXP_DONE >> "$R"

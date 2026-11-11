#!/bin/bash
# CONFIRM the mbuf-BYTES mechanism (not a coincidence / not count-based):
# one tenant, 10 pools of 16.777 MiB each (8192 x 2048). Vary max_mbuf_total_bytes cap and
# check the KILL fires on exactly pool index = floor(cap / 16.777MB) + 1.
#   cap=20MB -> kill on 2nd  (1 ALLOW then VIOLATION)
#   cap=40MB -> kill on 3rd  (2 ALLOW then VIOLATION)   [already seen]
#   cap=70MB -> kill on 5th  (4 ALLOW then VIOLATION)
# If the kill INDEX tracks the byte arithmetic across caps, the bytes projection is what
# enforces, and the loader's "room=0" is only a cosmetic log field.
set +e
D=/home/sungwoo/FINAL
libdir=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
MB=/home/sungwoo/old/dpdk_ebpf_work/DPDK_eBPF/stress/mbuf_stress
OUT=$D/results/res_mbufsweep_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
EALARGS="-n 4 --no-pci --in-memory --socket-mem=1024,0"
APPARGS="--rounds 10 --pool-n 8192 --rooms 2048"

run_one(){  # $1=cap_bytes  $2=expected_kill_index
  local CAP=$1 EXP=$2 tag=cap${1}
  sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sleep 1
  sudo -n setsid bash -c "echo \$\$ > $OUT/pid_$tag; kill -STOP \$\$; exec $MB -l 0 $EALARGS --file-prefix=mb_$tag -- $APPARGS" > "$OUT/t_$tag.log" 2>&1 < /dev/null & disown
  sleep 2; local P=$(cat "$OUT/pid_$tag")
  echo "{\"default\":{\"max_mbuf_total_bytes\":$CAP,\"action_on_violation\":\"KILL\"}}" > "$OUT/pol_$tag.json"
  sudo -n "$loader" --bpf "$bpf" --lib "$libdir" --policy "$OUT/pol_$tag.json" -v > "$OUT/loader_$tag.log" 2>&1 & local L=$!
  sleep 3; sudo -n kill -CONT "$P"; sleep 5
  # count pktmbuf ALLOW for this pid BEFORE its VIOLATION; kill index = allows+1
  local allows=$(grep -a "pid=$P" "$OUT/loader_$tag.log" | grep -a "rte_pktmbuf_pool_create" | grep -a "ALLOW" | wc -l)
  local viol=$(grep -a "pid=$P" "$OUT/loader_$tag.log" | grep -ac "VIOLATION.*pktmbuf")
  local killidx=$((allows+1))
  if [ "$viol" -ge 1 ]; then
    say "cap=$((CAP/1000000))MB  => ALLOW×$allows then VIOLATION  => KILL on pool #$killidx   (expected #$EXP)  $([ "$killidx" = "$EXP" ] && echo MATCH || echo MISMATCH)"
  else
    say "cap=$((CAP/1000000))MB  => NO violation (allows=$allows)  (expected kill #$EXP)  MISMATCH"
  fi
  sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sudo -n kill -9 $L 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sleep 1
}

say "pool bytes = 8192*2048 = 16.777 MB each; kill index should = floor(cap/16.777MB)+1"
run_one 20000000 2
run_one 40000000 3
run_one 70000000 5
n0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages)
say "node0 free (final) = $n0 (baseline 15872 = no leak)"
say "DONE OUT=$OUT"

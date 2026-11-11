#!/bin/bash
# eSAC resource-plane validation (lcore axis, FINAL paths):
# per-tenant LCORE QUOTA -> KILL. Both greedy_lcore use -l 0-3 (=> 3 rte_eal_remote_launch calls):
#   A = default (max_lcore_count=2, KILL) -> 3>2 -> KILLED
#   B = lenient (per-pid max_lcore_count=64) -> ALIVE
# Enforcement: BPF uprobe rte_eal_remote_launch counts per-tenant; over cap -> bpf_send_signal + loader kill.
set +e
D=/home/sungwoo/FINAL
lib=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
GL=/home/sungwoo/old/dpdk_ebpf_work/DPDK_eBPF/stress/greedy_lcore
OUT=$D/results/res_lcore_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
alive(){ local p=$1; [ -d /proc/$p ] || { echo KILLED; return; }; local s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo KILLED || echo ALIVE; }

sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'greedy_lcor[e]' 2>/dev/null; sleep 1

sudo -n setsid bash -c "echo \$\$ > $OUT/pidB; kill -STOP \$\$; exec $GL -l 0-3 -n 1 --no-pci --in-memory --file-prefix=glB" > "$OUT/tB.log" 2>&1 < /dev/null & disown
sudo -n setsid bash -c "echo \$\$ > $OUT/pidA; kill -STOP \$\$; exec $GL -l 0-3 -n 1 --no-pci --in-memory --file-prefix=glA" > "$OUT/tA.log" 2>&1 < /dev/null & disown
sleep 2; B=$(cat "$OUT/pidB"); A=$(cat "$OUT/pidA")
say "tenant A pid=$A (default cap=2)   tenant B pid=$B (per-pid cap=64)   both launch 4 lcores"

cat > "$OUT/policy.json" <<EOF
{"default":{"max_lcore_count":2,"action_on_violation":"KILL"},"pids":{"$B":{"max_lcore_count":64,"action_on_violation":"KILL"}}}
EOF
say "policy.json: $(cat "$OUT/policy.json")"

sudo -n "$loader" --bpf "$bpf" --lib "$lib" --policy "$OUT/policy.json" -v > "$OUT/loader.log" 2>&1 & L=$!
sleep 3
sudo -n kill -CONT "$B"; sudo -n kill -CONT "$A"; sleep 5

bA=$(alive $A); bB=$(alive $B)
echo ""
say "===== RESULT (both launched 4 lcores = 3 remote_launch) ====="
say "  A (default cap=2) => observed=$bA   expect=KILLED"
say "  B (cap=64)        => observed=$bB   expect=ALIVE"
echo "--- loader lcore/violation/kill lines ---"
grep -aE 'VIOLATION|KILL|remote_launch|lcore|ALLOW|pid=' "$OUT/loader.log" | head -14

sudo -n kill -9 $A $B 2>/dev/null; sudo -n pkill -9 -f 'greedy_lcor[e]' 2>/dev/null
sudo -n kill -9 $L 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null
say "DONE OUT=$OUT"

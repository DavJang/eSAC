#!/bin/bash
# eSAC resource-plane validation: MBUF-POOL BYTES axis (max_mbuf_total_bytes) -> KILL.
# mbuf_stress creates `rounds` pktmbuf pools, each pool_n x rooms bytes, KEEPING them
# (freed only at the end) -> cumulative mbuf bytes grow. BPF uprobe rte_pktmbuf_pool_create
# reads (n, data_room_size), projects st->mbuf_total_bytes += n*room, and when it crosses
# the per-tenant cap -> bpf_send_signal(SIGKILL).
#   Both tenants: --rounds 10 --pool-n 8192 --rooms 2048  => 8192*2048 = 16 MiB per pool.
#   A = default cap  max_mbuf_total_bytes=40000000 (~40MB) -> KILLED on 3rd pool (50MB>40MB)
#   B = per-pid cap  max_mbuf_total_bytes=2000000000(~2GB) -> COMPLETES all 10 pools (ALIVE)
# mbuf_stress runs to completion and EXITS, so the verdict is COMPLETION (did it print the
# "pktmbuf_pool_create  n=10" summary?) not /proc-aliveness: a killed tenant's log is
# truncated before that line.  --no-pci: no NIC needed.
set +e
D=/home/sungwoo/FINAL
libdir=/usr/local/lib/x86_64-linux-gnu/librte_eal.so   # loader resolves pktmbuf in librte_mbuf.so in same dir
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
MB=/home/sungwoo/old/dpdk_ebpf_work/DPDK_eBPF/stress/mbuf_stress
OUT=$D/results/res_mbuf_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
n0free(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null; }
# "COMPLETED" iff the tenant printed the full pktmbuf_pool_create summary with n=10
done10(){ grep -aq "pktmbuf_pool_create  n=10" "$1" && echo COMPLETED || echo KILLED/TRUNC; }
EALARGS="-n 4 --no-pci --in-memory --socket-mem=1024,0"
APPARGS="--rounds 10 --pool-n 8192 --rooms 2048"

sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sleep 1
say "node0 free hugepages (start) = $(n0free)  (per pool = 8192*2048 = 16 MiB; 3rd pool => ~50MB > A cap 40MB)"

# tenants: root + STOPPED so loader attaches rte_pktmbuf_pool_create uprobe before they create pools
sudo -n setsid bash -c "echo \$\$ > $OUT/pidB; kill -STOP \$\$; exec $MB -l 1 $EALARGS --file-prefix=mbB -- $APPARGS" > "$OUT/tB.log" 2>&1 < /dev/null & disown
sudo -n setsid bash -c "echo \$\$ > $OUT/pidA; kill -STOP \$\$; exec $MB -l 0 $EALARGS --file-prefix=mbA -- $APPARGS" > "$OUT/tA.log" 2>&1 < /dev/null & disown
sleep 2; B=$(cat "$OUT/pidB"); A=$(cat "$OUT/pidA")
say "tenant A pid=$A (default cap=40MB)   tenant B pid=$B (per-pid cap=2GB)   both create 10x16MiB pools"

cat > "$OUT/policy.json" <<EOF
{"default":{"max_mbuf_total_bytes":40000000,"action_on_violation":"KILL"},"pids":{"$B":{"max_mbuf_total_bytes":2000000000,"action_on_violation":"KILL"}}}
EOF
say "policy.json: $(cat "$OUT/policy.json")"

sudo -n "$loader" --bpf "$bpf" --lib "$libdir" --policy "$OUT/policy.json" -v > "$OUT/loader.log" 2>&1 & L=$!
sleep 3
sudo -n kill -CONT "$B"; sudo -n kill -CONT "$A"; sleep 6

cA=$(done10 "$OUT/tA.log"); cB=$(done10 "$OUT/tB.log")
echo ""
say "===== RESULT (both create 10 pools x 16MiB; cap decides) ====="
say "  A (default cap=40MB) => $cA   expect=KILLED/TRUNC (dies on 3rd pool ~50MB)"
say "  B (per-pid cap=2GB)  => $cB   expect=COMPLETED (all 10 pools)"
echo "--- A tenant log (truncated mid-pool = killed) ---"; grep -aE "mbuf_stress|pktmbuf_pool_create|failed|rte_errno" "$OUT/tA.log" | head -6
echo "--- B tenant log (should reach n=10 summary) ---"; grep -aE "mbuf_stress|pktmbuf_pool_create" "$OUT/tB.log" | head -4
echo "--- loader mbuf violation/kill lines ---"
grep -aE "VIOLATION|KILL|pktmbuf|mbuf|ALLOW|pid=" "$OUT/loader.log" | head -16

sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null
sudo -n kill -9 $L 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null
sleep 2; say "node0 free (after cleanup) = $(n0free)  (should return to start = no leak)"
say "DONE OUT=$OUT"

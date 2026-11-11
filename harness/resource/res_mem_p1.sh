#!/bin/bash
# eSAC resource-plane validation PART 1:
# per-tenant HUGEPAGE/socket-mem QUOTA -> KILL (differential policy).
# Two identical tenants each request --socket-mem=2048 MB (hugepages):
#   A = default policy (max_socket_mem_mb=1024, KILL) -> 2048>1024 -> KILLED
#   B = lenient (per-pid max_socket_mem_mb=4096, KILL) -> 2048<4096 -> ALIVE (grabs 2048)
# Same workload, opposite outcome decided purely by per-tenant policy.
# Tenants run as root + --in-memory (anon hugepages: no /dev/hugepages perm issue, no leak).
# Mechanism: resource_loader attaches KERNEL uprobe rte_eal_init; BPF parses --socket-mem,
# compares to per-pid quota, bpf_send_signal(SIGKILL) + loader kill() on violation.
set +e
D=/home/sungwoo/FINAL
lib=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
HP=/home/sungwoo/old/dpdk_policy_demo/hp_hold
OUT=$D/results/res_mem_p1_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
n0free(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null; }

sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'hp_hol[d]' 2>/dev/null; sleep 1
say "node0 free hugepages (start) = $(n0free) (x2MB)"

# tenants: root + STOPPED (loader attaches uprobe before their rte_eal_init); pidfile = real hp_hold pid (exec keeps pid)
sudo -n setsid bash -c "echo \$\$ > $OUT/pidB; kill -STOP \$\$; exec $HP -l 0 -n 4 --no-pci --in-memory --socket-mem=2048,0 --file-prefix=hpB" > "$OUT/tB.log" 2>&1 < /dev/null & disown
sudo -n setsid bash -c "echo \$\$ > $OUT/pidA; kill -STOP \$\$; exec $HP -l 0 -n 4 --no-pci --in-memory --socket-mem=2048,0 --file-prefix=hpA" > "$OUT/tA.log" 2>&1 < /dev/null & disown
sleep 2; B=$(cat "$OUT/pidB" 2>/dev/null); A=$(cat "$OUT/pidA" 2>/dev/null)
say "tenant A pid=$A (default cap=1024MB)   tenant B pid=$B (per-pid cap=4096MB)   both request 2048MB"

cat > "$OUT/policy.json" <<EOF
{"default":{"max_socket_mem_mb":1024,"action_on_violation":"KILL"},"pids":{"$B":{"max_socket_mem_mb":4096,"action_on_violation":"KILL"}}}
EOF
say "policy.json: $(cat "$OUT/policy.json")"

sudo -n "$loader" --bpf "$bpf" --lib "$lib" --policy "$OUT/policy.json" -v > "$OUT/loader.log" 2>&1 & L=$!
sleep 3
say "loader inj: $(grep -aE 'default|pid .* loaded|ready|attach' "$OUT/loader.log" | tr '\n' '|' | head -c 200)"

sudo -n kill -CONT "$B"; sudo -n kill -CONT "$A"; sleep 6

# alive = /proc exists AND not a zombie (SIGKILL'd procs linger as Z until reaped)
alive(){ local p=$1; [ -d /proc/$p ] || { echo KILLED; return; }
  local s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo KILLED || echo ALIVE; }
bA=$(alive $A); bB=$(alive $B)
say "  (A /proc state=$(awk '{print $3}' /proc/$A/stat 2>/dev/null||echo gone)  B state=$(awk '{print $3}' /proc/$B/stat 2>/dev/null||echo gone))"
echo "--- A tenant log tail (truncated mid-eal_init = killed) ---"; tail -3 "$OUT/tA.log"
echo ""
say "===== RESULT (both requested 2048MB hugepages) ====="
say "  A (default cap=1024) => observed=$bA   expect=KILLED"
say "  B (cap=4096)         => observed=$bB   expect=ALIVE"
say "  node0 free now = $(n0free)  (drop ~1024 pages = B holding 2048MB)"
echo "--- B tenant log tail ---"; tail -3 "$OUT/tB.log"
echo "--- loader violation/kill/eal lines ---"
grep -aE 'VIOLATION|KILL|eal_init|ALLOW|socket|pid=' "$OUT/loader.log" | head -12

sudo -n kill -9 $A $B 2>/dev/null; sudo -n pkill -9 -f 'hp_hol[d]' 2>/dev/null
sudo -n kill -9 $L 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null
sleep 2; say "node0 free (after cleanup) = $(n0free)  (should return to start = no leak)"
say "DONE OUT=$OUT"

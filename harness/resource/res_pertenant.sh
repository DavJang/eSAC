#!/bin/bash
set +e
root=/home/sungwoo/FINAL
lib=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
loader=$root/loader/resource_loader
bpf=$root/ebpf/resource_monitor.bpf.o
bin=$root/exp/support_binaries
out=/home/sungwoo/res_pertenant_$(date +%Y%m%d_%H%M%S); mkdir -p "$out"; echo "OUT=$out"
pkill -9 -f 'resource_loade[r]' 2>/dev/null; pkill -9 -f 'greedy_lcor[e]' 2>/dev/null; sleep 1

# two tenants, both request 4 lcores (-l 0-3), launched STOP'd to capture PIDs before EAL init
setsid bash -c 'kill -STOP $$; exec '"$bin"'/greedy_lcore -l 0-3 -n 1 --no-pci --file-prefix=gB' > "$out/tB.log" 2>&1 &
B=$!
setsid bash -c 'kill -STOP $$; exec '"$bin"'/greedy_lcore -l 0-3 -n 1 --no-pci --file-prefix=gA' > "$out/tA.log" 2>&1 &
A=$!
sleep 1
echo "GroupB_pid=$B (policy B: cap=4, lenient)   GroupA_pid=$A (default/policy A: cap=2, strict)"

# per-tenant differential policy: default=Group A (cap2); pids{B}=Group B (cap4)
cat > "$out/policy.json" <<EOF
{"default":{"max_lcore_count":2,"action_on_violation":"KILL"},"pids":{"$B":{"max_lcore_count":64,"action_on_violation":"KILL"}}}
EOF
echo "--- policy.json ---"; cat "$out/policy.json"

"$loader" --bpf "$bpf" --lib "$lib" --policy "$out/policy.json" -v > "$out/loader.log" 2>&1 &
L=$!
sleep 3
echo "--- policy injection (loader) ---"; grep -E "default loaded|pid .* loaded|ready" "$out/loader.log"

# release both: each calls rte_eal_init requesting 4 lcores
kill -CONT "$B"; kill -CONT "$A"
sleep 5

bA=ALIVE; [ -d /proc/$A ] || bA=KILLED
bB=ALIVE; [ -d /proc/$B ] || bB=KILLED
echo ""
echo "===== RESULT: both tenants requested 4 lcores ====="
echo "Group A tenant (default cap=2):  observed=$bA   expected=KILLED  (4 > 2 violates Policy A)"
echo "Group B tenant (per-PID cap=64):  observed=$bB   expected=ALIVE   (greedy launches <= 64; ALLOWED under lenient Policy B, same workload that Policy A kills)"
echo "--- loader violation/kill lines ---"; grep -aE "VIOLATION|KILL|lcore|pid=" "$out/loader.log" | head -20
kill -9 $A $B $L 2>/dev/null; pkill -9 -f 'greedy_lcor[e]' 2>/dev/null; pkill -9 -f 'resource_loade[r]' 2>/dev/null
echo "DONE out=$out"

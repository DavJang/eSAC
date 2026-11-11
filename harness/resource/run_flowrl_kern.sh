#!/bin/bash
# eSAC control-plane rate-limit — CORRECT mechanism (kernel uprobe + loader policy/KILL,
# matching res_pertenant.sh). NO bpftime agent / shm / syscall-server on the tenant.
set -u
F=/home/sungwoo/FINAL
LOADER=$F/comm_plane/loaders/resource_loader
OBJ=$F/comm_plane/bpf/flow_ratelimit.bpf.o
ETHDEV=/usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
APP=$F/traffic/flow_churn
DD=/usr/local/lib/x86_64-linux-gnu
OUT=$F/results/flowrlk_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-15}
pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null; sleep 1
# clear trace_pipe backlog
: > /sys/kernel/debug/tracing/trace 2>/dev/null
RP=$OUT/rpid
# boot churn STOPPED, PLAIN (no agent/shm) — just like res_pertenant greedy_lcore
setsid bash -c "echo \$\$ > $RP; kill -STOP \$\$; exec env LD_LIBRARY_PATH=$DD $APP -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=fck --in-memory -- $ITERS" > "$OUT/churn.log" 2>&1 &
sleep 2; PID=$(cat $RP 2>/dev/null); echo "churn pid=$PID (stopped, plain, no agent)"
[ -z "$PID" ] && { echo BOOTFAIL; exit 1; }
# loader PLAIN (no syscall-server LD_PRELOAD) -> KERNEL uprobe on rte_flow_create scoped to pid
"$LOADER" --bpf "$OBJ" --lib "$ETHDEV" --no-pin --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 30); do grep -qiE "attached .*rte_flow_create|attached 3|ready" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
echo "loader: $(grep -aiE "attached|error|flow_create" "$OUT/loader.log" | tail -2)"
kill -CONT "$PID"
for j in $(seq 1 20); do grep -q "CHURN done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== churn result ====="; grep -aE "rte_flow_create=|CHURN done" "$OUT/churn.log" | tail -6
echo "===== FLOWRL in kernel trace_pipe (proves kernel uprobe BPF fired) ====="
grep -a FLOWRL /sys/kernel/debug/tracing/trace 2>/dev/null | head -20
echo "trace FLOWRL count: $(grep -ac FLOWRL /sys/kernel/debug/tracing/trace 2>/dev/null)"
pkill -9 -f flow_churn 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null
echo "OUT=$OUT"

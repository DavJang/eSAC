#!/bin/bash
# bpftime in-process override test, CANONICAL order: loader(syscall-server) FIRST (global,
# no attach-pid) -> then victim(agent). If override works, churn's rte_flow_create -> NULL.
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so
AGENT=$F/agent/libbpftime-agent-hs.so
LOADER=$F/comm_plane/loaders/resource_loader
OBJ=${OBJ:-$F/comm_plane/bpf/flow_denyall.bpf.o}
ETHDEV=/usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
APP=$F/traffic/flow_churn
DD=/usr/local/lib/x86_64-linux-gnu
OUT=$F/results/ovr_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-15}
pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null; sleep 1
SHM=esac_ovr_$$
# 1) LOADER FIRST (syscall-server): create shm + register GLOBAL uprobe on rte_flow_create
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SRV" \
  "$LOADER" --bpf "$OBJ" --lib "$ETHDEV" --no-pin -v > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 25); do grep -qiE "attached .*rte_flow_create|attached [1-9]|ready" "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
echo "loader: $(grep -aiE "attached|ready|error" "$OUT/loader.log" | tail -2)"
# 2) VICTIM with agent (same shm) — agent attaches + installs the global hook
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$DD" \
  timeout 30 "$APP" -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=ovr --in-memory -- $ITERS > "$OUT/churn.log" 2>&1
echo "===== churn result (expect NULL if override fired) ====="; grep -aE "rte_flow_create=|CHURN done" "$OUT/churn.log" | tail -6
echo "agent init lines: $(grep -acE "bpftime|Attach|frida|shm|override" "$OUT/churn.log")"
echo "FLOWRL printk: $(grep -ac FLOWRL "$OUT/churn.log")"
kill -9 $LP 2>/dev/null; pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null
echo "OUT=$OUT"

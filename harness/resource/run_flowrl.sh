#!/bin/bash
# eSAC flow-rule rate-limit LIVE demo: churn tenant under agent + flow_ratelimit uprobe.
set -u
F=/home/sungwoo/FINAL
AGENT=$F/agent/libbpftime-agent.so
SRV=$F/agent/libbpftime-syscall-server.so
LOADER=$F/comm_plane/loaders/resource_loader
OBJ=$F/comm_plane/bpf/flow_ratelimit.bpf.o
ETHDEV=/usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
APP=$F/traffic/flow_churn
DD=/usr/local/lib/x86_64-linux-gnu
OUT=$F/results/flowrl_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-15}
pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null; sleep 1
SHM=esac_flowrl_$(date +%s%N)
RP=$OUT/rpid
# boot churn STOPPED with agent preloaded (before EAL/flow calls)
setsid bash -c "echo \$\$ > $RP; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$DD $APP -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=fcrl --in-memory -- $ITERS" > "$OUT/churn.log" 2>&1 &
sleep 2; PID=$(cat $RP 2>/dev/null); echo "churn pid=$PID (stopped)"
[ -z "$PID" ] && { echo BOOTFAIL; exit 1; }
# attach flow_ratelimit uprobe (override) scoped to the churn pid
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SRV" \
  "$LOADER" --bpf "$OBJ" --lib "$ETHDEV" --no-pin --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 40); do grep -qiE "attach|rte_flow_create|ready" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
echo "loader attach state: $(grep -aiE 'attach|rte_flow|flow_create|error' "$OUT/loader.log" | tail -3)"
kill -CONT "$PID"
# wait for churn to finish
for j in $(seq 1 20); do grep -q "CHURN done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== CHURN RESULT (with eSAC rate-limit) ====="; grep -aE "CHURN|rte_flow_create=" "$OUT/churn.log" | head -40
echo "===== FLOWRL gate decisions (bpf_printk / loader) ====="; grep -aiE "FLOWRL|ALLOW|DENY|override" "$OUT/loader.log" | head -40
pkill -9 -f flow_churn 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null
echo "OUT=$OUT"

#!/bin/bash
# DNS-EXACT STOP/CONT pattern for the flow-rate override (throttle). Full agent logging.
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so
AGENT=${AGENT:-$F/agent/libbpftime-agent.so}
LOADER=$F/comm_plane/loaders/resource_loader
OBJ=${OBJ:-$F/comm_plane/bpf/flow_ratelimit.bpf.o}
ETHDEV=/usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
APP=$F/traffic/flow_churn
DD=/usr/local/lib/x86_64-linux-gnu
OUT=$F/results/thr_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-20}
pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null; sleep 1
SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
# boot STOPPED (bash pid == exec'd flow_churn pid after CONT), EXACT DNS exec-env pattern
bash -c 'kill -STOP "$$"; exec env BPFTIME_GLOBAL_SHM_NAME='"$SHM"' BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=thr --in-memory -- '"$ITERS"'' _ "$AGENT" "$DD" "$APP" > "$OUT/churn.log" 2>&1 &
PID=$!
sleep 2; echo "churn pid=$PID (stopped bash->exec)" | tee "$OUT/info"
# attach override BPF scoped to churn pid (syscall-server loader)
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SRV" \
  "$LOADER" --bpf "$OBJ" --lib "$ETHDEV" --no-pin --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 40); do grep -qiE "attached .*rte_flow_create|attached [1-9]" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
echo "loader: $(grep -aiE 'attached|error|ready' "$OUT/loader.log" | tail -2)"
kill -CONT "$PID"
for j in $(seq 1 25); do grep -q "CHURN done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== churn.log (agent + results) ====="; grep -aviE "^EAL:|TELEMETRY|freebsd.sysctl" "$OUT/churn.log"
pkill -9 -f flow_churn 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f resource_loader 2>/dev/null
echo "OUT=$OUT"

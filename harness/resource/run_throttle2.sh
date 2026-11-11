#!/bin/bash
# eSAC flow-rate THROTTLE live demo: override-attach loader + agent victim.
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so
AGENT=$F/agent/libbpftime-agent.so
TLOADER=$F/traffic/flow_throttle_loader
OBJ=$F/comm_plane/bpf/flow_ratelimit.bpf.o
ETHDEV=/usr/local/lib/x86_64-linux-gnu/librte_ethdev.so
APP=$F/traffic/flow_churn
DD=/usr/local/lib/x86_64-linux-gnu
OUT=$F/results/thr2_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-20}
pkill -9 -f flow_churn 2>/dev/null; pkill -9 -f flow_throttle 2>/dev/null; sleep 1
# resolve rte_flow_create file offset in librte_ethdev.so
OFF=0x$(readelf -sW "$ETHDEV" | awk '$8=="rte_flow_create"{print $2; exit}')
echo "rte_flow_create offset=$OFF"
SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
# boot churn STOPPED (agent), DNS-exact exec-env pattern
bash -c 'kill -STOP "$$"; exec env BPFTIME_GLOBAL_SHM_NAME='"$SHM"' BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Warn LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=thr2 --in-memory -- '"$ITERS"'' _ "$AGENT" "$DD" "$APP" > "$OUT/churn.log" 2>&1 &
PID=$!; sleep 2; echo "churn pid=$PID (stopped)"
# override-attach loader (syscall-server), scoped to churn pid, stays alive
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Warn LD_PRELOAD="$SRV" \
  "$TLOADER" "$OBJ" "$ETHDEV" "$OFF" "$PID" > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 30); do grep -qiE "throttle. ready|ATTACH_FAIL" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
echo "loader: $(grep -aiE 'attach|ready|fail' "$OUT/loader.log" | tail -3)"
kill -CONT "$PID"
for j in $(seq 1 25); do grep -q "CHURN done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== CHURN result (with THROTTLE: expect first ~4 OK then NULL) ====="; grep -aE "rte_flow_create=|CHURN done" "$OUT/churn.log"
echo "===== FLOWRL decisions ====="; grep -a FLOWRL "$OUT/churn.log" | head -25
echo "agent attached: $(grep -ac "Attach successfully" "$OUT/churn.log")"
pkill -9 -f flow_churn 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f flow_throttle 2>/dev/null
echo "OUT=$OUT"

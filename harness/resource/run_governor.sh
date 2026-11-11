#!/bin/bash
# eSAC governor live demo: throttle many control-plane APIs + quota host-mem.
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so
AGENT=$F/agent/libbpftime-agent.so
GLOADER=$F/traffic/cp_governor_loader
OBJ=$F/comm_plane/bpf/cp_governor.bpf.o
APP=$F/traffic/control_churn
DD=/usr/local/lib/x86_64-linux-gnu
ETHDEV=$DD/librte_ethdev.so
EALSO=$DD/librte_eal.so
OUT=$F/results/gov_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-12}
pkill -9 -f control_churn 2>/dev/null; pkill -9 -f cp_governor 2>/dev/null; sleep 1
off(){ readelf -sW "$1" | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print "0x"$2; exit}'; }
CFG="$OUT/hooks.cfg"
{
  echo "$ETHDEV $(off $ETHDEV rte_flow_create|sed s/0x//) cp_rate_ptr"
  echo "$ETHDEV $(off $ETHDEV rte_eth_promiscuous_enable|sed s/0x//) cp_rate_int"
  echo "$ETHDEV $(off $ETHDEV rte_eth_dev_set_mtu|sed s/0x//) cp_rate_int"
  echo "$ETHDEV $(off $ETHDEV rte_eth_dev_mac_addr_add|sed s/0x//) cp_rate_int"
  echo "$EALSO $(off $EALSO rte_malloc|sed s/0x//) mem_quota_ptr"
} > "$CFG"
echo "=== hooks.cfg ==="; cat "$CFG"
SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
bash -c 'kill -STOP "$$"; exec env BPFTIME_GLOBAL_SHM_NAME='"$SHM"' BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Warn LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=gov --in-memory -- '"$ITERS"'' _ "$AGENT" "$DD" "$APP" > "$OUT/churn.log" 2>&1 &
PID=$!; sleep 2; echo "churn pid=$PID"
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Warn LD_PRELOAD="$SRV" \
  "$GLOADER" "$OBJ" "$PID" "$CFG" > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 30); do grep -qiE "gov. ready" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
echo "=== loader attach ==="; grep -aE "\[gov\]" "$OUT/loader.log" | tail -8
kill -CONT "$PID"
for j in $(seq 1 25); do grep -q "CTLCHURN done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== CTLCHURN result (with governor) ====="; grep -aE "CTLCHURN|^\[" "$OUT/churn.log"
echo "===== governor decisions ====="; grep -aE "CPGOV|MEMGOV" "$OUT/churn.log" | head -40
pkill -9 -f control_churn 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f cp_governor 2>/dev/null
echo "OUT=$OUT"

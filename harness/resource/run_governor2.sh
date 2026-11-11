#!/bin/bash
# eSAC governor (extended, 9 symbols) live demo on mlx5 VF — proven standalone pattern.
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so
AGENT=$F/agent/libbpftime-agent.so
GLOADER=$F/traffic/cp_governor_loader
OBJ=$F/comm_plane/bpf/cp_governor.bpf.o
APP=$F/traffic/control_churn2
DD=/usr/local/lib/x86_64-linux-gnu
ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
OUT=$F/results/gov2x_$(date +%s); mkdir -p "$OUT"
ITERS=${ITERS:-12}
pkill -9 -f control_churn2 2>/dev/null; pkill -9 -f cp_governor 2>/dev/null; sleep 1
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print "0x"$2; exit}'; }
CFG="$OUT/hooks.cfg"
{
 echo "$ETH $(off $ETH rte_flow_create|sed s/0x//) cp_rate_ptr"
 echo "$ETH $(off $ETH rte_eth_promiscuous_enable|sed s/0x//) cp_rate_int"
 echo "$ETH $(off $ETH rte_eth_dev_set_mtu|sed s/0x//) cp_rate_int"
 echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add|sed s/0x//) cp_rate_int"
 echo "$ETH $(off $ETH rte_eth_dev_vlan_filter|sed s/0x//) cp_rate_int"
 echo "$ETH $(off $ETH rte_eth_xstats_get|sed s/0x//) cp_rate_int"
 echo "$EALS $(off $EALS rte_malloc|sed s/0x//) mem_quota_ptr"
} > "$CFG"
echo "hooks.cfg:"; cat "$CFG"
SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
bash -c 'kill -STOP "$$"; exec env BPFTIME_GLOBAL_SHM_NAME='"$SHM"' SPDLOG_LEVEL=Warn LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -l 2 -n 4 -a 0000:3b:01.3 --file-prefix=gov2x --in-memory -- '"$ITERS"'' _ "$AGENT" "$DD" "$APP" > "$OUT/churn.log" 2>&1 &
PID=$!; sleep 2; echo "churn pid=$PID"
env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=Warn LD_PRELOAD="$SRV" "$GLOADER" "$OBJ" "$PID" "$CFG" > "$OUT/loader.log" 2>&1 &
LP=$!
for j in $(seq 1 30); do grep -qi "gov. ready" "$OUT/loader.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
grep -aE "\[gov\]" "$OUT/loader.log" | tail -11
kill -CONT "$PID"
for j in $(seq 1 25); do grep -q "CTLCHURN2 done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$PID" 2>/dev/null || break; sleep 1; done
sleep 1
echo "===== RESULT ====="; grep -aE "^\[|CTLCHURN2 done" "$OUT/churn.log"
echo "cp_denials=$(grep -ac 'CPGOV DENY' "$OUT/churn.log") mem_denials=$(grep -ac 'MEMGOV DENY' "$OUT/churn.log")"
pkill -9 -f control_churn2 2>/dev/null; kill -9 $LP 2>/dev/null; pkill -9 -f cp_governor 2>/dev/null
echo "OUT=$OUT"

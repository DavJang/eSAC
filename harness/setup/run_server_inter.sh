#!/usr/bin/env bash
# host1 eSAC server-ONLY launcher for 40G inter-host (mlx5 VF, run as ROOT for DevX TIS).
# bpftime mask_probe L4, per-tenant cgroup+policy. Holds server for HOLD_SEC then cleans up.
# Client runs remotely on host2 (separate). server.conf port MAC field = PEER(client) mac.
set +u
OUT=${OUT:?}; S_NIC=${S_NIC:?}; S_IP=${S_IP:?}; C_IP=${C_IP:?}; GW_MAC=${GW_MAC:?}
SCPU=${SCPU:-6}; SOCKET_MEM=${SOCKET_MEM:-1024}; PAYLOAD=${PAYLOAD:-64}; PROTO=${PROTO:-tcp}
HOLD_SEC=${HOLD_SEC:-120}; POLICY_N=${POLICY_N:-2}; POL_PROTO=${POL_PROTO:-6}; SRV_DUR=${SRV_DUR:-200}
R=/home/sungwoo/FINAL
APP=${APP:-/home/sungwoo/FINAL/traffic/dperf_probe}
LIB=${LIB:-/home/sungwoo/FINAL/lib/fstack-dpdk}
AGENT=${eSAC_AGENT_PATH:-/home/sungwoo/FINAL/agent/libbpftime-agent.so}
SERVER=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
COMBO=${eSAC_COMBO_OBJ:-/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o}
UFUNC=${eSAC_UFUNC:-}
BURST_LOADER=${BURST_LOADER:-/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup_maskprobe}
IDT=/home/sungwoo/FINAL/tamper_sentinel/esac_pidcg_verify.py
mkdir -p "$OUT"; rm -f "$OUT/.ready" "$OUT/.done"
SHM=esac_inter_$(basename "$OUT")_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
srv= loader= CG=
cleanup(){ for p in "$loader" "$srv"; do [[ $p =~ ^[0-9]+$ ]]&&kill -KILL "$p" 2>/dev/null; done
 [[ -n $CG && -d $CG ]]&&rmdir "$CG" 2>/dev/null; [[ -f /dev/shm/$SHM ]]&&rm -f "/dev/shm/$SHM" 2>/dev/null
 rm -f /dev/hugepages/dperf-*map_* 2>/dev/null; }
trap cleanup EXIT
cat > "$OUT/server.conf" <<EOF
mode server
tx_burst 32
cpu $SCPU
duration ${SRV_DUR}s
payload_size $PAYLOAD
protocol $PROTO
keepalive 1ms
socket_mem $SOCKET_MEM
port $S_NIC $S_IP $C_IP $GW_MAC
client $C_IP 1
server $S_IP 1
listen 9 1
EOF
echo "start=$(date -Ins) S_NIC=$S_NIC S_IP=$S_IP C_IP=$C_IP GW_MAC=$GW_MAC combo=$(basename $COMBO)" > "$OUT/run.log"
# server launched STOP'd with bpftime agent (as root; whole script runs under sudo)
bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT${UFUNC:+:$UFUNC}" "$LIB" "$APP" "$OUT/server.conf" > "$OUT/server.log" 2>&1 </dev/null & srv=$!
sleep 1; state=$(awk '{print $3}' /proc/$srv/stat 2>/dev/null); [[ $state == T || $state == t ]] || { echo FAIL_stop >> "$OUT/run.log"; exit 1; }
CG=/sys/fs/cgroup/esac_inter_$(basename "$OUT")_${srv}
mkdir -- "$CG" || { echo FAIL_cg >> "$OUT/run.log"; exit 1; }; chmod 755 "$CG"
printf '%s\n' "$srv" | tee "$CG/cgroup.procs" >/dev/null || { echo FAIL_cgmove >> "$OUT/run.log"; exit 1; }
python3 "$IDT" init "$srv" "$CG" "$OUT/identity.json" >> "$OUT/id.log" 2>&1 || { echo FAIL_id >> "$OUT/run.log"; exit 1; }
CGID=$(stat -c %i "$CG"); echo "cgroup_id=$CGID" >> "$OUT/run.log"
A="${eSAC_ACTION:-ALLOW}"; python3 /home/sungwoo/FINAL/policy/gen_policy_n.py "$CGID" "$S_IP" "$C_IP" "$A" "$POLICY_N" "$POL_PROTO" > "$OUT/policy.json"
env BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" "$BURST_LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$APP" --pmd-lib "$APP" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 & loader=$!
echo "loader_pid=$loader" >> "$OUT/run.log"
ready=NO; for ((j=0;j<40;j++)); do grep -q "scoped uprobe target pid=$srv" "$OUT/loader.log" 2>/dev/null && grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && grep -qE 'L2 rules loaded=[0-9]+' "$OUT/loader.log" 2>/dev/null && { ready=YES; break; }; kill -0 "$loader" 2>/dev/null||break; sleep 1; done
echo "attach_ready=$ready" >> "$OUT/run.log"; [[ $ready == YES ]] || { echo FAIL_attach >> "$OUT/run.log"; exit 1; }
kill -CONT "$srv"
sleep 2; kill -0 "$srv" 2>/dev/null || { echo FAIL_startup >> "$OUT/run.log"; exit 1; }
echo "server_pid=$srv READY" >> "$OUT/run.log"; touch "$OUT/.ready"
if [ "${TAMPER_SENTINEL:-0}" = 1 ]; then
  EVBT='"'"'tracepoint:syscalls:sys_enter_mprotect /pid=='"'"'"$srv"'"'"' && (args->prot & 2)/ { signal(9); }
tracepoint:syscalls:sys_enter_openat /pid=='"'"'"$srv"'"'"'/ { $fn=str(args->filename); if($fn=="/proc/self/mem"){ signal(9); } }'"'"'  # TAMPER_SENTINEL event TamperSentinel
  taskset -c "${POLCPU:-30}" bpftrace --unsafe -e "$EVBT" > "$OUT/tamper_sentinel_ev.log" 2>&1 & echo "tamper_sentinel_pid=$!" >> "$OUT/run.log"
fi
# hold for the measurement window (client runs on host2)
for ((h=0;h<HOLD_SEC;h++)); do kill -0 "$srv" 2>/dev/null || break; sleep 1; done
srx=$(grep -aoE 'tcpRx\s+[0-9,]+' "$OUT/server.log" 2>/dev/null|tr -d ,|awk '{print $2}'|sort -n|tail -1)
prx=$(grep -a '^pktRx' "$OUT/server.log" 2>/dev/null|awk '{print $2}'|tr -d ,|sort -n|tail -1)
echo "server_tcpRx_max=$srx server_pktRx_max=$prx done=YES" >> "$OUT/run.log"; touch "$OUT/.done"

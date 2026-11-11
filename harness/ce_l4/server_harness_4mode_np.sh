#!/usr/bin/env bash
# Isolated 40G mlx5 attach smoke, derived from run_inter_server.sh.
set -u
MODE=${MODE:?}; OUT=${OUT:?}; DUR=${DUR:-20}; PAYLOAD=${PAYLOAD:-64}; KEEPALIVE=${KEEPALIVE:-20us}
ACTION=${ACTION:-ALLOW}
NPOL=${NPOL:-2}
case "$ACTION" in ALLOW|DROP|KILL) ;; *) echo "Invalid ACTION=$ACTION" >&2; exit 2;; esac
SCPU=${SCPU:-2}; POLCPU=${POLCPU:-4}; PROCPU=${PROCPU:-5}; SOCKET_MEM=${SOCKET_MEM:-1024}
R=/home/sungwoo/FINAL; APP=${APP:-/home/sungwoo/FINAL/traffic/dperf_probe}; LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent.so
SERVER=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
COMBO=${COMBO:-/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_bpftime_cgroup.bpf.o}
KOBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_kernel128.bpf.o
GUARD=/home/sungwoo/FINAL/tamper_sentinel/bin; IDT=/home/sungwoo/FINAL/tamper_sentinel/esac_pidcg_verify.py
PORT=${PORT:-0000:3b:00.0}; SIP=192.168.1.1; SPEER=192.168.0.1; SMAC=3c:fd:fe:c4:93:38
mkdir -p "$OUT"; rm -f "$OUT/.ready" "$OUT/.done"
SHM=esac_inter_$(basename "$OUT")_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
srv= loader= polw= prow= polr= pror= resl= resr= kr= CG=
cleanup(){ for p in "$polr" "$pror" "$kr" "$resr" "$resl"; do [[ $p =~ ^[0-9]+$ ]]&&sudo -n kill -TERM "$p" 2>/dev/null||true;done
 for p in "$srv" "$loader" "$polw" "$prow"; do [[ $p =~ ^[0-9]+$ ]]&&kill -TERM "$p" 2>/dev/null||true;done; sleep 1
 for p in "$srv" "$loader"; do [[ $p =~ ^[0-9]+$ ]]&&kill -KILL "$p" 2>/dev/null||true;done
 [[ -n $CG && -d $CG ]]&&sudo -n rmdir "$CG" 2>/dev/null||true; [[ -f /dev/shm/$SHM ]]&&sudo -n rm -f "/dev/shm/$SHM" 2>/dev/null||true; }
trap cleanup EXIT
SDUR=$((DUR+35))
cat > "$OUT/server.conf" <<CONF
mode server
tx_burst ${TB:-32}
cpu $SCPU
duration ${SDUR}s
payload_size $PAYLOAD
protocol ${PROTO:-tcp}
keepalive $KEEPALIVE
socket_mem $SOCKET_MEM
port $PORT $SIP $SPEER $SMAC
client $SPEER 1
server $SIP 1
listen 9 1
CONF
[[ "$SCPU" == *" "* ]] && echo rss >> "$OUT/server.conf"
echo "start=$(date -Ins) mode=$MODE" > "$OUT/run.log"
if [[ $MODE == none ]]; then
  env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" "$APP" -c "$OUT/server.conf" > "$OUT/server.log" 2>&1 </dev/null & srv=$!
elif [[ $MODE == kernel ]]; then
  bash -c 'kill -STOP "$$"; exec env -u LD_PRELOAD LD_LIBRARY_PATH="$1" "$2" -c "$3"' _ "$LIB" "$APP" "$OUT/server.conf" > "$OUT/server.log" 2>&1 </dev/null & srv=$!
  sleep 1
  python3 /home/sungwoo/FINAL/policy/gen_policy_kern.py "$SIP" "$SPEER" "$ACTION" "$NPOL" 6 > "$OUT/policy.json"
  sudo -n "/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_kernel128" --bpf "$KOBJ" --lib "$APP" --pmd-lib "$APP" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 & loader=$!
  sleep 1; kr=$(pgrep -P "$loader"|head -1||true); rdy=NO
  for ((j=0;j<40;j++)); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log"&&{ rdy=YES;break;}; kill -0 "$loader" 2>/dev/null||break; sleep 1; done
  [[ $rdy == YES ]]||{ echo FAIL_attach >>"$OUT/run.log"; exit 1;}; kill -CONT "$srv"
else
  bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT" "$LIB" "$APP" "$OUT/server.conf" > "$OUT/server.log" 2>&1 </dev/null & srv=$!
  sleep 1; CG=/sys/fs/cgroup/esac_inter_$(basename "$OUT")_${srv}
  sudo -n mkdir -- "$CG"; sudo -n chmod 755 "$CG"; printf '%s\n' "$srv"|sudo -n tee "$CG/cgroup.procs" >/dev/null
  python3 "$IDT" init "$srv" "$CG" "$OUT/identity.json" >>"$OUT/identity_checks.log" 2>&1||{ echo FAIL_id >>"$OUT/run.log"; exit 1;}
  CGID=$(stat -c %i "$CG")
  python3 /home/sungwoo/FINAL/policy/gen_policy_n.py "$CGID" "$SIP" "$SPEER" "$ACTION" "$NPOL" 6 > "$OUT/policy.json"
  env BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" "${BURST_LOADER:-/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup}" --max-burst-inspect "${MAX_BURST_INSPECT:-32}" --bpf "$COMBO" --lib "$APP" --pmd-lib "$APP" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 & loader=$!
  rdy=NO; for ((j=0;j<40;j++)); do grep -q "scoped uprobe target pid=$srv" "$OUT/loader.log"&&grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log"&&grep -q 'L2 rules loaded=' "$OUT/loader.log"&&{ rdy=YES;break;}; kill -0 "$loader" 2>/dev/null||break; sleep 1; done
  [[ $rdy == YES ]]||{ echo FAIL_attach >>"$OUT/run.log"; exit 1;}
  printf '{"default":{"max_lcore_count":64,"max_mbuf_count":1048576,"max_tx_queues":128,"max_socket_mem_mb":4096,"action_on_violation":"KILL"}}\n' > "$OUT/rp.json"
  sudo -n "/home/sungwoo/FINAL/comm_plane/loaders/resource_loader" --bpf "/home/sungwoo/FINAL/comm_plane/bpf/resource_monitor.bpf.o" --lib /usr/local/lib/x86_64-linux-gnu/librte_eal.so --policy "$OUT/rp.json" -v > "$OUT/resl.log" 2>&1 & resl=$!
  for ((j=0;j<40;j++)); do grep -q '\[resource_loader\] ready' "$OUT/resl.log"&&break; sleep 0.25; done
  resr=$(pgrep -P "$resl"|head -1||true)
  kill -CONT "$srv"; sleep 8
  sudo -n taskset -c "$POLCPU" bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$srv && (args->prot & 2)/ { signal(9); } tracepoint:syscalls:sys_enter_openat /pid==$srv/ { \$fn=str(args->filename); if(\$fn==\"/proc/self/mem\"){ signal(9); } }" > "$OUT/tamper_sentinel_ev.log" 2>&1 & tamper_sentinel_ev=$!
  for ((j=0;j<60;j++)); do grep -q 'Attaching' "$OUT/tamper_sentinel_ev.log"&&break; kill -0 "$tamper_sentinel_ev" 2>/dev/null||break; sleep 0.1; done
  grep -q 'Attaching' "$OUT/tamper_sentinel_ev.log"||{ echo FAIL_tamper_sentinel_ev >>"$OUT/run.log"; exit 1;}
  polr=$tamper_sentinel_ev; pror=$tamper_sentinel_ev
fi
echo "server_pid=$srv polr=$polr pror=$pror" >> "$OUT/run.log"
sleep 2; kill -0 "$srv" 2>/dev/null||{ echo FAIL_startup >>"$OUT/run.log"; exit 1;}
touch "$OUT/.ready"
sleep $((DUR+10))
pps=$(awk '/Total Numbers/{exit}/^pktRx/{x=$2;gsub(",","",x);print x}' "$OUT/server.log"|tail -8|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)]}')
bits=$(awk '/Total Numbers/{exit}/^pktRx/{x=$6;gsub(",","",x);print x}' "$OUT/server.log"|tail -8|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)]}')
tot=$(grep -oE 'tcpRx +[0-9,]+' "$OUT/server.log"|tr -d ','|awk '{print $2}'|sort -n|tail -1)
echo "pps_med=${pps:-NA} bits_med=${bits:-NA} tcpRx_total=${tot:-NA}" >> "$OUT/run.log"
touch "$OUT/.done"

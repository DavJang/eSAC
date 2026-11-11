#!/usr/bin/env bash
# Isolated 40G mlx5 attach smoke, derived from run_inter_server.sh.
set -u
MODE=${MODE:?}; OUT=${OUT:?}; DUR=${DUR:-20}; PAYLOAD=${PAYLOAD:-64}; KEEPALIVE=${KEEPALIVE:-20us}
ACTION=${ACTION:-ALLOW}
case "$ACTION" in ALLOW|DROP|KILL) ;; *) echo "Invalid ACTION=$ACTION" >&2; exit 2;; esac
SCPU=${SCPU:-2}; POLCPU=${POLCPU:-4}; PROCPU=${PROCPU:-5}; SOCKET_MEM=${SOCKET_MEM:-1024}
R=/home/sungwoo/FINAL; APP=${APP:-/home/sungwoo/FINAL/traffic/dperf_probe}; LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
AGENT=${eSAC_AGENT_PATH:-/home/sungwoo/FINAL/agent/libbpftime-agent-hs.so}
HS_LIB=${eSAC_HS_LIB:-/home/sungwoo/FINAL/l7/ctl/esac_hs_ufunc.so}
HS_PATTERNS=${eSAC_HS_PATTERNS:-}
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
PLINE="payload_size $PAYLOAD"
[ -n "${PAYLOAD_FILE:-}" ] && PLINE="payload_file $PAYLOAD_FILE"
cat > "$OUT/server.conf" <<CONF
mode server
tx_burst ${TB:-32}
cpu $SCPU
duration ${SDUR}s
$PLINE
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
  printf '{"rules":[{"layer":"L2","dst_ip":"192.168.1.1","proto":6,"dst_port":9,"action":"%s"},{"layer":"L2","dst_ip":"192.168.0.1","proto":6,"action":"ALLOW"}]}\n' "$ACTION" > "$OUT/policy.json"
  sudo -n "/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_kernel128" --bpf "$KOBJ" --lib "$APP" --pmd-lib "$APP" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 & loader=$!
  sleep 1; kr=$(pgrep -P "$loader"|head -1||true); rdy=NO
  for ((j=0;j<40;j++)); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log"&&{ rdy=YES;break;}; kill -0 "$loader" 2>/dev/null||break; sleep 1; done
  [[ $rdy == YES ]]||{ echo FAIL_attach >>"$OUT/run.log"; exit 1;}; kill -CONT "$srv"
else
  bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" eSAC_HS_PATTERNS="$5" "$3" -c "$4"' _ "$AGENT:$HS_LIB" "$LIB" "$APP" "$OUT/server.conf" "$HS_PATTERNS" > "$OUT/server.log" 2>&1 </dev/null & srv=$!
  sleep 1; CG=/sys/fs/cgroup/esac_inter_$(basename "$OUT")_${srv}
  sudo -n mkdir -- "$CG"; sudo -n chmod 755 "$CG"; printf '%s\n' "$srv"|sudo -n tee "$CG/cgroup.procs" >/dev/null
  python3 "$IDT" init "$srv" "$CG" "$OUT/identity.json" >>"$OUT/identity_checks.log" 2>&1||{ echo FAIL_id >>"$OUT/run.log"; exit 1;}
  CGID=$(stat -c %i "$CG")
  PNUM=6; [ "${PROTO:-tcp}" = udp ] && PNUM=17
  printf '{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.1","proto":%s,"dst_port":9,"action":"%s"},{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.0.1","proto":%s,"action":"ALLOW"}]}\n' "$CGID" "$PNUM" "$ACTION" "$CGID" "$PNUM" > "$OUT/policy.json"
  env BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" "${BURST_LOADER:-/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup}" --max-burst-inspect "${MAX_BURST_INSPECT:-32}" --bpf "$COMBO" --lib "$APP" --pmd-lib "$APP" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 & loader=$!
  rdy=NO; for ((j=0;j<40;j++)); do grep -q "scoped uprobe target pid=$srv" "$OUT/loader.log"&&grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log"&&grep -q 'L2 rules loaded=2' "$OUT/loader.log"&&{ rdy=YES;break;}; kill -0 "$loader" 2>/dev/null||break; sleep 1; done
  [[ $rdy == YES ]]||{ echo FAIL_attach >>"$OUT/run.log"; exit 1;}
  printf '{"default":{"max_lcore_count":64,"max_mbuf_count":1048576,"max_tx_queues":128,"max_socket_mem_mb":4096,"action_on_violation":"KILL"}}\n' > "$OUT/rp.json"
  sudo -n "/home/sungwoo/FINAL/comm_plane/loaders/resource_loader" --bpf "/home/sungwoo/FINAL/comm_plane/bpf/resource_monitor.bpf.o" --lib /usr/local/lib/x86_64-linux-gnu/librte_eal.so --policy "$OUT/rp.json" -v > "$OUT/resl.log" 2>&1 & resl=$!
  for ((j=0;j<40;j++)); do grep -q '\[resource_loader\] ready' "$OUT/resl.log"&&break; sleep 0.25; done
  resr=$(pgrep -P "$resl"|head -1||true)
  sudo -n taskset -c "$POLCPU" env BPFTIME_GLOBAL_SHM_NAME="$SHM" "$GUARD/tamper_sentinel_cgroup" "$srv" > "$OUT/polw.log" 2>&1 & polw=$!
  for ((j=0;j<40;j++)); do grep -q "POLICY_READY .* pid=$srv " "$OUT/polw.log"&&break; sleep 0.1; done
  grep -q "POLICY_READY .* pid=$srv " "$OUT/polw.log"||{ echo FAIL_polwd >>"$OUT/run.log"; exit 1;}
  polr=$(sed -n 's/.*POLICY_READY self_pid=\([0-9]*\).*/\1/p' "$OUT/polw.log"|head -1)
  kill -CONT "$srv"; sleep 1
  sed -n 's/.*DRIVER level: \([^ ]*\) @ .*offset=0x\([0-9a-fA-F]*\)).*/0x\2 \1/p' "$OUT/loader.log"|sort -u -k1,1 > "$OUT/manifest.txt"
  [[ $(wc -l < "$OUT/manifest.txt") -eq 22 ]]||{ echo FAIL_manifest >>"$OUT/run.log"; exit 1;}
  sudo -n taskset -c "$PROCPU" "$GUARD/tamper_sentinel_prologue" "$srv" "$APP" "$OUT/manifest.txt" > "$OUT/prow.log" 2>&1 & prow=$!
  for ((j=0;j<40;j++)); do grep -q "READY .* pid=$srv hooks=22" "$OUT/prow.log"&&break; sleep 0.1; done
  grep -q "READY .* pid=$srv hooks=22" "$OUT/prow.log"||{ echo FAIL_prowd >>"$OUT/run.log"; exit 1;}
  pror=$(sed -n 's/.*READY self_pid=\([0-9]*\).*/\1/p' "$OUT/prow.log"|head -1)
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

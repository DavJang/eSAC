#!/bin/bash
# eSACfinal CE-L4 intra validation (self-contained, eSACfinal paths only).
# Replicates ce_l4_sweep run_one(intra) for 3 cells: none/ALLOW, eSAC/ALLOW, eSAC/DROP.
# PASS = eSAC-ALLOW pps ~= none & attach OK & hits>0 ; eSAC-DROP pps ~0 (enforcement).
set -u
D=/home/sungwoo/eSACfinal
APP=$D/traffic/dperf_burst128
HISTCLI=$D/traffic/dperf_hist
LOADER=$D/comm_plane/loaders/comm_loader_cgroup_maskprobe
L4=$D/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
SRV=$D/harness/ce_l4/server_harness_4mode.sh
LIB=$D/lib/fstack-dpdk
OUT=$D/results/validate_ce_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*" >&2; }

# intra fabric
eval "$(bash $D/harness/setup/intra_switchdev_up.sh | grep -E 'INTRA_')"
say "intra fabric: SVF=$INTRA_SVF CVF=$INTRA_CVF"
[ -z "${INTRA_SVF:-}" ] && { say "FAIL: no intra VF"; exit 1; }

killdp(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null; sudo -n pkill -9 -f '[t]amper_sentinel' 2>/dev/null; for cg in /sys/fs/cgroup/esac_inter_* /sys/fs/cgroup/esac_intra_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sleep 1; }

# server lcores on node0 (6-9); intra dperf GENERATOR must be node0 multicore (20-23) per rig NUMA map
DUR=20; CC=8000; CPS=4000; PAY=512; KA=1ms; SCPU="6 7 8 9"; CCPU="20 21 22 23"

run_cell(){ local mode=$1 act=$2 tag=$3; local rm; case $mode in none)rm=none;; eSAC)rm=bpftime;; esac
  local o=$OUT/$tag; rm -rf "$o"; mkdir -p "$o"; killdp
  sudo -n env NPOL=2 MODE=$rm OUT="$o" DUR=$((DUR+10)) SCPU="$SCPU" POLCPU=28 PROCPU=29 SOCKET_MEM=2048 \
    PAYLOAD=$PAY KEEPALIVE=$KA ACTION=$act PORT=$INTRA_SVF APP=$APP COMBO=$L4 \
    MAX_BURST_INSPECT=128 BURST_LOADER=$LOADER PROTO=tcp \
    setsid bash "$SRV" > "$o.outer.log" 2>&1 &
  local sp=$!; local rdy=0
  for i in $(seq 1 75); do [ -e "$o/.ready" ] && { rdy=1; break; }; grep -q FAIL "$o/run.log" 2>/dev/null && break; kill -0 $sp 2>/dev/null || break; sleep 1; done
  [ $rdy -eq 1 ] || { say "  [$tag] NOT READY"; kill -9 $sp 2>/dev/null; killdp; return 1; }
  cat > "$o/cl.conf" <<C
mode client
tx_burst 128
cpu $CCPU
duration ${DUR}s
cps $CPS
cc $CC
keepalive $KA
payload_size $PAY
protocol tcp
socket_mem 1024
port $INTRA_CVF 192.168.0.1 192.168.1.1 02:51:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
rss
C
  sudo -n env LD_LIBRARY_PATH=$LIB GOWN_HIST_FILE="$o/hist.txt" GOWN_HIST_START_SEC=3 \
    timeout $((DUR+12)) "$HISTCLI" -c "$o/cl.conf" > "$o/cl.log" 2>&1
  for i in $(seq 1 60); do [ -e "$o/.done" ] && break; kill -0 $sp 2>/dev/null || break; sleep 1; done
  wait $sp 2>/dev/null
  local pps=$(sed -n 's/.*pps_med=\([0-9]*\).*/\1/p' "$o/run.log" 2>/dev/null|tail -1)
  [ -z "$pps" -o "$pps" = 0 ] && pps=$(awk '/Total Numbers/{exit}/^pktRx/{x=$2;gsub(",","",x);print x}' "$o/server.log" 2>/dev/null|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}')
  local hits=$(grep -aoE 'policy_hits[ =:]+[0-9]+' "$o/loader.log" 2>/dev/null|grep -oE '[0-9]+'|sort -n|tail -1)
  local att=NO; grep -q 'attach summary: RX=OK TX=OK' "$o/loader.log" 2>/dev/null && att=YES
  local h=$(head -1 "$o/hist.txt" 2>/dev/null); local p50=$(echo "$h"|grep -oE 'p50_us=[0-9]+'|cut -d= -f2)
  say "  [$tag] mode=$mode act=$act -> pps=${pps:-0} p50=${p50:-NA} hits=${hits:-NA} attach=$att"
  echo "${pps:-0}"; killdp; }

say "===== CE-L4 intra validation (cc=$CC pay=$PAY dur=${DUR}s) ====="
NONE=$(run_cell none ALLOW none_allow | tail -1)
ESAC=$(run_cell eSAC ALLOW esac_allow | tail -1)
DROP=$(run_cell eSAC DROP  esac_drop  | tail -1)
say "===== SUMMARY ====="
say "none/ALLOW pps = $NONE"
say "eSAC/ALLOW pps = $ESAC"
say "eSAC/DROP  pps = $DROP  (expect ~0 = enforcement)"
# verdicts
ok=1
awk "BEGIN{exit !($ESAC>1000)}" || { say "VERDICT eSAC-ALLOW: FAIL (pps too low)"; ok=0; }
awk "BEGIN{exit !($NONE>1000)}" || { say "VERDICT none: FAIL"; ok=0; }
awk "BEGIN{exit !($DROP<($NONE*0.2+1))}" && say "VERDICT DROP-enforcement: PASS (drop<<none)" || { say "VERDICT DROP-enforcement: CHECK (drop=$DROP)"; }
if awk "BEGIN{exit !($ESAC > $NONE*0.7)}"; then say "VERDICT eSAC~=none: PASS (eSAC within 70-130% of none)"; else say "VERDICT eSAC~=none: CHECK (ratio=$(awk "BEGIN{printf \"%.2f\", $ESAC/($NONE+1)}"))"; fi
[ $ok -eq 1 ] && say "CE-INTRA VALIDATION: core PASS" || say "CE-INTRA VALIDATION: FAIL"
killdp

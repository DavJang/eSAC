#!/bin/bash
# eSAC pps campaign - INTRA (host1 VF-to-VF, switchdev + tc hairpin).
# ALLOW throughput vs none, with per-config DROP enforcement PROOF (so a config that
# silently bypasses -> FAIL, no fake 'same as none' numbers).
# dims: dir{rx,tx} x layer{l4,l7} x core{1,2,4}; payload sweep (64/256/512/1024/1400 @ saturate)
#       + load sweep (cc ladder @ 1400B). none baseline per (dir,core).
# RX: eSAC=server (loader=rxonly, attach server). TX: eSAC=client (loader=mlx5tx, attach client).
# metric: deliv = server pktRx median(nonzero); offered = client pktTx max. ALL esac cells --enforcement.
set -u
TESTMODE=${TESTMODE:-0}
PF_INTRA=0000:3b:00.0; IF_INTRA=enp59s0f0np0
DNS=/home/sungwoo/eSACfinal/traffic/dperf_dns
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk
AGENT=/home/sungwoo/eSACfinal/agent/libbpftime-agent-hs.so
BSRV=/home/sungwoo/eSACfinal/agent/libbpftime-syscall-server.so
UFUNC=/home/sungwoo/eSACfinal/l7/ctl/esac_suricata_dns_ufunc.so
L4OBJ=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
L7OBJ=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k_hs_gate.bpf.o
L_RX=/home/sungwoo/eSACfinal/comm_plane/loaders/comm_loader_rxonly
L_TX=/home/sungwoo/eSACfinal/comm_plane/loaders/comm_loader_mlx5tx
OFFS=/home/sungwoo/eSACfinal/comm_plane/offsets.json
IDT=/home/sungwoo/eSACfinal/tamper_sentinel/esac_pidcg_verify.py
GENPOL=/home/sungwoo/eSACfinal/policy/gen_policy_n.py
PAYDIR=/home/sungwoo/eSACfinal/l7/payloads
HSCTL=/home/sungwoo/eSACfinal/l7/ctl/esac_hs_ctl_rx_urlhaus
DOMCTL=/home/sungwoo/eSACfinal/l7/ctl/esac_dom_ctl_bulk
PATS=${PATS:-/home/sungwoo/eSACfinal/l7/patterns/suricata_dns_patterns.txt}
SIP=192.168.91.1; CIP=192.168.91.2; SMAC=02:50:00:00:01:01; CMAC=02:50:00:00:01:02
SRV_CORES="2 3 4 5"; CLI_CORES="6 7 8 9"
DUR_C=${DUR_C:-18}          # client flood seconds
SAT_CC_PER=${SAT_CC_PER:-8000}             # cc per core for saturate (100%)
LOAD_CC_PER="800 1600 2600 4000"   # lower load ladder (x core); top (saturate) comes from payload sweep 1400
PAYS="${PAYS:-64 128 256 512 1024 1400}"
CORES="${CORES:-1 2 4}"
[ "$TESTMODE" = 1 ] && { CORES="1"; PAYS="64 1400"; LOAD_CC_PER="1600"; DUR_C=10; }
[ "${VALIDATE:-0}" = 1 ] && { CORES="1"; PAYS="1400"; LOAD_CC_PER="1600"; DUR_C=20; }
PAYREST=$(echo $PAYS | tr ' ' '\n' | grep -v '^1400$' | tr '\n' ' ')   # payload sweep minus the 1400 anchor
[ -n "${ONLYCORES:-}" ] && CORES="$ONLYCORES"   # re-run a subset of core counts

ROOT=/home/sungwoo/esac_pps_intra_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"
RES="$ROOT/RESULTS.txt"; LOG="$ROOT/LOG"; : > "$RES"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
cpul(){ local n=$1; shift; local a=($@); local o=""; for((i=0;i<n;i++)); do o="$o ${a[i]}"; done; echo "${o# }"; }  # SPACE-separated (dperf requires)
KILL1(){ pkill -9 -x dperf 2>/dev/null; pkill -9 -f comm_loader_rxonly 2>/dev/null; pkill -9 -f comm_loader_mlx5tx 2>/dev/null; for cg in /sys/fs/cgroup/esac_*; do rmdir "$cg" 2>/dev/null; done; sleep 1; }
hsdb(){ rm -f /dev/shm/esac_hs_db /dev/shm/esac_dom_db; "$DOMCTL" /esac_dom_db /dev/null none >/dev/null 2>&1; chmod a+r /dev/shm/esac_dom_db 2>/dev/null; "$HSCTL" /esac_hs_db "$PATS" none >/dev/null 2>&1; chmod a+r /dev/shm/esac_hs_db 2>/dev/null; }
maxrx(){ grep -aE "^pktRx" "$1" 2>/dev/null|awk '{v=$2;gsub(/,/,"",v);print v}'|sort -n|tail -1; }
mx(){ grep -aoE "$2 +[0-9,]+" "$1" 2>/dev/null|grep -oE "[0-9,]+$"|tr -d ,|sort -n|tail -1; }
getf(){ grep "key=$1 " "$RES" 2>/dev/null|tail -1|grep -oE "$2=[0-9]+"|head -1|cut -d= -f2; }
# parse loader queue_stats -> "rx allow drop policy_hits" (summed over queues)
insp(){ awk '/queue_stats/{f=1;next} f&&/^[0-9]/{rx+=$3;dr+=$5;al+=$6;ph+=$12} END{printf "%d %d %d %d",rx+0,al+0,dr+0,ph+0}' "$1" 2>/dev/null; }

RDY=NO
# attach loader to pid.  args: pid obj act pp d shm loader enf
#   enf="--enforcement" applies drops (and arms the prologue-kill TamperSentinel) -> use ONLY for DROP proof.
#   enf="" = detection: full per-packet inspection (policy_hits counted) but no drop/kill -> use for ALLOW throughput.
attach(){ local pid=$1 obj=$2 act=$3 pp=$4 d=$5 shm=$6 loader=$7 enf=${8:-}
  local CG=/sys/fs/cgroup/esac_$pid; mkdir -- "$CG" 2>/dev/null; chmod 755 "$CG"; echo "$pid" > "$CG/cgroup.procs"
  python3 "$IDT" init "$pid" "$CG" "$d/identity.json" > "$d/id.log" 2>&1
  local cgid=$(stat -c %i "$CG")
  python3 "$GENPOL" "$cgid" "$POLSIP" "$POLCIP" "$act" ${NPOL:-2} "$pp" > "$d/policy.json"
  env BPFTIME_GLOBAL_SHM_NAME=$shm BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$BSRV" \
    "$loader" --max-burst-inspect 128 --bpf "$obj" --lib "$DNS" --pmd-lib "$DNS" --offsets "$OFFS" \
    --policy "$d/policy.json" --no-pin $enf --attach-pid "$pid" -v > "$d/loader.log" 2>&1 &
  LDRPID=$!
  RDY=NO; for j in $(seq 1 55); do grep -qE "attach summary:.*OK" "$d/loader.log" 2>/dev/null && { RDY=YES; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 1; done; }

intra_up(){ KILL1
  echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; sleep 2
  devlink dev eswitch set pci/$PF_INTRA mode switchdev 2>/dev/null; sleep 1
  ethtool -K $IF_INTRA hw-tc-offload on 2>/dev/null
  echo 2 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF_INTRA/virtfn1 ] && break; sleep 1; done; sleep 3
  ip link set $IF_INTRA up 2>/dev/null
  SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn0))
  CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn1))
  rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf0vf$1" ] && { basename "$n"; return; }; done; }
  SREP=$(rep 0); CREP=$(rep 1)
  ip link set $IF_INTRA vf 0 mac $SMAC 2>/dev/null; ip link set $IF_INTRA vf 1 mac $CMAC 2>/dev/null
  ip link set $IF_INTRA vf 0 spoofchk off 2>/dev/null; ip link set $IF_INTRA vf 0 trust on 2>/dev/null
  ip link set $IF_INTRA vf 1 spoofchk off 2>/dev/null; ip link set $IF_INTRA vf 1 trust on 2>/dev/null
  ip link set $SREP up 2>/dev/null; ip link set $CREP up 2>/dev/null
  tc qdisc add dev $SREP ingress 2>/dev/null; tc qdisc add dev $CREP ingress 2>/dev/null
  tc filter add dev $SREP ingress protocol all flower skip_sw action mirred egress redirect dev $CREP 2>/dev/null
  tc filter add dev $CREP ingress protocol all flower skip_sw action mirred egress redirect dev $SREP 2>/dev/null
  log "intra VFs S=$SVF C=$CVF tc=$(tc filter show dev $SREP ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1)"; }
intra_down(){ KILL1; echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; devlink dev eswitch set pci/$PF_INTRA mode legacy 2>/dev/null; }

# mkconf  file mode(server|client) pcidev selfip peerip peermac ncore payload_spec cc ka
mkconf(){ local f=$1 mode=$2 pci=$3 sip=$4 pip=$5 pmac=$6 nc=$7 pay=$8 cc=$9 ka=${10}
  local cores; if [ "$mode" = server ]; then cores=$(cpul $nc $SRV_CORES); else cores=$(cpul $nc $CLI_CORES); fi
  local sm; if [ "$mode" = server ]; then sm="socket_mem 2048"; else sm="socket_mem 0,2048"; fi
  # for server (node0) socket_mem goes on node0 = first field; both NICs node0 so use 2048 on node0 only
  { echo "mode $mode"; echo "tx_burst 128"; echo "cpu $cores";
    [ "$mode" = server ] && echo "duration $((DUR_C+12))s" || echo "duration ${DUR_C}s";
    echo "$pay"; echo "protocol udp";
    [ "$mode" = client ] && { echo "cps 4000"; echo "cc $cc"; }
    echo "keepalive ${ka}us"; echo "socket_mem 2048";
    echo "port $pci $sip $pip $pmac"; echo "client $CIP 1"; echo "server $SIP 1"; echo "listen 9 1";
    [ "$nc" -gt 1 ] && echo "rss"; } > "$f"
}

# cell: DIR LAYER NCORE PAYBYTES CC CASE(pass|drop) LABEL
cell(){ local DIR=$1 LAYER=$2 NC=$3 PB=$4 CC=$5 CASE=$6 LAB=$7
  local key="intra_${DIR}_${LAYER}_c${NC}_p${PB}_cc${CC}_${CASE}"
  grep -q "KEY .*key=$key " "$RES" 2>/dev/null && { log "skip done $key"; return; }
  local d="$ROOT/$key"; mkdir -p "$d"
  local obj=$L4OBJ pp=17; [ "$LAYER" = l7 ] && obj=$L7OBJ
  local act=ALLOW; [ "$CASE" = drop ] && [ "$LAYER" = l4 ] && act=DROP
  # payload spec: L4 -> payload_size; L7 -> payload_file (benign .com, or .su for drop)
  local payspec
  if [ "$LAYER" = l7 ]; then
    local pf="$PAYDIR/dnsq_com_$(printf %04d $PB).bin"; [ "$CASE" = drop ] && pf="$PAYDIR/dnsq_su_$(printf %04d $PB).bin"
    payspec="payload_file $pf"
  else
    payspec="payload_size $PB"
  fi
  POLSIP=$SIP; POLCIP=$CIP; KILL1; hsdb
  local eloader=$L_RX; [ "$DIR" = tx ] && eloader=$L_TX
  # DROP proof uses --enforcement (applies drops; may kill tenant). ALLOW throughput uses
  # detection (no --enforcement): full per-packet inspection w/o kill, measured via loader policy_hits.
  local ENF=""; [ "$CASE" = drop ] && ENF="--enforcement"
  local LDRPID=""
  # build confs. eSAC side uses payspec (inspected). none side uses payload_size PB (server) just for responses.
  # client ALWAYS sends the inspected payspec (it is the sender in both directions);
  # server always uses payload_size for its responses. Only the LOADER side differs.
  mkconf "$d/server.conf" server $SVF $SIP $CIP $CMAC $NC "payload_size $PB" 0 ${KA:-1000}
  mkconf "$d/client.conf" client $CVF $CIP $SIP $SMAC $NC "$payspec" $CC ${KA:-1000}
  local SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
  # launch none side (plain) and eSAC side (STOP'd + agent preload)
  if [ "$DIR" = rx ]; then
    # eSAC = server (STOP), none = client (plain, after attach)
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/server.conf" > "$d/server.log" 2>&1 &
    local epid=$!; sleep 1
    [ "$(awk '{print $3}' /proc/$epid/stat 2>/dev/null)" != T ] && { echo "KEY key=$key mode=esac verdict=FAIL_NOSTOP" | tee -a "$RES"; KILL1; return; }
    attach "$epid" "$obj" "$act" "$pp" "$d" "$SHM" "$eloader" "$ENF"; LDRPID=$LDRPID
    [ "$RDY" != YES ] && { echo "KEY key=$key mode=esac verdict=FAIL_ATTACH $(grep -aE 'rror|summary' "$d/loader.log"|tail -1|tr ' ' '_')" | tee -a "$RES"; kill -9 $epid 2>/dev/null; KILL1; return; }
    kill -CONT "$epid"; sleep 6
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+4)) "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep $((DUR_C+3))
  else
    # eSAC = client (STOP), none = server (plain) launched first
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+14)) "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 &
    sleep 3
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/client.conf" > "$d/client.log" 2>&1 &
    local epid=$!; sleep 1
    [ "$(awk '{print $3}' /proc/$epid/stat 2>/dev/null)" != T ] && { echo "KEY key=$key mode=esac verdict=FAIL_NOSTOP" | tee -a "$RES"; KILL1; return; }
    attach "$epid" "$obj" "$act" "$pp" "$d" "$SHM" "$eloader" "$ENF"
    [ "$RDY" != YES ] && { echo "KEY key=$key mode=esac verdict=FAIL_ATTACH $(grep -aE 'rror|summary' "$d/loader.log"|tail -1|tr ' ' '_')" | tee -a "$RES"; kill -9 $epid 2>/dev/null; KILL1; return; }
    kill -CONT "$epid"; sleep $((DUR_C+1))
  fi
  # dump loader queue_stats (proves inspection ran). loader may already be dead (enforcement kill).
  [ -n "$LDRPID" ] && kill -0 "$LDRPID" 2>/dev/null && { kill -USR1 "$LDRPID" 2>/dev/null; sleep 1; }
  KILL1
  local deliv=$(maxrx "$d/server.log"); local offered=$(mx "$d/client.log" pktTx)
  [ "$DIR" = tx ] && [ "${offered:-0}" -eq 0 ] && offered=$(grep -aoE "pktTx +[0-9,]+" "$d/client.log" 2>/dev/null|grep -oE "[0-9,]+$"|tr -d ,|sort -n|tail -1)
  read irx ial idr iph <<<"$(insp "$d/loader.log")"
  local drops=$(grep -ahoE "ACT_DROP" "$d/loader.log" 2>/dev/null|wc -l)
  local dirtag=$(grep -ahoE "dir=(RX|TX)" "$d/loader.log" 2>/dev/null|head -1)
  local killed=no; grep -q "ACT_KILL" "$d/loader.log" 2>/dev/null && killed=yes
  local verdict=OK
  if [ "$CASE" = drop ]; then
    # enforcement proof: real drops happened AND almost nothing delivered
    if [ "${idr:-0}" -gt 0 ] && [ "${deliv:-0}" -lt 50000 ]; then verdict=DROPOK; else verdict="DROPFAIL(deliv=$deliv idr=$idr)"; fi
  else
    # ALLOW throughput: inspection MUST have run (policy_hits>0) else it is a bypass = fake-none
    if [ "${iph:-0}" -gt 0 ]; then verdict=INSPECTED; else verdict=BYPASS_NOHITS; fi
  fi
  echo "KEY key=$key t=intra dir=$DIR layer=$LAYER core=$NC pay=$PB cc=$CC case=$CASE mode=esac offered=${offered:-0} deliv=${deliv:-0} insp_rx=${irx:-0} insp_allow=${ial:-0} insp_drop=${idr:-0} insp_hits=${iph:-0} killed=$killed $dirtag verdict=$verdict" | tee -a "$RES"
  gzip -f "$d/server.log" "$d/client.log" 2>/dev/null
}

# none baseline: DIR NCORE PAYBYTES CC
ncell(){ local DIR=$1 NC=$2 PB=$3 CC=$4
  local key="intra_${DIR}_none_c${NC}_p${PB}_cc${CC}"
  grep -q "KEY .*key=$key " "$RES" 2>/dev/null && { return; }
  local d="$ROOT/$key"; mkdir -p "$d"
  KILL1
  mkconf "$d/server.conf" server $SVF $SIP $CIP $CMAC $NC "payload_size $PB" 0 ${KA:-1000}
  mkconf "$d/client.conf" client $CVF $CIP $SIP $SMAC $NC "payload_size $PB" $CC ${KA:-1000}
  env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+14)) "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 3
  env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+4)) "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep $((DUR_C+3))
  KILL1
  local deliv=$(maxrx "$d/server.log"); local offered=$(mx "$d/client.log" pktTx)
  echo "KEY key=$key t=intra dir=$DIR layer=none core=$NC pay=$PB cc=$CC mode=none offered=${offered:-0} deliv=${deliv:-0}" | tee -a "$RES"
  gzip -f "$d/server.log" "$d/client.log" 2>/dev/null
}

log "=== eSAC PPS INTRA campaign start root=$ROOT TESTMODE=$TESTMODE VALIDATE=${VALIDATE:-0} ==="
intra_up
# warmup: prime the VF/hairpin path (first DPDK run after VF create is slow / lossy)
log "warmup flood..."; ncell rx 1 1400 4000 >/dev/null 2>&1; rm -f "$ROOT"/intra_rx_none_c1_p1400_cc4000/*.gz 2>/dev/null
sed -i '/key=intra_rx_none_c1_p1400_cc4000 /d' "$RES" 2>/dev/null
for DIR in ${DIRS:-rx tx}; do
  for NC in $CORES; do
    SAT=$((SAT_CC_PER*NC))
    # none baselines (reference capacity + load curve)
    for PB in $PAYS; do ncell $DIR $NC $PB $SAT; done
    [ "${PAYONLY:-0}" = 1 ] || for L in $LOAD_CC_PER; do ncell $DIR $NC 1400 $((L*NC)); done
    for LAYER in ${LAYERS:-l4 l7}; do
      # anchor PASS (1400 @ saturate, detection) - payload-sweep anchor + proof pass-side
      cell $DIR $LAYER $NC 1400 $SAT pass allow
      pk="intra_${DIR}_${LAYER}_c${NC}_p1400_cc${SAT}_pass"
      pdev=$(getf "$pk" deliv); pph=$(getf "$pk" insp_hits)
      # DROP proof (same loader+attach, --enforcement) @512 saturate -> must really drop
      cell $DIR $LAYER $NC 512 $SAT drop proof
      dk="intra_${DIR}_${LAYER}_c${NC}_p512_cc${SAT}_drop"; ddev=$(getf "$dk" deliv); ddr=$(getf "$dk" insp_drop)
      # PAIRED verdict: legitimate enforced route iff
      #   (a) benign PASS was really INSPECTED (policy_hits>0) and flows high, AND
      #   (b) malicious DROP was really dropped (insp_drop>0) to ~0 delivered.
      if [ "${pph:-0}" -gt 0 ] && [ "${pdev:-0}" -gt 500000 ] && [ "${ddev:-0}" -lt 50000 ] && [ "${ddr:-0}" -gt 0 ]; then
        echo "KEY key=intra_${DIR}_${LAYER}_c${NC}_PROOF verdict=ENFORCE_PROVEN pass_deliv=${pdev} pass_hits=${pph} drop_deliv=${ddev} drop_cnt=${ddr}" | tee -a "$RES"
        log "config $DIR/$LAYER/c$NC ENFORCE_PROVEN (pass=$pdev hits=$pph drop=$ddev dcnt=$ddr) -> ALLOW sweeps"
        for PB in $PAYREST; do cell $DIR $LAYER $NC $PB $SAT pass allow; done
        [ "${PAYONLY:-0}" = 1 ] || for L in $LOAD_CC_PER; do cell $DIR $LAYER $NC 1400 $((L*NC)) pass allow; done
      elif [ "${pph:-0}" -le 0 ]; then
        echo "KEY key=intra_${DIR}_${LAYER}_c${NC}_PROOF verdict=BYPASS_FAIL pass_hits=${pph} pass_deliv=${pdev} -> SKIP (inspection did not run = fake-none)" | tee -a "$RES"
        log "config $DIR/$LAYER/c$NC BYPASS_FAIL hits=$pph -> SKIP"
      elif [ "${pdev:-0}" -le 500000 ]; then
        echo "KEY key=intra_${DIR}_${LAYER}_c${NC}_PROOF verdict=PATH_BROKEN pass_deliv=${pdev} pass_hits=${pph} drop_deliv=${ddev} -> SKIP (path not delivering)" | tee -a "$RES"
        log "config $DIR/$LAYER/c$NC PATH_BROKEN pass=$pdev -> SKIP"
      else
        echo "KEY key=intra_${DIR}_${LAYER}_c${NC}_PROOF verdict=ENFORCE_FAIL drop_deliv=${ddev} drop_cnt=${ddr} pass_deliv=${pdev} -> SKIP (DROP not blocking)" | tee -a "$RES"
        log "config $DIR/$LAYER/c$NC ENFORCE_FAIL drop=$ddev dcnt=$ddr -> SKIP"
      fi
    done
  done
done
intra_down
log "=== INTRA DONE ==="
touch "$ROOT/.done"
echo "ROOT=$ROOT"

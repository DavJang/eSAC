#!/bin/bash
# eSAC pps campaign - INTER (host1 mlx5 VF 3b:00.3 <-> host2 i40e d9:00.0).
# Same rigor as intra: detection-mode ALLOW throughput (per-cell policy_hits self-cert)
# + per-config --enforcement DROP proof (insp_drop>0, deliv->0). Reuses validated cell logic.
# RX (none->eSAC): host1 eSAC SERVER (VF_I) + host2 dperf CLIENT (esac_40g_auto_client_hist.sh); load via host2 CC.
# TX (eSAC->none): host1 eSAC CLIENT (VF_I) + host2 dperf SERVER (h2_server.sh);        load via host1 CC.
#   metric: deliv = host1 server pktRx (RX) / host1 client pktTx egress (TX); offered = sender pktTx.
set -u
TESTMODE=${TESTMODE:-0}; VALIDATE=${VALIDATE:-0}
PF_INTER=0000:3b:00.0
PREP=/home/sungwoo/FINAL/harness/setup/host1_vf_prepare.sh
H2KEY=/home/sungwoo/FINAL/secrets/host2_key
H2=(ssh -i "$H2KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 9022 sungwoo@143.248.57.12)
H2MAC=3c:fd:fe:c4:93:38       # host2 d9:00.0 PF
H1VFMAC=02:40:00:00:00:11     # host1 inter VF
H2DEV=0000:d9:00.0; H2IF=enp217s0f0np0
SIP=192.168.1.1; CIP=192.168.0.1   # host1 VF = .1.1 ; host2 = .0.1
DNS=/home/sungwoo/FINAL/traffic/dperf_dns
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent-hs.so
BSRV=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
UFUNC=/home/sungwoo/FINAL/l7/ctl/esac_suricata_dns_ufunc.so
L4OBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
L7OBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k_hs_gate.bpf.o
L_RX=/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_rxonly
L_TX=/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_mlx5tx
OFFS=/home/sungwoo/FINAL/comm_plane/offsets.json
IDT=/home/sungwoo/FINAL/tamper_sentinel/esac_pidcg_verify.py
GENPOL=/home/sungwoo/FINAL/policy/gen_policy_n.py
PAYDIR=/home/sungwoo/FINAL/l7/payloads
HSCTL=/home/sungwoo/FINAL/l7/ctl/esac_hs_ctl_rx_urlhaus
DOMCTL=/home/sungwoo/FINAL/l7/ctl/esac_dom_ctl_bulk
PATS=/home/sungwoo/FINAL/l7/patterns/suricata_dns_patterns.txt
H2DNS=/home/sungwoo/FINAL/traffic/dperf   # host2 dperf
SRV_CORES="2 3 4 5"
DUR_C=${DUR_C:-18}
SAT_CC_PER=${SAT_CC_PER:-8000}
LOAD_CC_PER="800 1600 2600 4000"
PAYS="${PAYS:-64 128 256 512 1024 1400}"
CORES="${CORES:-1 2 4}"
[ "$TESTMODE" = 1 ] && { CORES="1"; PAYS="64 1400"; LOAD_CC_PER="1600"; DUR_C=10; }
[ "$VALIDATE" = 1 ] && { CORES="1"; PAYS="1400"; LOAD_CC_PER="1600"; DUR_C=18; }
PAYREST=$(echo $PAYS | tr ' ' '\n' | grep -v '^1400$' | tr '\n' ' ')

ROOT=/home/sungwoo/esac_pps_inter_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"
RES="$ROOT/RESULTS.txt"; LOG="$ROOT/LOG"; : > "$RES"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
scpu(){ local n=$1 a=(2 3 4 5) o=""; for((i=0;i<n;i++)); do o="$o ${a[i]}"; done; echo "${o# }"; }  # SPACE-separated (dperf requires)
maxrx(){ grep -aE "^pktRx" "$1" 2>/dev/null|awk '{v=$2;gsub(/,/,"",v);print v}'|sort -n|tail -1; }
mx(){ grep -aoE "$2 +[0-9,]+" "$1" 2>/dev/null|grep -oE "[0-9,]+$"|tr -d ,|sort -n|tail -1; }
getf(){ grep "key=$1 " "$RES" 2>/dev/null|tail -1|grep -oE "$2=[0-9]+"|head -1|cut -d= -f2; }
insp(){ awk '/queue_stats/{f=1;next} f&&/^[0-9]/{rx+=$3;dr+=$5;al+=$6;ph+=$12} END{printf "%d %d %d %d",rx+0,al+0,dr+0,ph+0}' "$1" 2>/dev/null; }
KILL1(){ pkill -9 -x dperf 2>/dev/null; pkill -9 -f comm_loader_rxonly 2>/dev/null; pkill -9 -f comm_loader_mlx5tx 2>/dev/null; for cg in /sys/fs/cgroup/esac_*; do rmdir "$cg" 2>/dev/null; done; sleep 1; }
h2_kill(){ "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1" >/dev/null 2>&1; }
h2_ready(){ # ensure host2 d9 is back on i40e, numvfs 0, no dperf
  "${H2[@]}" "d=$H2DEV; for i in \$(seq 1 20); do drv=\$(basename \$(readlink -f /sys/bus/pci/devices/\$d/driver) 2>/dev/null); [ \"\$drv\" = i40e ] && ! pgrep -x dperf >/dev/null && break; sleep 1; done; echo DRV=\$drv" 2>/dev/null; }
hsdb(){ rm -f /dev/shm/esac_hs_db /dev/shm/esac_dom_db; "$DOMCTL" /esac_dom_db /dev/null none >/dev/null 2>&1; chmod a+r /dev/shm/esac_dom_db 2>/dev/null; "$HSCTL" /esac_hs_db "$PATS" none >/dev/null 2>&1; chmod a+r /dev/shm/esac_hs_db 2>/dev/null; }

RDY=NO; LDRPID=""
attach(){ local pid=$1 obj=$2 act=$3 pp=$4 d=$5 shm=$6 loader=$7 enf=${8:-}
  local CG=/sys/fs/cgroup/esac_$pid; mkdir -- "$CG" 2>/dev/null; chmod 755 "$CG"; echo "$pid" > "$CG/cgroup.procs"
  python3 "$IDT" init "$pid" "$CG" "$d/identity.json" > "$d/id.log" 2>&1
  local cgid=$(stat -c %i "$CG")
  python3 "$GENPOL" "$cgid" "$SIP" "$CIP" "$act" ${NPOL:-2} "$pp" > "$d/policy.json"
  env BPFTIME_GLOBAL_SHM_NAME=$shm BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$BSRV" \
    "$loader" --max-burst-inspect 128 --bpf "$obj" --lib "$DNS" --pmd-lib "$DNS" --offsets "$OFFS" \
    --policy "$d/policy.json" --no-pin $enf --attach-pid "$pid" -v > "$d/loader.log" 2>&1 &
  LDRPID=$!
  RDY=NO; for j in $(seq 1 55); do grep -qE "attach summary:.*OK" "$d/loader.log" 2>/dev/null && { RDY=YES; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 1; done; }

inter_vf_up(){ KILL1; h2_kill
  echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; sleep 1
  env VF_TTL=14400 bash "$PREP" > "$ROOT/vf_inter.log" 2>&1
  VF_I=$(sed -n 's/^VF_BDF=//p' "$ROOT/vf_inter.log"|head -1)
  log "inter VF=$VF_I ($(grep -c VF_BDF "$ROOT/vf_inter.log") ok)"; }
inter_vf_down(){ KILL1; echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; rm -f /tmp/esac40g_host1_vf_failsafe.marker 2>/dev/null; }

# mkconf_h1 file mode selfip peerip ncore payspec cc
mkconf_h1(){ local f=$1 mode=$2 sip=$3 pip=$4 nc=$5 pay=$6 cc=$7
  { echo "mode $mode"; echo "tx_burst 128"; echo "cpu $(scpu $nc)";
    [ "$mode" = server ] && echo "duration $((DUR_C+16))s" || echo "duration ${DUR_C}s";
    echo "$pay"; echo "protocol udp";
    [ "$mode" = client ] && { echo "cps 4000"; echo "cc $cc"; }
    echo "keepalive 1000us"; echo "socket_mem 2048";
    echo "port $VF_I $sip $pip $H2MAC"; echo "client $CIP 1"; echo "server $SIP 1"; echo "listen 9 1";
    [ "$nc" -gt 1 ] && echo "rss"; } > "$f"
}

# cell: DIR LAYER NCORE PAYBYTES CC CASE
cell(){ local DIR=$1 LAYER=$2 NC=$3 PB=$4 CC=$5 CASE=$6
  local key="inter_${DIR}_${LAYER}_c${NC}_p${PB}_cc${CC}_${CASE}"
  grep -q "key=$key " "$RES" 2>/dev/null && { log "skip done $key"; return; }
  local d="$ROOT/$key"; mkdir -p "$d"
  local obj=$L4OBJ pp=17; [ "$LAYER" = l7 ] && obj=$L7OBJ
  local act=ALLOW; [ "$CASE" = drop ] && [ "$LAYER" = l4 ] && act=DROP
  local payspec h2pay
  if [ "$LAYER" = l7 ]; then
    local pf="$PAYDIR/dnsq_com_$(printf %04d $PB).bin"; [ "$CASE" = drop ] && pf="$PAYDIR/dnsq_su_$(printf %04d $PB).bin"
    payspec="payload_file $pf"; h2pay="PAYLOAD_FILE=$pf"
  else payspec="payload_size $PB"; h2pay="PAYLOAD=$PB"; fi
  local eloader=$L_RX; [ "$DIR" = tx ] && eloader=$L_TX
  local ENF=""; [ "$CASE" = drop ] && ENF="--enforcement"
  KILL1; h2_kill; hsdb; h2_ready >/dev/null 2>&1
  local SHM=esac_$(date +%s%N); export BPFTIME_GLOBAL_SHM_NAME=$SHM
  local deliv=0 offered=0
  if [ "$DIR" = rx ]; then
    # host1 eSAC server; host2 client floods (load=host2 CC)
    mkconf_h1 "$d/server.conf" server $SIP $CIP $NC "payload_size $PB" 0
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/server.conf" > "$d/server.log" 2>&1 &
    local epid=$!; sleep 1
    [ "$(awk '{print $3}' /proc/$epid/stat 2>/dev/null)" != T ] && { echo "KEY key=$key mode=esac verdict=FAIL_NOSTOP" | tee -a "$RES"; KILL1; return; }
    attach "$epid" "$obj" "$act" "$pp" "$d" "$SHM" "$eloader" "$ENF"
    [ "$RDY" != YES ] && { echo "KEY key=$key mode=esac verdict=FAIL_ATTACH" | tee -a "$RES"; kill -9 $epid 2>/dev/null; KILL1; return; }
    kill -CONT "$epid"; sleep 2
    "${H2[@]}" "env DUR=$DUR_C CPU=16 PROTO=udp $h2pay KEEPALIVE=${KA:-1000}us CPS=4000 CC=$CC SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=$H2DNS HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh" > "$d/h2c.out" 2>&1
    sleep 1
    [ -n "$LDRPID" ] && kill -0 "$LDRPID" 2>/dev/null && { kill -USR1 "$LDRPID" 2>/dev/null; sleep 1; }
    KILL1
    deliv=$(maxrx "$d/server.log"); offered=$(mx "$d/h2c.out" pktTx)
  else
    # host2 server; host1 eSAC client floods (load=host1 CC)
    "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1; setsid env DUR=$((DUR_C+30)) CPU=6 PROTO=udp PAYLOAD=$PB KEEPALIVE=${KA:-1000}us CLIENT_MAC=$H1VFMAC SERVER_BIN=$H2DNS OUT=/tmp/h2srv bash /home/sungwoo/FINAL/harness/setup/host2_server.sh > /tmp/h2srv.out 2>&1 < /dev/null & echo LAUNCHED" > "$d/h2s.out" 2>&1
    sleep 7
    mkconf_h1 "$d/client.conf" client $CIP $SIP $NC "$payspec" $CC
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/client.conf" > "$d/client.log" 2>&1 &
    local epid=$!; sleep 1
    [ "$(awk '{print $3}' /proc/$epid/stat 2>/dev/null)" != T ] && { echo "KEY key=$key mode=esac verdict=FAIL_NOSTOP" | tee -a "$RES"; KILL1; h2_kill; return; }
    attach "$epid" "$obj" "$act" "$pp" "$d" "$SHM" "$eloader" "$ENF"
    [ "$RDY" != YES ] && { echo "KEY key=$key mode=esac verdict=FAIL_ATTACH" | tee -a "$RES"; kill -9 $epid 2>/dev/null; KILL1; h2_kill; return; }
    kill -CONT "$epid"; sleep $((DUR_C+1))
    [ -n "$LDRPID" ] && kill -0 "$LDRPID" 2>/dev/null && { kill -USR1 "$LDRPID" 2>/dev/null; sleep 1; }
    KILL1; h2_kill
    deliv=$(mx "$d/client.log" pktTx); offered=$deliv   # TX egress rate (eSAC push); host2 recv ~= this
  fi
  read irx ial idr iph <<<"$(insp "$d/loader.log")"
  local dirtag=$(grep -ahoE "dir=(RX|TX)" "$d/loader.log" 2>/dev/null|head -1)
  local killed=no; grep -q "ACT_KILL" "$d/loader.log" 2>/dev/null && killed=yes
  local verdict=OK
  if [ "$CASE" = drop ]; then
    # loader-authoritative proof: it allowed ~nothing and dropped the rest.
    # (TX deliv = host1 client pktTx counts PRE-hook attempts, so cannot be used for TX drop.)
    if [ "${idr:-0}" -gt 0 ] && [ "${ial:-0}" -lt 1000 ]; then verdict=DROPOK; else verdict="DROPFAIL(ial=$ial idr=$idr deliv=$deliv)"; fi
  else
    if [ "${iph:-0}" -gt 0 ]; then verdict=INSPECTED; else verdict=BYPASS_NOHITS; fi
  fi
  echo "KEY key=$key t=inter dir=$DIR layer=$LAYER core=$NC pay=$PB cc=$CC case=$CASE mode=esac offered=${offered:-0} deliv=${deliv:-0} insp_rx=${irx:-0} insp_allow=${ial:-0} insp_drop=${idr:-0} insp_hits=${iph:-0} killed=$killed $dirtag verdict=$verdict" | tee -a "$RES"
  gzip -f "$d"/*.log 2>/dev/null
}

# none inter baseline: DIR NCORE PAYBYTES CC
ncell(){ local DIR=$1 NC=$2 PB=$3 CC=$4
  local key="inter_${DIR}_none_c${NC}_p${PB}_cc${CC}"
  grep -q "key=$key " "$RES" 2>/dev/null && return
  local d="$ROOT/$key"; mkdir -p "$d"; KILL1; h2_kill; h2_ready >/dev/null 2>&1
  local deliv=0 offered=0
  if [ "$DIR" = rx ]; then
    mkconf_h1 "$d/server.conf" server $SIP $CIP $NC "payload_size $PB" 0
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+20)) "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 2
    "${H2[@]}" "env DUR=$DUR_C CPU=16 PROTO=udp PAYLOAD=$PB KEEPALIVE=${KA:-1000}us CPS=4000 CC=$CC SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=$H2DNS HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh" > "$d/h2c.out" 2>&1
    sleep 1; KILL1
    deliv=$(maxrx "$d/server.log"); offered=$(mx "$d/h2c.out" pktTx)
  else
    "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1; setsid env DUR=$((DUR_C+30)) CPU=6 PROTO=udp PAYLOAD=$PB KEEPALIVE=${KA:-1000}us CLIENT_MAC=$H1VFMAC SERVER_BIN=$H2DNS OUT=/tmp/h2srv bash /home/sungwoo/FINAL/harness/setup/host2_server.sh > /tmp/h2srv.out 2>&1 < /dev/null & echo LAUNCHED" > "$d/h2s.out" 2>&1
    sleep 7
    mkconf_h1 "$d/client.conf" client $CIP $SIP $NC "payload_size $PB" $CC
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout $((DUR_C+4)) "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep $((DUR_C+2))
    KILL1; h2_kill
    deliv=$(mx "$d/client.log" pktTx); offered=$deliv
  fi
  echo "KEY key=$key t=inter dir=$DIR layer=none core=$NC pay=$PB cc=$CC mode=none offered=${offered:-0} deliv=${deliv:-0}" | tee -a "$RES"
  gzip -f "$d"/*.log 2>/dev/null
}

log "=== eSAC PPS INTER campaign start root=$ROOT TESTMODE=$TESTMODE VALIDATE=$VALIDATE ==="
inter_vf_up
[ -z "${VF_I:-}" ] && { log "FATAL no inter VF"; exit 1; }
log "warmup..."; ncell rx 1 1400 4000 >/dev/null 2>&1; sed -i '/key=inter_rx_none_c1_p1400_cc4000 /d' "$RES" 2>/dev/null
for DIR in ${DIRS:-rx tx}; do
  for NC in $CORES; do
    SAT=$((SAT_CC_PER*NC))
    for PB in $PAYS; do ncell $DIR $NC $PB $SAT; done
    [ "${PAYONLY:-0}" = 1 ] || for L in $LOAD_CC_PER; do ncell $DIR $NC 1400 $((L*NC)); done
    for LAYER in ${LAYERS:-l4 l7}; do
      cell $DIR $LAYER $NC 1400 $SAT pass
      pk="inter_${DIR}_${LAYER}_c${NC}_p1400_cc${SAT}_pass"; pdev=$(getf "$pk" deliv); pph=$(getf "$pk" insp_hits)
      cell $DIR $LAYER $NC 512 $SAT drop
      dk="inter_${DIR}_${LAYER}_c${NC}_p512_cc${SAT}_drop"; ddr=$(getf "$dk" insp_drop); dal=$(getf "$dk" insp_allow)
      if [ "${pph:-0}" -gt 0 ] && [ "${pdev:-0}" -gt 300000 ] && [ "${ddr:-0}" -gt 0 ] && [ "${dal:-0}" -lt 1000 ]; then
        echo "KEY key=inter_${DIR}_${LAYER}_c${NC}_PROOF verdict=ENFORCE_PROVEN pass_deliv=${pdev} pass_hits=${pph} drop_allow=${dal} drop_cnt=${ddr}" | tee -a "$RES"
        for PB in $PAYREST; do cell $DIR $LAYER $NC $PB $SAT pass; done
        [ "${PAYONLY:-0}" = 1 ] || for L in $LOAD_CC_PER; do cell $DIR $LAYER $NC 1400 $((L*NC)) pass; done
      elif [ "${pph:-0}" -le 0 ]; then
        echo "KEY key=inter_${DIR}_${LAYER}_c${NC}_PROOF verdict=BYPASS_FAIL pass_hits=${pph} pass_deliv=${pdev} -> SKIP" | tee -a "$RES"
      elif [ "${pdev:-0}" -le 300000 ]; then
        echo "KEY key=inter_${DIR}_${LAYER}_c${NC}_PROOF verdict=PATH_BROKEN pass_deliv=${pdev} pass_hits=${pph} -> SKIP" | tee -a "$RES"
      else
        echo "KEY key=inter_${DIR}_${LAYER}_c${NC}_PROOF verdict=ENFORCE_FAIL drop_allow=${dal} drop_cnt=${ddr} pass_deliv=${pdev} -> SKIP" | tee -a "$RES"
      fi
    done
  done
done
inter_vf_down; h2_kill
log "=== INTER DONE ==="; touch "$ROOT/.done"; echo "ROOT=$ROOT"

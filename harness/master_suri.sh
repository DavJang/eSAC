#!/bin/bash
# ============================================================================
# eSAC direction-isolated campaign: eSAC->none (TX) & none->eSAC (RX),
#   L4 throughput + L4 RTT + L7 throughput, 1c & 4c, INTRA + INTER, max & matched offered, 64B & 512B.
# Runs entirely on host1 as root (self-contained; survives my SSH drop via setsid).
# host1<->host2 orchestration done internally. Results appended to RESULTS.txt; resumable (skips done keys).
# Order: PASS1 (headline: all T/dir/core @ 64B/max) -> Suricata -> PASS2 (variants: 512B, matched).
# ============================================================================
set +u
ROOT=/home/sungwoo/esac_dirsweep_$(date +%Y%m%d_%H%M%S)
[ -n "$RESUME_DIR" ] && ROOT="$RESUME_DIR"
mkdir -p "$ROOT"; echo "$ROOT" > /home/sungwoo/.dirsweep_dir
RES="$ROOT/RESULTS.txt"; touch "$RES"
NONEC="$ROOT/none_cache.txt"; touch "$NONEC"
log(){ echo "[$(date +%m-%d_%H:%M:%S)] $*" | tee -a "$ROOT/LOG"; }
emit(){ echo "$*" | tee -a "$RES"; }
done_key(){ grep -q "^KEY=$1 " "$RES" 2>/dev/null; }

# ---- asset paths ----
PF_INTRA=0000:3b:00.1; IF_INTRA=enp59s0f1np1
PF_INTER=0000:3b:00.0
PREP=/home/sungwoo/FINAL/harness/setup/host1_vf_prepare.sh
H2KEY=/home/sungwoo/FINAL/secrets/host2_key
H2=(ssh -i "$H2KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 9022 sungwoo@143.248.57.12)
H2IP=sungwoo@143.248.57.12
DNS=/home/sungwoo/FINAL/traffic/dperf_dns          # DNS flood client / udp server
ECHO=/home/sungwoo/FINAL/traffic/dperf_probe        # plain echo server
HIST=/home/sungwoo/FINAL/traffic/dperf_hist   # host1 RTT client
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent-hs.so
BSRV=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
UFUNC=/home/sungwoo/FINAL/l7/ctl/esac_suricata_dns_ufunc.so
L4OBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
L7OBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k_hs_gate.bpf.o
L_TX=/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_mlx5tx
L_RX=/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_rxonly
OFFS=/home/sungwoo/FINAL/comm_plane/offsets.json
IDT=/home/sungwoo/FINAL/tamper_sentinel/esac_pidcg_verify.py
GENPOL=/home/sungwoo/FINAL/policy/gen_policy_n.py
HSCTL=/home/sungwoo/FINAL/l7/ctl/esac_hs_ctl_rx_urlhaus
DOMCTL=/home/sungwoo/FINAL/l7/ctl/esac_dom_ctl_bulk
PATS=/home/sungwoo/FINAL/l7/patterns/suricata_dns_patterns.txt
QCOM=/home/sungwoo/FINAL/l7/payloads/dnsq_com.bin; QSU=/home/sungwoo/FINAL/l7/payloads/dnsq_su.bin
H2MAC=3c:fd:fe:c4:93:38       # host2 d9:00.0 PF (inter peer)
H1VFMAC=02:40:00:00:00:11     # host1 inter VF
SURI=/home/sungwoo/FINAL/suricata/bin/suricata
SYAML=/home/sungwoo/FINAL/suricata/conf/suri_ips.yaml
SURILIB=/home/sungwoo/FINAL/suricata/lib:/usr/local/lib/x86_64-linux-gnu

med(){ grep -aE "^pktRx" "$1" 2>/dev/null|awk '{print $2}'|tr -d ,|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}'; }
lasttx(){ grep -aoE "pktTx +[0-9,]+" "$1" 2>/dev/null|grep -oE "[0-9,]+$"|tr -d ,|awk '$1>0'|sort -n|tail -1; }
rttus(){ grep -aoE "appRtt\(us\) [0-9.]+" "$1" 2>/dev/null|tail -1|awk '{print $2}'; }
hp(){ awk 'NF>=1 && $1 ~ /^[0-9.]+$/ {print $1}' "$1" 2>/dev/null | sort -n | awk '{a[NR]=$1} END{if(NR){print a[int(NR*0.5)+0]","a[int(NR*0.9)+0]}else print "NA,NA"}'; }
actsum(){ grep -ahoE "dir=(RX|TX)|ACT_(DROP|KILL)" "$@" 2>/dev/null|sort|uniq -c|tr '\n' ' '; }
KILL1(){ pkill -9 -x dperf 2>/dev/null; pkill -9 -f comm_loader_mlx5tx 2>/dev/null; pkill -9 -f comm_loader_rxonly 2>/dev/null; pkill -9 suricata 2>/dev/null; for cg in /sys/fs/cgroup/esac_*; do rmdir "$cg" 2>/dev/null; done; }
hsdb(){ rm -f /dev/shm/esac_hs_db /dev/shm/esac_dom_db; "$DOMCTL" /esac_dom_db /dev/null none >/dev/null 2>&1; chmod a+r /dev/shm/esac_dom_db 2>/dev/null; "$HSCTL" /esac_hs_db "$PATS" none >/dev/null 2>&1; chmod a+r /dev/shm/esac_hs_db 2>/dev/null; }

# offered presets
off_cps(){ [ "$1" = max ] && echo 4000 || echo 2000; }
off_cc(){  [ "$1" = max ] && echo 10000 || echo 100; }
off_ka(){  [ "$1" = max ] && echo 20us || echo 1000us; }
# core presets
scpu(){ [ "$1" = 1 ] && echo 6 || echo "6 7 8 9"; }
ccpu(){ [ "$1" = 1 ] && echo 16 || echo "16 17 18 19"; }

echo 16384 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null
echo 16384 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null

# ======================= INTRA plumbing =======================
intra_up(){ KILL1; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; sleep 2
  devlink dev eswitch set pci/$PF_INTRA mode switchdev 2>/dev/null; sleep 1
  ethtool -K $IF_INTRA hw-tc-offload on 2>/dev/null
  echo 2 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF_INTRA/virtfn1 ] && break; sleep 1; done; sleep 3
  ip link set $IF_INTRA up 2>/dev/null
  SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn0))
  CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn1))
  rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
  SREP=$(rep 0); CREP=$(rep 1)
  ip link set $IF_INTRA vf 0 mac 02:50:00:00:01:01 2>/dev/null; ip link set $IF_INTRA vf 1 mac 02:50:00:00:01:02 2>/dev/null
  ip link set $IF_INTRA vf 0 spoofchk off 2>/dev/null; ip link set $IF_INTRA vf 0 trust on 2>/dev/null
  ip link set $IF_INTRA vf 1 spoofchk off 2>/dev/null; ip link set $IF_INTRA vf 1 trust on 2>/dev/null
  ip link set $SREP up 2>/dev/null; ip link set $CREP up 2>/dev/null
  tc qdisc add dev $SREP ingress 2>/dev/null; tc qdisc add dev $CREP ingress 2>/dev/null
  tc filter add dev $SREP ingress protocol all flower skip_sw action mirred egress redirect dev $CREP 2>/dev/null
  tc filter add dev $CREP ingress protocol all flower skip_sw action mirred egress redirect dev $SREP 2>/dev/null
  SMAC_I=02:50:00:00:01:01; CMAC_I=02:50:00:00:01:02; SIP_I=192.168.91.1; CIP_I=192.168.91.2
  log "intra VFs S=$SVF C=$CVF tc=$(tc filter show dev $SREP ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1)"; }
intra_down(){ KILL1; echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; devlink dev eswitch set pci/$PF_INTRA mode legacy 2>/dev/null; }

# attach eSAC loader to a stopped pid; gate on RX=OK. args: pid dir(rx/tx) obj loader libbin polproto act outdir shm
RDY=NO; GLOADER=
attach(){ local pid=$1 obj=$3 loader=$4 lb=$5 pp=$6 act=$7 d=$8 shm=$9
  local CG=/sys/fs/cgroup/esac_$pid; mkdir -- "$CG" 2>/dev/null; chmod 755 "$CG"; echo "$pid" > "$CG/cgroup.procs"
  python3 "$IDT" init "$pid" "$CG" "$d/identity.json" > "$d/id.log" 2>&1
  local cgid=$(stat -c %i "$CG")
  python3 "$GENPOL" "$cgid" "$POLSIP" "$POLCIP" "$act" 2 "$pp" > "$d/policy.json"
  env BPFTIME_GLOBAL_SHM_NAME=$shm BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$BSRV" "$loader" --max-burst-inspect 128 --bpf "$obj" --lib "$lb" --pmd-lib "$lb" --offsets "$OFFS" --policy "$d/policy.json" --no-pin --attach-pid "$pid" -v > "$d/loader.log" 2>&1 &
  GLOADER=$!; RDY=NO
  for j in $(seq 1 55); do grep -qE "attach summary: RX=OK" "$d/loader.log" 2>/dev/null && { RDY=YES; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 1; done; }

# ---- INTRA cell: echoes "pps|offered|act" ----
# params: REG(none/esac) DIR(rx/tx) LAYER(l4/l7) CORE OFF PAY CASE(pass/drop) outdir
intra_cell(){ local REG=$1 DIR=$2 LAYER=$3 CORE=$4 OFF=$5 PAY=$6 CASE=$7 d=$8; mkdir -p "$d"
  local obj=$L4OBJ pp=17; [ "$LAYER" = l7 ] && obj=$L7OBJ
  local Q=$QCOM; [ "$CASE" = drop ] && [ "$LAYER" = l7 ] && Q=$QSU
  local act=ALLOW; [ "$CASE" = drop ] && [ "$LAYER" = l4 ] && act=DROP
  local PLINE="payload_file $Q"; [ "$PAY" = 512 ] && PLINE="payload_size 512"
  POLSIP=$SIP_I; POLCIP=$CIP_I
  KILL1; sleep 2; hsdb
  cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu $(scpu $CORE)
duration 55s
payload_size $PAY
protocol udp
keepalive $(off_ka $OFF)
socket_mem 2048
port $SVF $SIP_I $CIP_I $CMAC_I
client $CIP_I 1
server $SIP_I 1
listen 9 1
C
  [ "$CORE" = 4 ] && echo rss >> "$d/server.conf"
  cat > "$d/client.conf" <<C
mode client
tx_burst 32
cpu $(ccpu $CORE)
duration 22s
$PLINE
protocol udp
cps $(off_cps $OFF)
cc $(off_cc $OFF)
keepalive $(off_ka $OFF)
socket_mem 0,2048
port $CVF $CIP_I $SIP_I $SMAC_I
client $CIP_I 1
server $SIP_I 1
listen 9 1
C
  [ "$CORE" = 4 ] && echo rss >> "$d/client.conf"
  local SHM=esac_$(date +%s%N)
  if [ "$REG" = none ]; then
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 50 "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 26 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 25
  elif [ "$DIR" = rx ]; then   # eSAC on server (receiver), rxonly loader
    export BPFTIME_GLOBAL_SHM_NAME=$SHM
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/server.conf" > "$d/server.log" 2>&1 &
    local srv=$!; sleep 1; [ "$(awk '{print $3}' /proc/$srv/stat 2>/dev/null)" != T ] && { echo "0|0|NOSTOP"; KILL1; return; }
    attach "$srv" rx "$obj" "$L_RX" "$DNS" "$pp" "$act" "$d" "$SHM"
    [ "$RDY" != YES ] && { echo "0|0|ATTACHFAIL"; grep -aE 'rror|summary' "$d/loader.log"|tail -2 >> "$ROOT/LOG"; kill -9 $srv 2>/dev/null; KILL1; return; }
    kill -CONT "$srv"; sleep 8
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 26 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 25
  else   # tx: eSAC on client (sender), mlx5tx loader; none server
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 50 "$ECHO" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    export BPFTIME_GLOBAL_SHM_NAME=$SHM
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/client.conf" > "$d/client.log" 2>&1 &
    local cli=$!; sleep 1; [ "$(awk '{print $3}' /proc/$cli/stat 2>/dev/null)" != T ] && { echo "0|0|NOSTOP"; KILL1; return; }
    attach "$cli" tx "$obj" "$L_TX" "$DNS" "$pp" "$act" "$d" "$SHM"
    [ "$RDY" != YES ] && { echo "0|0|ATTACHFAIL"; grep -aE 'rror|summary' "$d/loader.log"|tail -2 >> "$ROOT/LOG"; kill -9 $cli 2>/dev/null; KILL1; return; }
    kill -CONT "$cli"; sleep 25
  fi
  KILL1; sleep 2
  echo "$(med "$d/server.log")|$(lasttx "$d/client.log")|$(actsum "$d"/loader.log 2>/dev/null)"
}

# ---- INTRA RTT cell (TCP closed-loop, hist client) ----
intra_rtt(){ local REG=$1 DIR=$2 CORE=$3 OFF=$4 PAY=$5 d=$6; mkdir -p "$d"
  POLSIP=$SIP_I; POLCIP=$CIP_I; KILL1; sleep 2
  cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu $(scpu $CORE)
duration 70s
payload_size $PAY
protocol tcp
keepalive $(off_ka $OFF)
socket_mem 2048
port $SVF $SIP_I $CIP_I $CMAC_I
client $CIP_I 1
server $SIP_I 1
listen 9 1
C
  [ "$CORE" = 4 ] && echo rss >> "$d/server.conf"
  cat > "$d/client.conf" <<C
mode client
tx_burst 32
cpu $(ccpu $CORE)
duration 30s
payload_size $PAY
protocol tcp
cps $(off_cps $OFF)
cc $(off_cc $OFF)
keepalive $(off_ka $OFF)
socket_mem 0,2048
port $CVF $CIP_I $SIP_I $SMAC_I
client $CIP_I 1
server $SIP_I 1
listen 9 1
C
  [ "$CORE" = 4 ] && echo rss >> "$d/client.conf"
  local SHM=esac_$(date +%s%N)
  if [ "$REG" = none ]; then
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 60 "$ECHO" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" ESAC_HIST_FILE="$d/hist.txt" ESAC_HIST_START_SEC=3 timeout 34 "$HIST" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 33
  elif [ "$DIR" = rx ]; then
    export BPFTIME_GLOBAL_SHM_NAME=$SHM
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$ECHO" "$d/server.conf" > "$d/server.log" 2>&1 &
    local srv=$!; sleep 1; [ "$(awk '{print $3}' /proc/$srv/stat 2>/dev/null)" != T ] && { echo "NA,NA|NOSTOP"; KILL1; return; }
    attach "$srv" rx "$L4OBJ" "$L_RX" "$ECHO" 6 ALLOW "$d" "$SHM"
    [ "$RDY" != YES ] && { echo "NA,NA|ATTACHFAIL"; kill -9 $srv 2>/dev/null; KILL1; return; }
    kill -CONT "$srv"; sleep 8
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" ESAC_HIST_FILE="$d/hist.txt" ESAC_HIST_START_SEC=3 timeout 34 "$HIST" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 33
  else
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 60 "$ECHO" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    export BPFTIME_GLOBAL_SHM_NAME=$SHM
    bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" ESAC_HIST_FILE="$3" ESAC_HIST_START_SEC=3 "$4" -c "$5"' _ "$AGENT:$UFUNC" "$LIB" "$d/hist.txt" "$HIST" "$d/client.conf" > "$d/client.log" 2>&1 &
    local cli=$!; sleep 1; [ "$(awk '{print $3}' /proc/$cli/stat 2>/dev/null)" != T ] && { echo "NA,NA|NOSTOP"; KILL1; return; }
    attach "$cli" tx "$L4OBJ" "$L_TX" "$HIST" 6 ALLOW "$d" "$SHM"
    [ "$RDY" != YES ] && { echo "NA,NA|ATTACHFAIL"; kill -9 $cli 2>/dev/null; KILL1; return; }
    kill -CONT "$cli"; sleep 33
  fi
  KILL1; sleep 2
  local rp=$(hp "$d/hist.txt"); local ar=$(rttus "$d/client.log")
  echo "${rp}|appRtt=${ar:-NA}|$(actsum "$d"/loader.log 2>/dev/null)"
}

# ======================= INTER plumbing =======================
inter_vf_up(){ echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; sleep 1
  env VF_TTL=9000 bash "$PREP" > "$ROOT/vf_inter.log" 2>&1
  VF_I=$(sed -n 's/^VF_BDF=//p' "$ROOT/vf_inter.log"|head -1); log "inter VF=$VF_I"; }
inter_vf_down(){ KILL1; echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; }
h2_kill(){ "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; pkill -9 -x dperf_hist_bin 2>/dev/null; sleep 1" 2>/dev/null; }

# host2 client launcher (for inter RX). args: dur cpu proto payarg keepalive cps cc
h2_client(){ local dur=$1 cpu=$2 proto=$3 payarg=$4 ka=$5 cps=$6 cc=$7 bin=$8
  "${H2[@]}" "env DUR=$dur CPU='$cpu' PROTO=$proto $payarg KEEPALIVE=$ka CPS=$cps CC=$cc SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=$bin HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh" > "$1_h2c.out" 2>&1; }

# INTER throughput cell. REG DIR LAYER CORE OFF PAY CASE outdir
inter_cell(){ local REG=$1 DIR=$2 LAYER=$3 CORE=$4 OFF=$5 PAY=$6 CASE=$7 d=$8; mkdir -p "$d"
  local obj=$L4OBJ pp=17; [ "$LAYER" = l7 ] && obj=$L7OBJ
  local Q=$QCOM; [ "$CASE" = drop ] && [ "$LAYER" = l7 ] && Q=$QSU
  local act=ALLOW; [ "$CASE" = drop ] && [ "$LAYER" = l4 ] && act=DROP
  local payarg="PAYLOAD_FILE=$Q"; [ "$PAY" = 512 ] && payarg="PAYLOAD=512"
  local payfile_h1="payload_file $Q"; [ "$PAY" = 512 ] && payfile_h1="payload_size 512"
  POLSIP=192.168.1.1; POLCIP=192.168.0.1
  KILL1; h2_kill; sleep 2; hsdb
  local SHM=esac_$(date +%s%N)
  if [ "$DIR" = rx ]; then
    # host1 = server (eSAC rxonly if esac), host2 = none client
    cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu $(scpu $CORE)
duration 60s
payload_size $PAY
protocol udp
keepalive $(off_ka $OFF)
socket_mem 2048
port $VF_I 192.168.1.1 192.168.0.1 $H2MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/server.conf"
    if [ "$REG" = none ]; then
      env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 56 "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    else
      export BPFTIME_GLOBAL_SHM_NAME=$SHM
      bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/server.conf" > "$d/server.log" 2>&1 &
      local srv=$!; sleep 1; [ "$(awk '{print $3}' /proc/$srv/stat 2>/dev/null)" != T ] && { echo "0|0|NOSTOP"; KILL1; return; }
      attach "$srv" rx "$obj" "$L_RX" "$DNS" "$pp" "$act" "$d" "$SHM"
      [ "$RDY" != YES ] && { echo "0|0|ATTACHFAIL"; grep -aE 'rror|summary' "$d/loader.log"|tail -2 >> "$ROOT/LOG"; kill -9 $srv 2>/dev/null; KILL1; return; }
      kill -CONT "$srv"; sleep 8
    fi
    # host2 none client floods
    "${H2[@]}" "env DUR=24 CPU='$(ccpu $CORE|tr ' ' ,)' PROTO=udp $payarg KEEPALIVE=$(off_ka $OFF) CPS=$(off_cps $OFF) CC=$(off_cc $OFF) SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=/home/sungwoo/FINAL/traffic/dperf HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh" > "$d/h2client.out" 2>&1
    KILL1; sleep 2
    echo "$(med "$d/server.log")|$(grep -aoE 'pktTx +[0-9,]+' "$d/h2client.out"|grep -oE '[0-9,]+$'|tr -d ,|sort -n|tail -1)|$(actsum "$d"/loader.log 2>/dev/null)"
  else
    # tx: host1 = client (eSAC mlx5tx if esac), host2 = none server
    "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1; setsid env DUR=50 CPU='$(scpu $CORE|tr ' ' ,)' PROTO=udp $payarg KEEPALIVE=$(off_ka $OFF) CLIENT_MAC=$H1VFMAC OUT=/tmp/h2srv bash /home/sungwoo/FINAL/harness/setup/host2_server.sh > /tmp/h2srv.out 2>&1 < /dev/null & echo LAUNCHED" > "$d/h2srv_launch.out" 2>&1
    sleep 13
    cat > "$d/client.conf" <<C
mode client
tx_burst 32
cpu $(ccpu $CORE)
duration 24s
$payfile_h1
protocol udp
cps $(off_cps $OFF)
cc $(off_cc $OFF)
keepalive $(off_ka $OFF)
socket_mem 0,2048
port $VF_I 192.168.0.1 192.168.1.1 $H2MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/client.conf"
    if [ "$REG" = none ]; then
      env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 28 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 27
    else
      export BPFTIME_GLOBAL_SHM_NAME=$SHM
      bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/client.conf" > "$d/client.log" 2>&1 &
      local cli=$!; sleep 1; [ "$(awk '{print $3}' /proc/$cli/stat 2>/dev/null)" != T ] && { echo "0|0|NOSTOP"; KILL1; h2_kill; return; }
      attach "$cli" tx "$obj" "$L_TX" "$DNS" "$pp" "$act" "$d" "$SHM"
      [ "$RDY" != YES ] && { echo "0|0|ATTACHFAIL"; grep -aE 'rror|summary' "$d/loader.log"|tail -2 >> "$ROOT/LOG"; kill -9 $cli 2>/dev/null; KILL1; h2_kill; return; }
      kill -CONT "$cli"; sleep 27
    fi
    KILL1; sleep 3
    "${H2[@]}" "cat /tmp/h2srv/result 2>/dev/null" > "$d/h2result" 2>/dev/null
    local hp=$(grep -aoE "H2SRV_PKTRX=[0-9]+" "$d/h2result"|grep -oE "[0-9]+$")
    h2_kill
    echo "${hp:-0}|$(lasttx "$d/client.log")|$(actsum "$d"/loader.log 2>/dev/null)"
  fi
}

# INTER RTT (TCP). Only RX dir uses host2 hist client; TX dir uses host1 hist client + host2 echo server.
inter_rtt(){ local REG=$1 DIR=$2 CORE=$3 OFF=$4 PAY=$5 d=$6; mkdir -p "$d"
  POLSIP=192.168.1.1; POLCIP=192.168.0.1; KILL1; h2_kill; sleep 2
  local SHM=esac_$(date +%s%N)
  if [ "$DIR" = rx ]; then
    cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu $(scpu $CORE)
duration 70s
payload_size $PAY
protocol tcp
keepalive $(off_ka $OFF)
socket_mem 2048
port $VF_I 192.168.1.1 192.168.0.1 $H2MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/server.conf"
    if [ "$REG" = none ]; then
      env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 66 "$ECHO" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    else
      export BPFTIME_GLOBAL_SHM_NAME=$SHM
      bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$ECHO" "$d/server.conf" > "$d/server.log" 2>&1 &
      local srv=$!; sleep 1; [ "$(awk '{print $3}' /proc/$srv/stat 2>/dev/null)" != T ] && { echo "NA,NA|NOSTOP"; KILL1; return; }
      attach "$srv" rx "$L4OBJ" "$L_RX" "$ECHO" 6 ALLOW "$d" "$SHM"
      [ "$RDY" != YES ] && { echo "NA,NA|ATTACHFAIL"; kill -9 $srv 2>/dev/null; KILL1; return; }
      kill -CONT "$srv"; sleep 8
    fi
    "${H2[@]}" "env DUR=30 CPU='$(ccpu $CORE|tr ' ' ,)' PROTO=tcp PAYLOAD=$PAY KEEPALIVE=$(off_ka $OFF) CPS=$(off_cps $OFF) CC=$(off_cc $OFF) SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh" > "$d/h2client.out" 2>&1
    "${H2[@]}" "cat \$(sed -n 's/^HIST_FILE=//p' /tmp/esac40g_auto_client_*/*.out 2>/dev/null|tail -1) 2>/dev/null" > "$d/hist.txt" 2>/dev/null
    local cd=$(sed -n 's/^CLIENT_LOG_DIR=//p' "$d/h2client.out"|head -1)
    [ -n "$cd" ] && scp -q -i "$H2KEY" -P 9022 "$H2IP:$cd/hist.txt" "$d/hist.txt" 2>/dev/null
    [ -n "$cd" ] && scp -q -i "$H2KEY" -P 9022 "$H2IP:$cd/client.log" "$d/client.log" 2>/dev/null
    KILL1; sleep 2
    echo "$(hp "$d/hist.txt")|appRtt=$(rttus "$d/client.log")|$(actsum "$d"/loader.log 2>/dev/null)"
  else
    # tx: host2 echo server + host1 hist client (eSAC mlx5tx)
    "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1; setsid env DUR=60 CPU='$(scpu $CORE|tr ' ' ,)' PROTO=tcp PAYLOAD=$PAY KEEPALIVE=$(off_ka $OFF) CLIENT_MAC=$H1VFMAC SERVER_BIN=/home/sungwoo/FINAL/traffic/dperf OUT=/tmp/h2srv bash /home/sungwoo/FINAL/harness/setup/host2_server.sh > /tmp/h2srv.out 2>&1 < /dev/null & echo LAUNCHED" > "$d/h2srv_launch.out" 2>&1
    sleep 13
    cat > "$d/client.conf" <<C
mode client
tx_burst 32
cpu $(ccpu $CORE)
duration 30s
payload_size $PAY
protocol tcp
cps $(off_cps $OFF)
cc $(off_cc $OFF)
keepalive $(off_ka $OFF)
socket_mem 0,2048
port $VF_I 192.168.0.1 192.168.1.1 $H2MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/client.conf"
    if [ "$REG" = none ]; then
      env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" ESAC_HIST_FILE="$d/hist.txt" ESAC_HIST_START_SEC=3 timeout 34 "$HIST" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 33
    else
      export BPFTIME_GLOBAL_SHM_NAME=$SHM
      bash -c 'kill -STOP "$$"; exec env LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" ESAC_HIST_FILE="$3" ESAC_HIST_START_SEC=3 "$4" -c "$5"' _ "$AGENT:$UFUNC" "$LIB" "$d/hist.txt" "$HIST" "$d/client.conf" > "$d/client.log" 2>&1 &
      local cli=$!; sleep 1; [ "$(awk '{print $3}' /proc/$cli/stat 2>/dev/null)" != T ] && { echo "NA,NA|NOSTOP"; KILL1; h2_kill; return; }
      attach "$cli" tx "$L4OBJ" "$L_TX" "$HIST" 6 ALLOW "$d" "$SHM"
      [ "$RDY" != YES ] && { echo "NA,NA|ATTACHFAIL"; kill -9 $cli 2>/dev/null; KILL1; h2_kill; return; }
      kill -CONT "$cli"; sleep 33
    fi
    KILL1; sleep 2; h2_kill
    echo "$(hp "$d/hist.txt")|appRtt=$(rttus "$d/client.log")|$(actsum "$d"/loader.log 2>/dev/null)"
  fi
}

# ======================= cell dispatch with none-cache + pct =======================
getnone(){ local T=$1 DIR=$2 METRIC=$3 CORE=$4 OFF=$5 PAY=$6; local nk="${T}_${DIR}_${METRIC}_${CORE}_${OFF}_${PAY}"
  local v=$(sed -n "s/^$nk=//p" "$NONEC"|head -1); [ -n "$v" ] && { echo "$v"; return; }
  local d="$ROOT/none_$nk"; local out
  if [ "$METRIC" = rtt ]; then
    [ "$T" = intra ] && out=$(intra_rtt none "$DIR" "$CORE" "$OFF" "$PAY" "$d") || out=$(inter_rtt none "$DIR" "$CORE" "$OFF" "$PAY" "$d")
  else
    local layer=l4; [ "$METRIC" = l7t ] && layer=l7
    [ "$T" = intra ] && out=$(intra_cell none "$DIR" "$layer" "$CORE" "$OFF" "$PAY" pass "$d") || out=$(inter_cell none "$DIR" "$layer" "$CORE" "$OFF" "$PAY" pass "$d")
  fi
  echo "$nk=$out" >> "$NONEC"; echo "$out"
}

# run one esac cell + its none, emit KEY line. args: T DIR METRIC CORE OFF PAY
cell(){ local T=$1 DIR=$2 METRIC=$3 CORE=$4 OFF=$5 PAY=$6
  local key="${T}_${DIR}_${METRIC}_${CORE}c_${OFF}_${PAY}B"
  done_key "$key" && { log "skip $key (done)"; return; }
  log "RUN $key"
  local nraw=$(getnone "$T" "$DIR" "$METRIC" "$CORE" "$OFF" "$PAY")
  local eraw d="$ROOT/esac_$key"
  if [ "$METRIC" = rtt ]; then
    [ "$T" = intra ] && eraw=$(intra_rtt esac "$DIR" "$CORE" "$OFF" "$PAY" "$d") || eraw=$(inter_rtt esac "$DIR" "$CORE" "$OFF" "$PAY" "$d")
    emit "KEY=$key METRIC=rtt | none[$nraw] esac[$eraw]"
  else
    local layer=l4; [ "$METRIC" = l7t ] && layer=l7
    [ "$T" = intra ] && eraw=$(intra_cell esac "$DIR" "$layer" "$CORE" "$OFF" "$PAY" pass "$d") || eraw=$(inter_cell esac "$DIR" "$layer" "$CORE" "$OFF" "$PAY" pass "$d")
    local nd=$(echo "$nraw"|cut -d'|' -f1) ed=$(echo "$eraw"|cut -d'|' -f1)
    local pct=NA; [ "${nd:-0}" -gt 0 ] 2>/dev/null && pct=$(awk "BEGIN{printf \"%.0f\", $ed*100/$nd}")
    emit "KEY=$key METRIC=$METRIC | none=$nd esac=$ed pct=${pct}% | none_raw[$nraw] esac_raw[$eraw]"
    # enforcement proof: L7 domain-drop (dnsq_su .su -> DROP). Only meaningful for L7 (L4 port-drop tuple differs from DNS flood). Once per T/DIR at 1c/max/64.
    if [ "$METRIC" = l7t ] && [ "$OFF" = max ] && [ "$PAY" = 64 ] && [ "$CORE" = 1 ]; then
      local dd="$ROOT/drop_${T}_${DIR}_l7"; local draw
      [ "$T" = intra ] && draw=$(intra_cell esac "$DIR" l7 1 max 64 drop "$dd") || draw=$(inter_cell esac "$DIR" l7 1 max 64 drop "$dd")
      emit "ENF=$key layer=l7 .su_drop_delivered[$draw]"
    fi
  fi
}

# ======================= PASS1: headline (64B, max) =======================
run_pass(){ local OFFS_L="$1" PAYS_L="$2" TAG=$3
  log "==== PASS $TAG offered=($OFFS_L) payload=($PAYS_L) ===="
  for T in intra inter; do
    if [ "$T" = intra ]; then intra_up; else inter_vf_up; fi
    for DIR in rx tx; do
      for CORE in 1 4; do
        for OFF in $OFFS_L; do
          for PAY in $PAYS_L; do
            for M in l4t rtt l7t; do cell "$T" "$DIR" "$M" "$CORE" "$OFF" "$PAY"; done
          done
        done
      done
    done
    if [ "$T" = intra ]; then intra_down; else inter_vf_down; fi
  done
}

# ======================= Suricata (intra + inter), L7 throughput =======================
suricata_phase(){ log "==== Suricata phase ===="
  # INTRA suricata via 4-VF (client-nfA-nfB-server). 1c and 4c(attempt).
  KILL1; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; sleep 2
  devlink dev eswitch set pci/$PF_INTRA mode switchdev 2>/dev/null; sleep 1
  ethtool -K $IF_INTRA hw-tc-offload on 2>/dev/null
  echo 4 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF_INTRA/virtfn3 ] && break; sleep 1; done; sleep 3
  ip link set $IF_INTRA up 2>/dev/null
  rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
  local CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn0))
  local AVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn1))
  local BVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn2))
  local SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn3))
  local E0=$(rep 0) E1=$(rep 1) E2=$(rep 2) E3=$(rep 3)
  ip link set $IF_INTRA vf 0 mac 02:60:00:00:00:01 2>/dev/null; ip link set $IF_INTRA vf 3 mac 02:60:00:00:00:04 2>/dev/null
  ip link set $IF_INTRA vf 1 mac 02:60:00:00:00:02 2>/dev/null; ip link set $IF_INTRA vf 2 mac 02:60:00:00:00:03 2>/dev/null
  for i in 0 1 2 3; do ip link set $IF_INTRA vf $i spoofchk off 2>/dev/null; ip link set $IF_INTRA vf $i trust on 2>/dev/null; done
  for e in $E0 $E1 $E2 $E3; do ip link set $e up 2>/dev/null; tc qdisc add dev $e ingress 2>/dev/null; done
  for CORE in 1 4; do
    local key="suri_intra_l7t_${CORE}c_max_64B"; done_key "$key" && { log "skip $key"; continue; }
    log "RUN $key"
    local d="$ROOT/$key"; mkdir -p "$d"; hsdb
    for e in $E0 $E1 $E2 $E3; do tc filter del dev $e ingress 2>/dev/null; done
    tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1
    tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0
    tc filter add dev $E2 ingress protocol all flower skip_sw action mirred egress redirect dev $E3
    tc filter add dev $E3 ingress protocol all flower skip_sw action mirred egress redirect dev $E2
    cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu $(scpu $CORE)
duration 60s
payload_size 64
protocol udp
keepalive 20us
socket_mem 1024
port $SVF 192.168.1.1 192.168.0.1 02:60:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/server.conf"
    cat > "$d/client.conf" <<C
mode client
tx_burst 32
cpu $(ccpu $CORE)
duration 26s
payload_file $QCOM
protocol udp
cps 4000
cc 10000
keepalive 20us
socket_mem 0,2048
port $CVF 192.168.0.1 192.168.1.1 02:60:00:00:00:04
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
    [ "$CORE" = 4 ] && echo rss >> "$d/client.conf"
    # suricata IPS between nfA(E1)<->nfB(E2); SURI threads = CORE
    local st=NO
    env LD_LIBRARY_PATH=$SURILIB timeout 85 "$SURI" -c "$SYAML" --dpdk -l "$d" > "$d/suri.log" 2>&1 &
    for j in $(seq 1 50); do grep -qiE "engine started|Threads created" "$d/suri.log" 2>/dev/null && { st=YES; break; }; sleep 1; done
    if [ "$st" != YES ]; then emit "KEY=$key METRIC=suri | SURI_FAIL core=$CORE $(grep -iE 'error|no supported|mlx5|thread' "$d/suri.log"|tail -2|tr '\n' ';')"; KILL1; continue; fi
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 56 "$ECHO" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 28 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 30
    KILL1; sleep 2
    local alert=$(grep -ac "\"event_type\":\"alert\"" "$d/eve.json" 2>/dev/null)
    emit "KEY=$key METRIC=suri | delivered=$(med "$d/server.log") offered=$(lasttx "$d/client.log") alerts=${alert:-NA}"
  done
  KILL1; echo 0 > /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs 2>/dev/null; devlink dev eswitch set pci/$PF_INTRA mode legacy 2>/dev/null
  log "Suricata inter: SKIPPED (middlebox needs 3-port on host1; mlx5 VF suri 4-thread known-broken) — intra covers comparison"
}


# ======================= MAIN (Suricata only) =======================
log "SURI-ONLY START root=$ROOT"
suricata_phase
KILL1
log "SURI-ONLY DONE root=$ROOT"

#!/bin/bash
# Autonomous L4 CE sweep campaign: CE6->CE7->CE5->CE4->CE3. inter(f0,host2) + intra(f1,local).
# modes: inter {none,eSAC,kernel}; intra {none,eSAC} (kernel deferred). pps + RTT p50/p90/p99.
set +u
RES=/home/sungwoo/eSACfinal/results/CE_RESULTS; mkdir -p "$RES"
ROOT=/home/sungwoo/eSACfinal/results/ce_l4_run_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"; echo "$ROOT">/home/sungwoo/eSACfinal/results/.ce_l4_dir
PROG=$RES/progress.log; say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$PROG"; }

APP=/home/sungwoo/eSACfinal/traffic/dperf_burst128
LOADER=/home/sungwoo/eSACfinal/comm_plane/loaders/comm_loader_cgroup_maskprobe
L4=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
RUN=/home/sungwoo/eSACfinal/harness/ce_l4/auto_case_hist.sh
RUNNP=/home/sungwoo/eSACfinal/harness/ce_l4/auto_case_hist_np.sh
SRV=/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode.sh
SRVNP=/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode_np.sh
HISTCLI=/home/sungwoo/eSACfinal/traffic/dperf_hist
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk
PF0=0000:3b:00.0; PF1=0000:3b:00.1; IF1=enp59s0f1np1
INTRA_SVF=; INTRA_CVF=

killdp(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f comm_loader 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel_prologue 2>/dev/null; for cg in /sys/fs/cgroup/esac_inter_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sleep 1; }
rep_of1(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }

prep_vf_inter(){ # create VF 3b:00.3 on f0 if missing
  grep -q 1 /sys/bus/pci/devices/$PF0/sriov_numvfs 2>/dev/null && [ -e /sys/bus/pci/devices/0000:3b:00.3 ] && return 0
  sudo -n env VF_TTL=14400 bash /home/sungwoo/eSACfinal/harness/setup/host1_vf_prepare.sh > "$ROOT/vfinter.log" 2>&1
  grep -q '^VF_BDF=0000:3b:00.3$' "$ROOT/vfinter.log"; }

intra_up(){
  sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null; sleep 2
  sudo -n devlink dev eswitch set pci/$PF1 mode switchdev 2>/dev/null; sleep 1
  sudo -n ethtool -K $IF1 hw-tc-offload on 2>/dev/null
  sudo -n sh -c "echo 2 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF1/virtfn1 ] && break; sleep 1; done; sleep 3
  sudo -n ip link set $IF1 up 2>/dev/null
  INTRA_SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn0))
  INTRA_CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn1))
  sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null
  sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
  for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
  local srep=$(rep_of1 0) crep=$(rep_of1 1)
  sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
  sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
  sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
  sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
  local hw=$(sudo -n tc filter show dev $srep ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1)
  say "intra_up SVF=$INTRA_SVF CVF=$INTRA_CVF tc=$hw"; }

cps_of(){ local cc=$1; local c=4000; [ "$cc" -lt 4000 ] && c=$cc; [ "$c" -lt 1 ] && c=1; echo $c; }
cdur_of(){ local cc=$1 cps=$2; local d=$(( cc/cps + 22 )); [ $d -lt 32 ] && d=32; echo $d; }

# run_one path o mode ka cc cps pay scpu ccpu npol action
run_one(){ local path=$1 o=$2 mode=$3 ka=$4 cc=$5 cps=$6 pay=$7 scpu="$8" ccpu="$9" npol=${10} act=${11}
  local rm; case $mode in none)rm=none;; eSAC)rm=bpftime;; kernel)rm=kernel;; esac
  if [ "$path" = inter ]; then ccpu="16 17"; else ccpu="20 21 22 23"; fi  # FIX: fixed client cores (client fails at 4c); only server lcores sweep
  killdp
  local cdur=$(cdur_of $cc $cps)
  if [ "$path" = inter ]; then
    prep_vf_inter || { echo "VFPREP_FAIL" > "$o/FAIL"; return 1; }
    local RX=$RUN; [ "$npol" != 2 ] && RX=$RUNNP
    timeout --signal=TERM --kill-after=25 $((cdur+150))s env NPOL=$npol MODE=$rm ACTION=$act PORT=0000:3b:00.3 SERVER_MAC=02:40:00:00:00:11 \
      APP=$APP COMBO=$L4 BURST_LOADER=$LOADER SCPU="$scpu" CLIENT_CPU="$ccpu" DUR=55 CLIENT_DUR=$cdur CC=$cc CPS=$cps KEEPALIVE=$ka PROTO=tcp \
      PAYLOAD=$pay SOCKET_MEM=2048 MAX_BURST_INSPECT=128 POLCPU=10 PROCPU=11 OUT="$o" \
      setsid bash "$RX" > "$o.outer.log" 2>&1
    return 0
  fi
  # intra
  :  # intra-kernel enabled
  [ -z "$INTRA_SVF" ] && intra_up
  local SX=$SRV; [ "$npol" != 2 ] && SX=$SRVNP
  sudo -n env NPOL=$npol MODE=$rm OUT="$o" DUR=55 SCPU="$scpu" POLCPU=28 PROCPU=29 SOCKET_MEM=2048 \
    PAYLOAD=$pay KEEPALIVE=$ka ACTION=$act PORT=$INTRA_SVF APP=$APP COMBO=$L4 \
    MAX_BURST_INSPECT=128 BURST_LOADER=$LOADER PROTO=tcp \
    setsid bash "$SX" > "$o.outer.log" 2>&1 &
  local sp=$!
  local rdy=0; for i in $(seq 1 75); do [ -e "$o/.ready" ] && { rdy=1; break; }; grep -q FAIL "$o/run.log" 2>/dev/null && break; kill -0 $sp 2>/dev/null || break; sleep 1; done
  [ $rdy -eq 1 ] || { echo "INTRA_NOTREADY" > "$o/FAIL"; kill -9 $sp 2>/dev/null; return 1; }
  local ccpu2=${ccpu// /,}
  cat > "$o/cl.conf" <<C
mode client
tx_burst 128
cpu $ccpu
duration ${cdur}s
cps $cps
cc $cc
keepalive $ka
payload_size $pay
protocol tcp
socket_mem 1024
port $INTRA_CVF 192.168.0.1 192.168.1.1 02:51:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
  [[ "$ccpu" == *" "* ]] && echo rss >> "$o/cl.conf"
  sudo -n env LD_LIBRARY_PATH=$LIB GOWN_HIST_FILE="$o/hist.txt" GOWN_HIST_START_SEC=3 \
    timeout $((cdur+10)) "$HISTCLI" -c "$o/cl.conf" > "$o/cl.log" 2>&1
  for i in $(seq 1 90); do [ -e "$o/.done" ] && break; kill -0 $sp 2>/dev/null || break; sleep 1; done
  wait $sp 2>/dev/null; killdp; return 0
}

# extract outdir -> "pps p50 p90 p99 hits att"
extract(){ local o=$1
  local pps=$(sed -n 's/.*pps_med=\([0-9]*\).*/\1/p' "$o/run.log" 2>/dev/null|tail -1)
  { [ -z "$pps" ] || [ "$pps" = 0 ]; } && pps=$(awk '/Total Numbers/{exit}/^pktRx/{x=$2;gsub(",","",x);print x}' "$o/server.log" 2>/dev/null|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}')
  local h=$(head -1 "$o/hist.txt" 2>/dev/null)
  local p50=$(echo "$h"|grep -oE 'p50_us=[0-9]+'|cut -d= -f2)
  local p90=$(echo "$h"|grep -oE 'p90_us=[0-9]+'|cut -d= -f2)
  local p99=$(echo "$h"|grep -oE 'p99_us=[0-9]+'|cut -d= -f2)
  local hits=$(grep -aoE 'policy_hits[ =:]+[0-9]+' "$o/loader.log" 2>/dev/null|grep -oE '[0-9]+'|sort -n|tail -1)
  local att=NO; grep -q 'attach summary: RX=OK TX=OK' "$o/loader.log" 2>/dev/null && att=YES
  echo "${pps:-0} ${p50:-NA} ${p90:-NA} ${p99:-NA} ${hits:-NA} $att"; }

declare -A ENF
enforce_proof(){ local path=$1 mode=$2 ka=$3 cc=$4 cps=$5 pay=$6 scpu="$7" ccpu="$8"
  local key="${path}_${mode}"; [ "$mode" = none ] && { ENF[$key]=NA; return; }
  [ -n "${ENF[$key]}" ] && return
  local o=$ROOT/ENF_${path}_${mode}; rm -rf "$o"; mkdir -p "$o"
  say "ENFORCE-PROOF $path/$mode (DROP)"
  run_one "$path" "$o" "$mode" "$ka" "$cc" "$cps" "$pay" "$scpu" "$ccpu" 2 DROP
  read pps p50 p90 p99 hits att <<< "$(extract "$o")"
  if [ "${pps:-0}" -lt 100000 ] && [ "$att" = YES -o "$mode" = kernel ]; then ENF[$key]=YES; else ENF[$key]=NO; fi
  say "ENFORCE-PROOF $path/$mode -> ${ENF[$key]} (drop_pps=$pps att=$att)"; }

# cell ce path mode svar value ka cc cps pay scpu ccpu npol
cell(){ local ce=$1 path=$2 mode=$3 svar=$4 val=$5 ka=$6 cc=$7 cps=$8 pay=$9 scpu="${10}" ccpu="${11}" npol=${12}
  local o=$ROOT/${ce}_${path}_${mode}_${svar}_${val}; rm -rf "$o"; mkdir -p "$o"
  say "CELL $ce $path $mode $svar=$val (ka=$ka cc=$cc pay=$pay lc='$scpu' npol=$npol)"
  run_one "$path" "$o" "$mode" "$ka" "$cc" "$cps" "$pay" "$scpu" "$ccpu" "$npol" ALLOW
  local rc=$?
  if [ $rc -eq 2 ]; then printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ce" "$path" "$mode" "$svar" "$val" NA NA NA NA NA NA DEFERRED >> "$RES/$ce.tsv"; return; fi
  read pps p50 p90 p99 hits att <<< "$(extract "$o")"
  local status=ready; local need=0
  { [ -z "$pps" ] || [ "${pps:-0}" -lt 1000 ]; } && need=1
  [ "$mode" = eSAC ] && [ "$att" != YES ] && need=1
  if [ $need -eq 1 ]; then
    say "  remeasure $ce $path $mode $svar=$val (pps=$pps att=$att)"
    rm -rf "$o"; mkdir -p "$o"
    run_one "$path" "$o" "$mode" "$ka" "$cc" "$cps" "$pay" "$scpu" "$ccpu" "$npol" ALLOW
    read pps p50 p90 p99 hits att <<< "$(extract "$o")"
    { [ -z "$pps" ] || [ "${pps:-0}" -lt 1000 ]; } && status=FAILED
    [ "$mode" = eSAC ] && [ "$att" != YES ] && status=FAILED
  fi
  local enf=${ENF[${path}_${mode}]:-NA}
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ce" "$path" "$mode" "$svar" "$val" "${pps:-0}" "${p50:-NA}" "${p90:-NA}" "${p99:-NA}" "${hits:-NA}" "$enf" "$status" >> "$RES/$ce.tsv"
  say "  -> pps=$pps p50=$p50 p90=$p90 p99=$p99 hits=$hits enf=$enf $status"; }

HDR='ce\tpath\tmode\tsweepvar\tvalue\tpps\trtt_p50\trtt_p90\trtt_p99\tpolicy_hits\tenforced\tstatus'
DEF_SCPU="6 7 8 9"; DEF_CCPU="16 17 18 19"; DEF_KA=20us; DEF_CC=10000; DEF_PAY=512; DEF_NPOL=2
lc_scpu(){ case $1 in 1)echo "6";; 2)echo "6 7";; 4)echo "6 7 8 9";; esac; }
lc_ccpu(){ case $1 in 1)echo "16";; 2)echo "16 17";; 4)echo "16 17 18 19";; esac; }

say "===== CE5 payload=1400 re-measure (inter+intra, none/eSAC/kernel, 2x) root=$ROOT ====="
killdp
prep_vf_inter && say "inter VF ready" || say "inter VF FAIL"
intra_up && say "intra VF ready SVF=$INTRA_SVF CVF=$INTRA_CVF" || say "intra VF FAIL"
ENF[inter_none]=NA; ENF[inter_eSAC]=NA; ENF[inter_kernel]=NA
ENF[intra_none]=NA; ENF[intra_eSAC]=NA; ENF[intra_kernel]=NA
echo -e "$HDR" > "$RES/CE5p1400.tsv"
# intra: cc8000/1ms/4c
for m in none eSAC kernel; do
  for r in a b; do cell CE5p1400 intra $m pay "1400_${r}" 1ms 8000 $(cps_of 8000) 1400 "$DEF_SCPU" "20 21 22 23" 2; done
done
# inter: cc10000/20us/4c  (run_one forces inter client cores 16 17)
for m in none eSAC kernel; do
  for r in a b; do cell CE5p1400 inter $m pay "1400_${r}" 20us 10000 $(cps_of 10000) 1400 "$DEF_SCPU" "16 17" 2; done
done
touch "$RES/CE5p1400.done"; say "===== CE5p1400 DONE ====="
killdp

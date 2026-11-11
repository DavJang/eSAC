#!/bin/bash
# Motivation sweep v3: adds PROBE-SERVER AUTO-RECOVERY to beat the cascade collapse seen in v2.
# When a cell returns ~0 samples (attacker churn wedged the shared eSwitch for the probe VF pair),
# we kill+restart the probe SERVER and re-install its hairpin, then retry the cell once.
# LOAD A->B 64B UDP ~14Mpps saturation; LIGHT dperf_hist TCP RTT probe on a separate VF pair;
# attacker kernel VF issues ONE control-API install/delete cycle per call. 3 reps/cell, median of
# non-zero reps. Produces (a) mean & (b) p99 latency vs attacker calls/s for 4 control APIs.
set +u
PF=0000:3b:00.1; IF=enp59s0f1np1
DL=/home/sungwoo/FINAL/traffic/dperf
DH=/home/sungwoo/eSACfinal/traffic/dperf_hist
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk:/home/sungwoo/FINAL/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=/home/sungwoo/FINAL/results/motiv_sweep3_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; CSV="$OUT/sweep.csv"; : > "$R"
echo "api,rate,mean_us,p50_us,p90_us,p99_us,p999_us,loadMpps,samples" > "$CSV"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -x dperf_hist 2>/dev/null; sudo -n pkill -9 -f atksw 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  sudo -n find /dev/hugepages -maxdepth 1 -name 'dperf-*' -delete 2>/dev/null
  say "RESTORED numvfs=0 node0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages)"; echo EXP_DONE>>"$R"; }
trap restore EXIT

sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -x dperf_hist 2>/dev/null
echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 6 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn5 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
LC=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0)); LS=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1))
PC=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn2)); PS=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn3))
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2) E3=$(rep 3) E4=$(rep 4)
AVF=; for n in /sys/class/net/*; do [ "$(basename $(readlink -f $n/device 2>/dev/null))" = "$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn4))" ] && AVF=$(basename $n); done
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
sudo -n ip link set $IF vf 2 mac 02:70:00:00:00:03 2>/dev/null; sudo -n ip link set $IF vf 3 mac 02:70:00:00:00:04 2>/dev/null
for i in 0 1 2 3 4; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2 $E3 $E4; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
sudo -n ip link set $AVF up 2>/dev/null
install_hairpin(){
  sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
  sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
  sudo -n tc filter add dev $E2 ingress protocol all flower skip_sw action mirred egress redirect dev $E3 2>/dev/null
  sudo -n tc filter add dev $E3 ingress protocol all flower skip_sw action mirred egress redirect dev $E2 2>/dev/null; }
reinstall_probe_hairpin(){
  sudo -n tc filter del dev $E2 ingress 2>/dev/null; sudo -n tc filter del dev $E3 ingress 2>/dev/null; sleep 0.3
  sudo -n tc filter add dev $E2 ingress protocol all flower skip_sw action mirred egress redirect dev $E3 2>/dev/null
  sudo -n tc filter add dev $E3 ingress protocol all flower skip_sw action mirred egress redirect dev $E2 2>/dev/null; }
install_hairpin
say "LOAD $LC->$LS ; PROBE(TCP) $PC<->$PS ; ATTACKER kernel=$AVF rep=$E4"

cat > "$OUT/ls.conf" <<C
mode server
rss
tx_burst 128
cpu 24 25 26 27
duration 3000s
payload_size 64
protocol udp
keepalive 1ms
socket_mem 4096
port $LS 192.168.11.1 192.168.10.1 02:70:00:00:00:01
client 192.168.10.1 1
server 192.168.11.1 1
listen 80 1
C
cat > "$OUT/lc.conf" <<C
mode client
rss
tx_burst 128
cpu 20 21 22 23
duration 3000s
payload_size 64
protocol udp
cps 40000
cc 40000
keepalive 10us
socket_mem 5120
port $LC 192.168.10.1 192.168.11.1 02:70:00:00:00:02
client 192.168.10.1 1
server 192.168.11.1 1
listen 80 1
C
cat > "$OUT/ps.conf" <<C
mode server
tx_burst 32
cpu 6
duration 3000s
payload_size 64
protocol tcp
keepalive 1ms
socket_mem 1024
port $PS 192.168.21.1 192.168.20.1 02:70:00:00:00:03
client 192.168.20.1 1
server 192.168.21.1 1
listen 9 1
C
cat > "$OUT/pc.conf" <<C
mode client
tx_burst 32
cpu 8
duration 15s
payload_size 64
protocol tcp
cps 1000
cc 1000
keepalive 1ms
socket_mem 2048
port $PC 192.168.20.1 192.168.21.1 02:70:00:00:00:04
client 192.168.20.1 1
server 192.168.21.1 1
listen 9 1
C

atksw(){ local api=$1 rate=$2; local gap; gap=$(awk -v r=$rate 'BEGIN{printf "%.3f",1.0/r}'); local end=$((SECONDS+14)); local i=0
  while [ $SECONDS -lt $end ]; do i=$((i+1))
    case $api in
      flow)    sudo -n tc filter add dev $E4 ingress pref 1 protocol ip flower skip_sw dst_ip 10.1.1.1 action drop 2>/dev/null; sudo -n tc filter del dev $E4 ingress pref 1 2>/dev/null;;
      restart) sudo -n ip link set $AVF down 2>/dev/null; sudo -n ip link set $AVF up 2>/dev/null;;
      promisc) sudo -n ip link set $AVF promisc on 2>/dev/null; sudo -n ip link set $AVF promisc off 2>/dev/null;;
      mcast)   sudo -n ip maddr add 01:00:5e:01:02:03 dev $AVF 2>/dev/null; sudo -n ip maddr del 01:00:5e:01:02:03 dev $AVF 2>/dev/null;;
    esac
    sleep "$gap"
  done; }

loadnow(){ sed 's/\x1b\[[0-9;]*m//g' "$OUT/ls.log" | grep -aoE 'pktRx +[0-9,]+' | sed 's/pktRx//; s/[ ,]//g' | awk '$1+0>1000000 && $1+0<30000000{v=$1} END{printf "%.1f", (v+0)/1e6}'; }

start_probe_server(){ sudo -n pkill -9 -x dperf_hist 2>/dev/null; sleep 1; reinstall_probe_hairpin
  sudo -n env LD_LIBRARY_PATH=$LIB "$DH" -c "$OUT/ps.conf" > "$OUT/ps.log" 2>&1 & sleep 5; }

# median of NON-ZERO values; if all zero -> 0
mednz(){ local vals=(); for v in "$@"; do [ "${v%.*}" != 0 ] 2>/dev/null && vals+=("$v"); done
  [ ${#vals[@]} -eq 0 ] && { echo 0; return; }; printf '%s\n' "${vals[@]}" | sort -n | awk '{a[NR]=$0} END{print a[int((NR+1)/2)]}'; }

onerep(){ local api=$1 rate=$2 tag=$3 try
  for try in 1 2; do
    if [ "$api" != none ]; then ( exec -a atksw bash -c "$(declare -f atksw); E4=$E4; AVF=$AVF; atksw $api $rate" ) & local ap=$!; sleep 1; fi
    sudo -n env LD_LIBRARY_PATH=$LIB GOWN_HIST_FILE=$OUT/h_${tag}_t$try.txt GOWN_HIST_START_SEC=4 "$DH" -c "$OUT/pc.conf" > "$OUT/pc_${tag}_t$try.log" 2>&1
    [ "$api" != none ] && { kill $ap 2>/dev/null; sudo -n pkill -9 -f atksw 2>/dev/null; }
    local L=$(grep -a 'gown_hist' "$OUT/h_${tag}_t$try.txt" 2>/dev/null)
    local sm=$(echo "$L"|grep -oE 'samples=[0-9]+'|cut -d= -f2)
    if [ "${sm:-0}" -ge 5000 ] 2>/dev/null; then echo "$L"; return; fi
    # probe collapsed: recover server + hairpin, retry once
    say "    [recover] $tag try$try samples=${sm:-0} -> restart probe server"; start_probe_server
  done
  echo "$L"; }

runcell(){ local api=$1 rate=$2; local means=() p99s=() p50s=() samps=()
  for r in 1 2 3; do
    local L=$(onerep "$api" "$rate" "${api}_${rate}_r$r")
    means+=("$(echo "$L"|grep -oE 'mean_us=[0-9.]+'|cut -d= -f2)") ; means[-1]="${means[-1]:-0}"
    p99s+=("$(echo "$L"|grep -oE 'p99_us=[0-9]+'|cut -d= -f2)") ; p99s[-1]="${p99s[-1]:-0}"
    p50s+=("$(echo "$L"|grep -oE 'p50_us=[0-9]+'|cut -d= -f2)") ; p50s[-1]="${p50s[-1]:-0}"
    samps+=("$(echo "$L"|grep -oE 'samples=[0-9]+'|cut -d= -f2)") ; samps[-1]="${samps[-1]:-0}"
  done
  local Mmean=$(mednz "${means[@]}"); local Mp99=$(mednz "${p99s[@]}"); local Mp50=$(mednz "${p50s[@]}"); local Msm=$(mednz "${samps[@]}"); local lp=$(loadnow)
  local dn=""; [ "${Msm%.*}" -lt 5000 ] 2>/dev/null && dn=" DENIED(victim near-0 samples)"
  echo "$api,$rate,$Mmean,$Mp50,,$Mp99,,$lp,$Msm" >> "$CSV"
  say "  $api @ $rate/s : mean=${Mmean} p50=${Mp50} p99=${Mp99} (reps mean=[${means[*]}] p99=[${p99s[*]}]) load=${lp} samp=${Msm}$dn"; }

sudo -n env LD_LIBRARY_PATH=$LIB "$DL" -c "$OUT/ls.conf" > "$OUT/ls.log" 2>&1 & sleep 4
sudo -n env LD_LIBRARY_PATH=$LIB "$DL" -c "$OUT/lc.conf" > "$OUT/lc.log" 2>&1 & sleep 10
start_probe_server
say "load steady: $(loadnow) Mpps"
say "===== SWEEP v3 (3-rep median of nonzero, TCP probe + auto-recovery) ====="
runcell none 0
for rate in 0.5 1 2 4 8 16; do
  for api in flow restart promisc mcast; do runcell $api $rate; done
done
say "===== CSV ====="; cat "$CSV" | tee -a "$R"
say "DONE OUT=$OUT"

#!/bin/bash
# Rate SWEEP v4 = EXACT motiv_saturation.sh mechanics (which survived single-pass) expanded to a
# full rate sweep: 4 control APIs x 5 rates, ONE rep each, persistent LOAD + persistent probe
# SERVER, short 15s probe phases. Produces the professor's 2-panel figure data (mean/p99 RTT vs
# attacker calls/s for flow/restart/promisc/mcast). No 3-rep thrash, no per-cell server restart
# (those wedged v3). A load-health line is printed each phase so a mid-sweep collapse is visible.
set +u
PF=0000:3b:00.1; IF=enp59s0f1np1
DL=/home/sungwoo/FINAL/traffic/dperf
DH=/home/sungwoo/eSACfinal/traffic/dperf_hist
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk:/home/sungwoo/FINAL/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=/home/sungwoo/FINAL/results/motiv_sweep4_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; CSV="$OUT/sweep.csv"; : > "$R"
echo "api,rate,mean_us,p50_us,p90_us,p99_us,p999_us,loadMpps" > "$CSV"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -x dperf_hist 2>/dev/null; sudo -n pkill -9 -f atksat 2>/dev/null; sleep 1
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
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
sudo -n tc filter add dev $E2 ingress protocol all flower skip_sw action mirred egress redirect dev $E3 2>/dev/null
sudo -n tc filter add dev $E3 ingress protocol all flower skip_sw action mirred egress redirect dev $E2 2>/dev/null
say "LOAD $LC->$LS ; PROBE $PC<->$PS ; ATTACKER kernel=$AVF rep=$E4"

cat > "$OUT/ls.conf" <<C
mode server
rss
tx_burst 128
cpu 24 25 26 27
duration 900s
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
duration 900s
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
duration 900s
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
cps 100
cc 100
keepalive 1ms
socket_mem 2048
port $PC 192.168.20.1 192.168.21.1 02:70:00:00:00:04
client 192.168.20.1 1
server 192.168.21.1 1
listen 9 1
C

atksat(){ local api=$1 rate=$2; local gap; gap=$(awk -v r=$rate 'BEGIN{printf "%.3f",1.0/r}'); local end=$((SECONDS+19)); local i=0
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

runphase(){ local api=$1 rate=$2 tag="${api}_${rate}"
  if [ "$api" != none ]; then ( exec -a atksat bash -c "$(declare -f atksat); E4=$E4; AVF=$AVF; atksat $api $rate" ) & local ap=$!; sleep 1; fi
  sudo -n env LD_LIBRARY_PATH=$LIB GOWN_HIST_FILE=$OUT/ph_$tag.txt GOWN_HIST_START_SEC=4 "$DH" -c "$OUT/pc.conf" > "$OUT/pc_$tag.log" 2>&1
  [ "$api" != none ] && { kill $ap 2>/dev/null; sudo -n pkill -9 -f atksat 2>/dev/null; }
  local L=$(grep -a 'gown_hist' "$OUT/ph_$tag.txt" 2>/dev/null)
  local mean=$(echo "$L"|grep -oE 'mean_us=[0-9.]+'|cut -d= -f2); local p50=$(echo "$L"|grep -oE 'p50_us=[0-9]+'|cut -d= -f2)
  local p90=$(echo "$L"|grep -oE 'p90_us=[0-9]+'|cut -d= -f2); local p99=$(echo "$L"|grep -oE 'p99_us=[0-9]+'|cut -d= -f2)
  local p999=$(echo "$L"|grep -oE 'p999_us=[0-9]+'|cut -d= -f2); local sm=$(echo "$L"|grep -oE 'samples=[0-9]+'|cut -d= -f2); local lp=$(loadnow)
  echo "$api,$rate,${mean:-0},${p50:-0},${p90:-0},${p99:-0},${p999:-0},$lp" >> "$CSV"
  say "  ${api}@${rate}/s : mean=${mean:-NA} p50=${p50:-NA} p99=${p99:-NA} p999=${p999:-NA} samp=${sm:-0} load=${lp}"; }

sudo -n env LD_LIBRARY_PATH=$LIB "$DL" -c "$OUT/ls.conf" > "$OUT/ls.log" 2>&1 & sleep 4
sudo -n env LD_LIBRARY_PATH=$LIB "$DL" -c "$OUT/lc.conf" > "$OUT/lc.log" 2>&1 & sleep 8
sudo -n env LD_LIBRARY_PATH=$LIB "$DH" -c "$OUT/ps.conf" > "$OUT/ps.log" 2>&1 & sleep 5
say "load warmed: $(loadnow) Mpps"
say "===== SWEEP v4 (single-pass, saturation mechanics) ====="
runphase none 0
for rate in 0.5 1 2 5 10; do
  for api in flow restart promisc mcast; do runphase $api $rate; done
done
say "===== CSV ====="; cat "$CSV" | tee -a "$R"
say "DONE OUT=$OUT"

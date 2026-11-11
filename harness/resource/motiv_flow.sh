#!/bin/bash
# MOTIVATION flow-mechanism: the victim collapse is caused by FLOW-RULE activity in the shared mlx5
# eSwitch. Is it the RULE COUNT (table fill) or the CHURN RATE (insert/remove HW reprogram thrash)?
#   baseline      : no attacker
#   churn_max     : attacker adds DISTINCT rules forever at max rate (reproduce the collapse)
#   hold500       : attacker installs 500 rules fast, then IDLE (count high, no churn)
#   churn1_max    : attacker add+del the SAME 1 rule at max rate (count ~1, pure reprogram thrash)
# If hold500 is fine but churn1 collapses -> it's the CHURN RATE -> cp_rate throttle is the right fix.
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1; DPERF=$D/traffic/dperf; LIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=$D/results/motiv_flow_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f 'atkflow' 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  sudo -n find /dev/hugepages -maxdepth 1 -name 'dperf-*' -delete 2>/dev/null
  say "RESTORED PF numvfs=0 legacy node0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages)"; echo EXP_DONE >> "$R"; }
trap restore EXIT

sudo -n pkill -9 -x dperf 2>/dev/null; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0))
CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1))
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2)
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
for i in 0 1 2 3; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
say "probe: server=$SVF client=$CVF (hairpin $E0<->$E1); attacker rep=$E2"

cat > "$OUT/server.conf" <<C
mode server
tx_burst 32
cpu 6
duration 60s
payload_size 64
protocol tcp
keepalive 1ms
socket_mem 1024
port $SVF 192.168.1.1 192.168.0.1 02:70:00:00:00:02
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
cat > "$OUT/client.conf" <<C
mode client
tx_burst 32
cpu 16
duration 45s
payload_size 64
protocol tcp
cps 100
cc 100
keepalive 1ms
socket_mem 0,2048
port $CVF 192.168.0.1 192.168.1.1 02:70:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C

# attacker variants on E2 ingress. skip_sw => HW-offloaded into the shared eSwitch.
atkflow(){ local kind=$1; local end=$((SECONDS+50)); local i=0
  case $kind in
    churn_max) while [ $SECONDS -lt $end ]; do i=$((i+1)); printf -v q '10.%d.%d.%d' $(((i>>16)&255)) $(((i>>8)&255)) $((i&255))
                 sudo -n tc filter add dev $E2 ingress pref $(((i%32000)+1)) protocol ip flower skip_sw dst_ip $q action drop 2>/dev/null; done;;
    hold500)   for i in $(seq 1 500); do printf -v q '10.%d.%d.%d' $(((i>>16)&255)) $(((i>>8)&255)) $((i&255))
                 sudo -n tc filter add dev $E2 ingress pref $((i+1)) protocol ip flower skip_sw dst_ip $q action drop 2>/dev/null; done
               say "    (hold500 installed, now idle)"; while [ $SECONDS -lt $end ]; do sleep 1; done;;
    churn1_max) while [ $SECONDS -lt $end ]; do i=$((i+1))
                 sudo -n tc filter add dev $E2 ingress pref 1 protocol ip flower skip_sw dst_ip 10.9.9.9 action drop 2>/dev/null
                 sudo -n tc filter del dev $E2 ingress pref 1 2>/dev/null; done;;
  esac
  say "    (atkflow $kind did $i iters)"; }

metric(){ sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -aoE 'tcpRsp +[0-9,]+' | sed 's/tcpRsp//; s/[ ,]//g' | awk '
  {v=$1+0; if(v>=90000 && v<=300000){st++; if(min==""||v<min)min=v} if(v>40000&&v<300000){any++}}
  END{printf "steady100k_secs=%d min_steady=%s nonzero_secs=%d", st+0, (min==""?"-":min), any+0}'; }

runprobe(){ local tag=$1; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/server.conf" > "$OUT/srv_$tag.log" 2>&1 & sleep 6
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/client.conf" > "$OUT/cli_$tag.log" 2>&1
  sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
  sudo -n tc filter del dev $E2 ingress 2>/dev/null; sudo -n tc qdisc del dev $E2 ingress 2>/dev/null; sudo -n tc qdisc add dev $E2 ingress 2>/dev/null; }

series(){ sed 's/\x1b\[[0-9;]*m//g' "$1" | grep -aoE 'tcpRsp +[0-9,]+' | sed 's/tcpRsp//; s/[ ,]//g' | sed -n '2,56p' | tr '\n' ' '; }

phase(){ local tag=$1 kind=$2
  if [ "$kind" = none ]; then runprobe "$tag"
  else ( atkflow "$kind" ) & local ap=$!; runprobe "$tag"; kill $ap 2>/dev/null; sudo -n pkill -9 -f 'atkflow' 2>/dev/null; fi
  say "  [$tag] $(metric "$OUT/cli_$tag.log")"; say "    series: $(series "$OUT/cli_$tag.log")"; }

say "===== flow-mechanism: rate vs count (victim steady = 100000 tcpRsp/s) ====="
phase baseline   none
phase churn_max  churn_max
phase hold500    hold500
phase churn1_max churn1_max
say "DONE OUT=$OUT"

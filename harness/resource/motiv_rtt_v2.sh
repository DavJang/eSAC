#!/bin/bash
# MOTIVATION v2 — catch TRANSIENT data-path stalls (prof: "a few multicast calls -> huge slowdown").
# Fixes v1: (1) fast warmup cps=100 so steady state (100k tcpRsp/s = cc100/keepalive1ms) lasts ~38s,
# (2) per-second STEADY metric (min + count of dips) instead of a diluted 16s total,
# (3) attacker ACCUMULATES distinct mcast/flow entries (no delete) at MAX rate -> repeated eSwitch
#     steering rebuilds, and runs for the WHOLE steady window. mlx5 PF1 switchdev, HW hairpin probe.
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1; DPERF=$D/traffic/dperf; LIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=$D/results/motiv2_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f 'atkchurn' 2>/dev/null; sleep 1
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
AVFnet=; for n in /sys/class/net/*; do [ "$(basename $(readlink -f $n/device 2>/dev/null))" = "$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn2))" ] && AVFnet=$(basename $n); done
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2)
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
for i in 0 1 2 3; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
sudo -n ip link set $AVFnet up 2>/dev/null
say "probe: server=$SVF client=$CVF (hairpin $E0<->$E1); attacker(kernel)=$AVFnet rep=$E2"

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

# attacker: $1=api $2=rate(calls/s, 0=MAX). mcast/flow ACCUMULATE distinct entries (no delete).
atkchurn(){ local api=$1 rate=$2; local gap=0; [ "${rate:-0}" -gt 0 ] 2>/dev/null && gap=$(awk -v r=$rate 'BEGIN{printf "%.3f",1.0/r}')
  local end=$((SECONDS+50)); local i=0
  while [ $SECONDS -lt $end ]; do i=$((i+1))
    case $api in
      restart) sudo -n ip link set $AVFnet down 2>/dev/null; sudo -n ip link set $AVFnet up 2>/dev/null;;
      promisc) sudo -n ip link set $AVFnet promisc on 2>/dev/null; sudo -n ip link set $AVFnet promisc off 2>/dev/null;;
      mcast)   printf -v m '01:00:5e:%02x:%02x:%02x' $(((i>>16)&255)) $(((i>>8)&255)) $((i&255)); sudo -n ip maddr add $m dev $AVFnet 2>/dev/null;;
      flow)    printf -v q '10.%d.%d.%d' $(((i>>16)&255)) $(((i>>8)&255)) $((i&255)); sudo -n tc filter add dev $E2 ingress protocol ip flower dst_ip $q action drop 2>/dev/null;;
    esac
    [ "$gap" != "0" ] && sleep "$gap"
  done; say "    (atkchurn $api did $i calls)"; }

# per-second STEADY throughput: only seconds with tcpRsp>40000 (post-warmup). min/dips expose stalls.
metric(){ sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -aoE 'tcpRsp +[0-9,]+' | sed 's/tcpRsp//; s/,//g; s/ //g' | awk '
  {v=$1+0; if(v>40000){n++; s+=v; if(min==""||v<min)min=v; if(v>max)max=v; if(v<95000)d95++; if(v<80000)d80++}}
  END{if(n==0){print "no-steady-seconds"; exit} printf "steady_s=%d mean=%.0f min=%d max=%d dips<95k=%d dips<80k=%d", n, s/n, min, max, d95, d80}'; }

runprobe(){ local tag=$1; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/server.conf" > "$OUT/srv_$tag.log" 2>&1 & sleep 6
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/client.conf" > "$OUT/cli_$tag.log" 2>&1
  sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
  # flush accumulated attacker state so next phase starts clean
  sudo -n tc filter del dev $E2 ingress 2>/dev/null; sudo -n tc qdisc del dev $E2 ingress 2>/dev/null; sudo -n tc qdisc add dev $E2 ingress 2>/dev/null; }

phase(){ local tag=$1 api=$2 rate=$3
  if [ "$api" = none ]; then runprobe "$tag"
  else ( atkchurn "$api" "$rate" ) & local ap=$!; runprobe "$tag"; kill $ap 2>/dev/null; sudo -n pkill -9 -f 'ip link set' 2>/dev/null; fi
  say "  [$tag ${api}@${rate}] $(metric "$OUT/cli_$tag.log")"; }

say "===== MOTIVATION v2: steady 100k tcpRsp/s probe; attacker MAX-rate accumulating control-API churn (mlx5) ====="
phase baseline none 0
phase mcastMAX   mcast   0
phase flowMAX    flow    0
phase promiscMAX promisc 0
phase restartMAX restart 0
say "DONE OUT=$OUT"

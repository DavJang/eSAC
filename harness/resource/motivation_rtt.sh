#!/bin/bash
# MOTIVATION exp (paper Fig motivation_exp_lat), CORRECT setup: mlx5 ConnectX, DATA-PATH RTT victim +
# control-API churn attacker. PF1 (3b:00.1) switchdev, 4 VFs: probe server(vf0)<->client(vf1) via HW
# hairpin run a DPDK dperf TCP RTT probe (keepalive 1ms); ATTACKER = kernel VF (vf2) churns ONE NIC
# control op at a fixed rate (port restart / promiscuous / multicast / flow install). We measure the
# probe's appRtt (mean + p99) at each attacker rate. Claim: firmware rebuilds PF-shared steering ->
# victim RTT rises even though victim cores stay idle. Detached; trap-restore.
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1; DPERF=$D/traffic/dperf; LIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=$D/results/motiv_rtt_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f 'atkchurn' 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  say "RESTORED PF numvfs=0 legacy"; echo EXP_DONE >> "$R"; }
trap restore EXIT

sudo -n pkill -9 -x dperf 2>/dev/null; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0))   # probe server (DPDK)
CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1))   # probe client (DPDK)
AVFnet=; for n in /sys/class/net/*; do [ "$(basename $(readlink -f $n/device 2>/dev/null))" = "$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn2))" ] && AVFnet=$(basename $n); done  # attacker (kernel)
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2)
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
for i in 0 1 2 3; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
# hairpin probe pair (server rep E0 <-> client rep E1)
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
sudo -n ip link set $AVFnet up 2>/dev/null
say "probe: server=$SVF client=$CVF (hairpin $E0<->$E1); attacker(kernel)=$AVFnet rep=$E2"

cat > "$OUT/server.conf" <<C
mode server
tx_burst 32
cpu 6
duration 20s
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
duration 16s
payload_size 64
protocol tcp
cps 10
cc 100
keepalive 1ms
socket_mem 0,2048
port $CVF 192.168.0.1 192.168.1.1 02:70:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C

# attacker churn: $1=api $2=rate(calls/s)  (runs ~14s)
atkchurn(){ local api=$1 rate=$2; local gap; gap=$(awk -v r=$rate 'BEGIN{printf "%.3f", 1.0/r}')
  local end=$((SECONDS+14))
  while [ $SECONDS -lt $end ]; do
    case $api in
      restart) sudo -n ip link set $AVFnet down 2>/dev/null; sudo -n ip link set $AVFnet up 2>/dev/null;;
      promisc) sudo -n ip link set $AVFnet promisc on 2>/dev/null; sudo -n ip link set $AVFnet promisc off 2>/dev/null;;
      mcast)   sudo -n ip maddr add 01:00:5e:00:00:fb dev $AVFnet 2>/dev/null; sudo -n ip maddr del 01:00:5e:00:00:fb dev $AVFnet 2>/dev/null;;
      flow)    sudo -n tc filter add dev $E2 ingress protocol ip flower dst_ip 10.1.2.3 action drop 2>/dev/null; sudo -n tc filter del dev $E2 ingress 2>/dev/null;;
    esac
    sleep "$gap"
  done; }

# RTT proxy from plain dperf: fixed cc=100 request/response -> tcpRsp (completed responses) is
# inversely proportional to RTT (rsp/s ~= cc/RTT); synRt/pushRt (retransmits) rise under stall.
metric(){ sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | awk '
  /tcpRsp/{for(i=1;i<=NF;i++)if($i=="tcpRsp")r=$(i+1)}
  /synRt/{for(i=1;i<=NF;i++)if($i=="synRt")s=$(i+1)}
  /pushRt/{for(i=1;i<=NF;i++)if($i=="pushRt")p=$(i+1)}
  /tcpRx/{for(i=1;i<=NF;i++)if($i=="tcpRx")rx=$(i+1)}
  END{gsub(/,/,"",r); gsub(/,/,"",rx); printf "tcpRsp=%s tcpRx=%s synRt=%s pushRt=%s", r, rx, s, p}'; }

runprobe(){ local tag=$1; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/server.conf" > "$OUT/srv_$tag.log" 2>&1 & sleep 6
  sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/client.conf" > "$OUT/cli_$tag.log" 2>&1
  sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1; }

phase(){ local tag=$1 api=$2 rate=$3
  if [ "$api" = none ]; then runprobe "$tag"; else ( atkchurn "$api" "$rate" ) & local ap=$!; sleep 1; runprobe "$tag"; kill $ap 2>/dev/null; sudo -n pkill -9 -f 'atkchurn' 2>/dev/null; fi
  say "  [$tag ${api}@${rate}/s] probe: $(metric "$OUT/cli_$tag.log")"; }

say "===== MOTIVATION: victim probe RTT under attacker control-API churn (mlx5) ====="
phase baseline none 0
phase restart10 restart 10
phase promisc10 promisc 10
phase mcast2    mcast   2
phase flow10    flow    10
say "DONE OUT=$OUT"

#!/bin/bash
# Calibrate dperf offered-load knob on intra none 1c 1400B. (no set -u)
PF_INTRA=0000:3b:00.1; IF_INTRA=enp59s0f1np1
DNS=/home/sungwoo/FINAL/traffic/dperf_dns
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
ROOT=/home/sungwoo/calib_$(date +%H%M%S); mkdir -p "$ROOT"; RES="$ROOT/RES.txt"; : > "$RES"
KILL1(){ sudo pkill -9 -x dperf 2>/dev/null; sleep 1; }
intra_up(){ KILL1
  echo 0 | sudo tee /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs >/dev/null 2>&1; sleep 2
  sudo devlink dev eswitch set pci/$PF_INTRA mode switchdev 2>/dev/null; sleep 1
  sudo ethtool -K $IF_INTRA hw-tc-offload on 2>/dev/null
  echo 2 | sudo tee /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs >/dev/null 2>&1
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF_INTRA/virtfn1 ] && break; sleep 1; done; sleep 3
  sudo ip link set $IF_INTRA up 2>/dev/null
  SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn0))
  CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF_INTRA/virtfn1))
  rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
  SREP=$(rep 0); CREP=$(rep 1)
  sudo ip link set $IF_INTRA vf 0 mac 02:50:00:00:01:01 2>/dev/null; sudo ip link set $IF_INTRA vf 1 mac 02:50:00:00:01:02 2>/dev/null
  sudo ip link set $IF_INTRA vf 0 spoofchk off 2>/dev/null; sudo ip link set $IF_INTRA vf 0 trust on 2>/dev/null
  sudo ip link set $IF_INTRA vf 1 spoofchk off 2>/dev/null; sudo ip link set $IF_INTRA vf 1 trust on 2>/dev/null
  sudo ip link set $SREP up 2>/dev/null; sudo ip link set $CREP up 2>/dev/null
  sudo tc qdisc add dev $SREP ingress 2>/dev/null; sudo tc qdisc add dev $CREP ingress 2>/dev/null
  sudo tc filter add dev $SREP ingress protocol all flower skip_sw action mirred egress redirect dev $CREP 2>/dev/null
  sudo tc filter add dev $CREP ingress protocol all flower skip_sw action mirred egress redirect dev $SREP 2>/dev/null
  echo "intra VFs S=$SVF C=$CVF" | tee -a "$RES"; }
intra_down(){ KILL1; echo 0 | sudo tee /sys/bus/pci/devices/$PF_INTRA/sriov_numvfs >/dev/null 2>&1; sudo devlink dev eswitch set pci/$PF_INTRA mode legacy 2>/dev/null; }
SIP=192.168.91.1; CIP=192.168.91.2; SMAC=02:50:00:00:01:01; CMAC=02:50:00:00:01:02
cell(){ KA=$1; CC=$2; d="$ROOT/ka${KA}_cc${CC}"; mkdir -p "$d"; KILL1
  cat > "$d/server.conf" <<C
mode server
tx_burst 128
cpu 6
duration 18s
payload_size 1400
protocol udp
keepalive ${KA}us
socket_mem 2048
port $SVF $SIP $CIP $CMAC
client $CIP 1
server $SIP 1
listen 9 1
C
  cat > "$d/client.conf" <<C
mode client
tx_burst 128
cpu 16
duration 14s
payload_size 1400
protocol udp
cps 4000
cc $CC
keepalive ${KA}us
socket_mem 0,2048
port $CVF $CIP $SIP $SMAC
client $CIP 1
server $SIP 1
listen 9 1
C
  sudo env LD_LIBRARY_PATH=$LIB timeout 28 "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 2
  sudo env LD_LIBRARY_PATH=$LIB timeout 20 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 13
  KILL1
  off=$(grep -aoE "pktTx +[0-9,]+" "$d/client.log"|grep -oE "[0-9,]+$"|tr -d ,|sort -n|tail -1)
  rx=$(grep -aE "^pktRx" "$d/server.log"|awk "{print \$2}"|tr -d ,|sort -n|tail -1)
  echo "ka=${KA}us cc=${CC} offered(cliTx)=${off:-NA} delivered(srvRx)=${rx:-NA}" | tee -a "$RES"
}
echo "=== CALIB start $(date) ===" | tee -a "$RES"
intra_up
cell 20 10000
cell 1250 10000
cell 2500 10000
cell 5000 10000
cell 10000 10000
intra_down
echo "=== DONE ===" | tee -a "$RES"

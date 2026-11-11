#!/usr/bin/env bash
# Host2 XL710 PF DPDK SERVER (for inter eSAC->none TX: host1 eSAC client -> host2 none server).
# Uses the same narrow NOPASSWD grants as the client harness. Binds d9:00.0 to vfio, runs dperf mode server.
set -Eeuo pipefail
dev=0000:d9:00.0
iface=enp217s0f0np0
out=${OUT:-/tmp/h2srv_$(date +%Y%m%d_%H%M%S)}
dur=${DUR:-45}
cpu=${CPU:-6}; cpu=${cpu//,/ }
bound=0; was_up=0; app_pid=
CLIENT_MAC=${CLIENT_MAC:-02:40:00:00:00:11}
BIN=${SERVER_BIN:-/home/sungwoo/FINAL/traffic/dperf}
mkdir -p "$out"
if pgrep -x dperf >/dev/null; then echo 'DPDK active on host2' >&2; exit 1; fi
if [[ $(basename "$(readlink -f "/sys/bus/pci/devices/$dev/driver")") != i40e ]]; then echo 'unexpected host2 driver' >&2; exit 1; fi
if [[ $(cat "/sys/bus/pci/devices/$dev/sriov_numvfs") != 0 ]]; then echo 'active VFs on host2 PF' >&2; exit 1; fi
if ip -o link show dev "$iface" | grep -q '<[^>]*UP[^>]*>'; then was_up=1; fi
restore(){ local rc=$?; trap - EXIT INT TERM
  [[ $app_pid =~ ^[0-9]+$ ]] && { kill -TERM "$app_pid" 2>/dev/null||true; wait "$app_pid" 2>/dev/null||true; }
  if (( bound )); then sudo -n dpdk-devbind.py -b i40e "$dev" || echo DRIVER_RESTORE_FAILED >&2; (( was_up )) && sudo -n ip link set "$iface" up||true; fi
  echo "RESTORE_DRIVER=$(basename "$(readlink -f "/sys/bus/pci/devices/$dev/driver")" 2>/dev/null||echo MISSING)"
  exit "$rc"; }
trap restore EXIT INT TERM
PLINE="payload_size ${PAYLOAD:-64}"; [ -n "${PAYLOAD_FILE:-}" ] && PLINE="payload_file $PAYLOAD_FILE"
cat > "$out/server.conf" <<CONF
mode server
tx_burst ${TX_BURST:-32}
cpu $cpu
duration ${dur}s
$PLINE
protocol ${PROTO:-udp}
keepalive ${KEEPALIVE:-20us}
socket_mem ${SOCKET_MEM:-1024}
port $dev 192.168.1.1 192.168.0.1 $CLIENT_MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
CONF
[[ "$cpu" == *" "* ]] && echo rss >> "$out/server.conf"
echo "H2SRV_OUT=$out"
sudo -n ip link set "$iface" down
bound=1
sudo -n dpdk-devbind.py --force -b vfio-pci "$dev"
group=$(basename "$(readlink -f "/sys/bus/pci/devices/$dev/iommu_group")")
sudo -n chmod a+rw "/dev/vfio/$group"
env -u LD_PRELOAD LD_LIBRARY_PATH=/home/sungwoo:/usr/local/lib/x86_64-linux-gnu \
  "$BIN" -c "$out/server.conf" > "$out/server.log" 2>&1 &
app_pid=$!
for ((e=0;e<dur+20;e++)); do kill -0 "$app_pid" 2>/dev/null||break; sleep 1; done
kill -0 "$app_pid" 2>/dev/null && kill -TERM "$app_pid" 2>/dev/null
wait "$app_pid" 2>/dev/null; app_pid=
pps=$(grep -aE "^pktRx" "$out/server.log"|awk '{print $2}'|tr -d ,|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}')
bits=$(grep -aE "^pktRx" "$out/server.log"|awk '{print $6}'|tr -d ,|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}')
echo "H2SRV_PKTRX=${pps:-0} H2SRV_BITS=${bits:-0}" | tee "$out/result"

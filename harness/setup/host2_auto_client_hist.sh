#!/usr/bin/env bash
# Host2 Intel XL710 PF DPDK client. Host-side binding uses existing narrow NOPASSWD grants.
set -Eeuo pipefail

dev=0000:d9:00.0
iface=enp217s0f0np0
out=${OUT:-/tmp/esac40g_auto_client_$(date +%Y%m%d_%H%M%S)}
dur=${DUR:-20}
cpu=${CPU:-16}
cpu=${cpu//,/ }
bound=0
was_up=0
app_pid=

if [[ $EUID == 0 ]]; then echo 'Run as sungwoo, not root' >&2; exit 1; fi
if pgrep -x dperf >/dev/null || pgrep -x dperf_hist_bin >/dev/null || pgrep -x dpdk-testpmd >/dev/null; then
    echo 'Another DPDK experiment is active on host2' >&2; exit 1
fi
if [[ $(basename "$(readlink -f "/sys/bus/pci/devices/$dev/driver")") != i40e ]]; then
    echo 'Unexpected host2 PF driver' >&2; exit 1
fi
if [[ $(cat "/sys/bus/pci/devices/$dev/sriov_numvfs") != 0 ]]; then
    echo 'Active VFs found on host2 PF' >&2; exit 1
fi
if ip -o addr show dev "$iface" | grep -Eq ' inet6? '; then
    echo 'IP assigned to experiment port' >&2; exit 1
fi
if ip -o link show dev "$iface" | grep -q '<[^>]*UP[^>]*>'; then was_up=1; fi

restore() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ $app_pid =~ ^[0-9]+$ ]]; then
        kill -TERM "$app_pid" 2>/dev/null || true
        wait "$app_pid" 2>/dev/null || true
    fi
    if (( bound )); then
        sudo -n dpdk-devbind.py -b i40e "$dev" || echo 'DRIVER_RESTORE_FAILED' >&2
        if (( was_up )); then sudo -n ip link set "$iface" up || true; fi
    fi
    echo "RESTORE_DRIVER=$(basename "$(readlink -f "/sys/bus/pci/devices/$dev/driver")" 2>/dev/null || echo MISSING)"
    echo "VFS_REMAINING=$(cat "/sys/bus/pci/devices/$dev/sriov_numvfs")"
    echo "CLIENT_LOG_DIR=$out"
    exit "$rc"
}
trap restore EXIT INT TERM

mkdir -p "$out"
PLINE="payload_size ${PAYLOAD:-64}"
[ -n "${PAYLOAD_FILE:-}" ] && PLINE="payload_file $PAYLOAD_FILE"
cat > "$out/client.conf" <<CONF
mode client
tx_burst ${TX_BURST:-32}
cpu $cpu
duration ${dur}s
$PLINE
protocol ${PROTO:-tcp}
cps ${CPS:-10}
cc ${CC:-100}
keepalive ${KEEPALIVE:-1ms}
socket_mem ${SOCKET_MEM:-0,512}
port $dev 192.168.0.1 192.168.1.1 ${SERVER_MAC:-94:6d:ae:cf:d2:1e}
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
CONF
[[ "$cpu" == *" "* ]] && echo rss >> "$out/client.conf"

echo "CLIENT_LOG_DIR=$out"
echo "RUN_UID=$(id -u)"
sudo -n ip link set "$iface" down
bound=1
sudo -n dpdk-devbind.py --force -b vfio-pci "$dev"
group=$(basename "$(readlink -f "/sys/bus/pci/devices/$dev/iommu_group")")
sudo -n chmod a+rw "/dev/vfio/$group"
echo "BOUND_DRIVER=$(basename "$(readlink -f "/sys/bus/pci/devices/$dev/driver")")"

set +e
env -u LD_PRELOAD LD_LIBRARY_PATH=/home/sungwoo:/usr/local/lib/x86_64-linux-gnu \
  ESAC_HIST_FILE="$out/hist.txt" ESAC_HIST_START_SEC="${HIST_START:-3}" \
  "${CLIENT_BIN:-/home/sungwoo/dperf_hist_checkpoint_bin}" -c "$out/client.conf" > "$out/client.log" 2>&1 &
app_pid=$!
for ((elapsed=0; elapsed<dur+15; elapsed++)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then break; fi
    sleep 1
done
if kill -0 "$app_pid" 2>/dev/null; then kill -TERM "$app_pid" 2>/dev/null; fi
wait "$app_pid"
rc=$?
app_pid=
set -e

echo "CLIENT_RC=$rc"
grep -E 'tcpRx|tcpTx|pktRx|pktTx|port init fail|dpdk init fail|EAL: Error' "$out/client.log" | tail -14 || true
echo "HIST_FILE=$out/hist.txt"

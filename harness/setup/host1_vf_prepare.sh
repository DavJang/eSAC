#!/usr/bin/env bash
set -Eeuo pipefail
pf=0000:3b:00.0
iface=enp59s0f0np0
marker=/tmp/esac40g_host1_vf_failsafe.marker
ttl=${VF_TTL:-300}
if ! [[ $ttl =~ ^[0-9]+$ ]] || (( ttl < 60 || ttl > 14400 )); then
    echo 'VF_TTL must be 60..14400 seconds' >&2; exit 1
fi

if [[ $EUID != 0 ]]; then echo 'Run as root' >&2; exit 1; fi
if [[ $(basename "$(readlink -f /sys/bus/pci/devices/$pf/driver)") != mlx5_core ]]; then
    echo 'Unexpected PF driver' >&2; exit 1
fi
if [[ $(cat "/sys/bus/pci/devices/$pf/sriov_numvfs") != 0 ]]; then
    echo 'PF already has VFs; refusing' >&2; exit 1
fi
if pgrep -x dperf >/dev/null || pgrep -x dpdk-testpmd >/dev/null; then
    echo 'DPDK process active; refusing' >&2; exit 1
fi

# Recovery survives an SSH disconnect. The marker is removed after normal teardown.
token="$(date +%s%N)-$$"
printf '%s\n' "$token" > "$marker"
nohup bash -c 'sleep "$1"; if [[ $(cat /tmp/esac40g_host1_vf_failsafe.marker 2>/dev/null || true) == "$2" ]]; then echo 0 > /sys/bus/pci/devices/0000:3b:00.0/sriov_numvfs; rm -f /tmp/esac40g_host1_vf_failsafe.marker; fi' _ "$ttl" "$token" \
    >/tmp/esac40g_host1_vf_failsafe.log 2>&1 </dev/null &
echo "FAILSAFE_PID=$!"

echo 1 > "/sys/bus/pci/devices/$pf/sriov_numvfs"
vf=$(basename "$(readlink -f "/sys/bus/pci/devices/$pf/virtfn0")")
ip link set dev "$iface" vf 0 mac 02:40:00:00:00:11
ip link set dev "$iface" vf 0 spoofchk off
ip link set dev "$iface" vf 0 trust on
echo "VF_BDF=$vf"
echo "VF_DRIVER=$(basename "$(readlink -f /sys/bus/pci/devices/$vf/driver)" 2>/dev/null || echo NONE)"
echo "PF_DRIVER=$(basename "$(readlink -f /sys/bus/pci/devices/$pf/driver)")"
echo "PF_LINK=$(cat /sys/class/net/$iface/operstate)"
echo "VFS=$(cat /sys/bus/pci/devices/$pf/sriov_numvfs)"

#!/usr/bin/env bash
# One isolated 40G eSAC case; uses no interactive sudo on either host.
set -Eeuo pipefail

mode=${MODE:-bpftime}
dur=${DUR:-25}
client_dur=${CLIENT_DUR:-12}
out=${OUT:-/home/sungwoo/FINAL/results/esac40g_auto_${mode}_$(date +%Y%m%d_%H%M%S)}
server=/home/sungwoo/FINAL/harness/l7/server_harness_hs.sh
client=/home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh
h2=(ssh -i /home/sungwoo/FINAL/secrets/host2_key -o IdentitiesOnly=yes -o BatchMode=yes -p 9022 sungwoo@143.248.57.12)
runner=

exec 9>/tmp/esac40g_autocase.lock
flock -n 9 || { echo 'Another 40G auto case is active'; exit 1; }
if pgrep -x dperf >/dev/null || pgrep -x dpdk-testpmd >/dev/null; then
    echo 'DPDK process active on host1'; exit 1
fi
if "${h2[@]}" 'pgrep -x dperf >/dev/null || pgrep -x dperf_hist_bin >/dev/null || pgrep -x dpdk-testpmd >/dev/null'; then
    echo 'DPDK process active on host2'; exit 1
fi

mkdir -p "$out"
echo "CASE_DIR=$out"
printf 'mode=%s\naction=%s\nserver_app=%s\nbpf_obj=%s\nport=%s\nserver_mac=%s\nserver_cpus=%s\nclient_cpus=%s\npayload=%s\nkeepalive=%s\ncc=%s\ncps=%s\n' \
    "$mode" "${ACTION:-ALLOW}" "${APP:-/home/sungwoo/FINAL/traffic/dperf_probe}" \
    "${COMBO:-/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_strict.bpf.o}" "${PORT:-0000:3b:00.0}" \
    "${SERVER_MAC:-94:6d:ae:cf:d2:1e}" "${SCPU:-6}" "${CLIENT_CPU:-16}" \
    "${PAYLOAD:-64}" "${KEEPALIVE:-1ms}" "${CC:-100}" "${CPS:-10}" > "$out/config.txt"
sudo -n env MODE="$mode" OUT="$out" DUR="$dur" SCPU="${SCPU:-6}" POLCPU="${POLCPU:-10}" PROCPU="${PROCPU:-11}" \
    SOCKET_MEM="${SOCKET_MEM:-256}" PAYLOAD="${PAYLOAD:-64}" KEEPALIVE="${KEEPALIVE:-1ms}" \
    ACTION="${ACTION:-ALLOW}" PORT="${PORT:-0000:3b:00.0}" APP="${APP:-/home/sungwoo/FINAL/traffic/dperf_probe}" \
    COMBO="${COMBO:-/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_strict.bpf.o}" MAX_BURST_INSPECT="${MAX_BURST_INSPECT:-128}" BURST_LOADER="${BURST_LOADER:-/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup_burst}" \
    eSAC_HS_PATTERNS="${eSAC_HS_PATTERNS:-}" eSAC_AGENT_PATH="${eSAC_AGENT_PATH:-}" eSAC_HS_LIB="${eSAC_HS_LIB:-}" \
    PROTO="${PROTO:-}" \
    timeout --signal=TERM 140s bash "$server" > "$out/launch.log" 2>&1 &
runner=$!

ready=0
for _ in $(seq 1 50); do
    if [[ -f "$out/.ready" ]]; then ready=1; break; fi
    if grep -q FAIL "$out/run.log" 2>/dev/null; then break; fi
    sleep 1
done

if (( ready )); then
    echo 'SERVER_READY=YES'
    client_cpu=${CLIENT_CPU:-16}
    client_cpu=${client_cpu// /,}
    set +e
    "${h2[@]}" env DUR="$client_dur" PAYLOAD="${PAYLOAD:-64}" PROTO="${PROTO:-}" PAYLOAD_FILE="${PAYLOAD_FILE:-}" CLIENT_BIN="${CLIENT_BIN:-}" KEEPALIVE="${KEEPALIVE:-1ms}" SERVER_MAC="${SERVER_MAC:-94:6d:ae:cf:d2:1e}" \
        CC="${CC:-100}" CPS="${CPS:-10}" CPU="$client_cpu" \
        bash "$client" > "$out/host2_client.out" 2>&1
    client_rc=$?
    set -e
    echo "CLIENT_SSH_RC=$client_rc"
    client_dir=$(sed -n 's/^CLIENT_LOG_DIR=//p' "$out/host2_client.out" | head -1)
    if [[ $client_dir == /tmp/esac40g_auto_client_* ]]; then
        scp -q -i /home/sungwoo/FINAL/secrets/host2_key -P 9022 \
            "sungwoo@143.248.57.12:$client_dir/client.log" "$out/client.log" || true
        scp -q -i /home/sungwoo/FINAL/secrets/host2_key -P 9022 \
            "sungwoo@143.248.57.12:$client_dir/hist.txt" "$out/hist.txt" || true
        scp -q -i /home/sungwoo/FINAL/secrets/host2_key -P 9022 \
            "sungwoo@143.248.57.12:$client_dir/client.conf" "$out/client.conf" || true
    fi
else
    echo 'SERVER_READY=NO'
fi

wait "$runner" || true
runner=
cat "$out/run.log" 2>/dev/null || true
cat "$out/host2_client.out" 2>/dev/null | tail -18 || true

server_pid=$(sed -n 's/^server_pid=\([0-9]*\).*/\1/p' "$out/run.log" 2>/dev/null | tail -1)
if [[ $server_pid =~ ^[0-9]+$ ]] && ! kill -0 "$server_pid" 2>/dev/null; then
    sudo -n find /dev/hugepages -maxdepth 1 -type f -name "dperf-${server_pid}map_*" -delete
fi
echo "HOST1_HUGEPAGES_FREE=$(awk '/HugePages_Free:/ {print $2}' /proc/meminfo)"
echo "HOST1_DRIVER=$(basename "$(readlink -f /sys/bus/pci/devices/0000:3b:00.0/driver)")"
echo "CASE_DIR=$out"

if (( ! ready )) || [[ ${client_rc:-1} != 0 ]]; then exit 1; fi

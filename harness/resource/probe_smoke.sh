#!/bin/bash
# smoke test: does eSACfinal/dperf_hist run on an mlx5 HW-hairpin VF pair and emit p99 RTT?
set +u
PF=0000:3b:00.1; IF=enp59s0f1np1; DH=/home/sungwoo/eSACfinal/traffic/dperf_hist
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk:/home/sungwoo/FINAL/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=/home/sungwoo/FINAL/results/probe_smoke_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf_hist 2>/dev/null; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
  sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  sudo -n find /dev/hugepages -maxdepth 1 -name 'dperf-*' -delete 2>/dev/null; say "RESTORED"; echo EXP_DONE>>"$R"; }
trap restore EXIT
echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0)); CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1))
E0=$(rep 0) E1=$(rep 1)
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
for i in 0 1; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
say "probe pair server=$SVF client=$CVF"
cat > "$OUT/s.conf" <<C
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
cat > "$OUT/c.conf" <<C
mode client
tx_burst 32
cpu 16
duration 15s
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
say "ldd check:"; ldd "$DH" 2>&1 | grep -i "not found" | tee -a "$R" || true
sudo -n pkill -9 -x dperf_hist 2>/dev/null; sleep 1
sudo -n env LD_LIBRARY_PATH=$LIB "$DH" -c "$OUT/s.conf" > "$OUT/srv.log" 2>&1 & sleep 6
sudo -n env LD_LIBRARY_PATH=$LIB GOWN_HIST_FILE=$OUT/probe_hist.txt GOWN_HIST_START_SEC=3 "$DH" -c "$OUT/c.conf" > "$OUT/cli.log" 2>&1
sudo -n pkill -9 -x dperf_hist 2>/dev/null; sleep 1
say "=== probe client tail ==="; grep -aiE "gown_hist|p99|Segmentation|error|init" "$OUT/cli.log" | tail -8 | tee -a "$R"
say "=== hist summary line ==="; grep -a "gown_hist" "$OUT/probe_hist.txt" 2>/dev/null | tee -a "$R"
say "hist lines=$(wc -l < "$OUT/probe_hist.txt" 2>/dev/null)"
say "DONE OUT=$OUT"

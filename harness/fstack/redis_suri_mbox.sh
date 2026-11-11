#!/bin/bash
# Suricata IPS middlebox in front of f-stack redis: redis-benchmark(kernel, CVF) ->
# [switchdev hairpin] -> Suricata DPDK copy-ips (AVF 3b:01.4 <-> BVF 3b:01.5) -> [hairpin]
# -> f-stack redis (DPDK, SVF 3b:01.6). Measures redis-benchmark ops/sec THROUGH Suricata.
# (Same 4-VF chain as the dperf Suricata experiment; endpoints swapped to redis.) Detached; trap-restore.
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1
REDIS=$D/apps/redis/redis-server; FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf; INI=$D/apps/redis/ff_redis_suri.ini
SURI=$D/suricata/bin/suricata; SYAML=$D/suricata/conf/suri_ips.yaml
SURILD=$D/suricata/lib:/usr/local/lib/x86_64-linux-gnu
SIP=192.168.1.1; CIP=192.168.1.2
SVF=0000:3b:01.6   # vf3 = f-stack redis server
RB="/usr/bin/redis-benchmark -h $SIP -p 6379 -t set,get -n 100000 -c 50 -P 16 -d 32 --csv"
OUT=$D/results/redis_suri_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }

restore(){ sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x redis-server 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
  sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  say "RESTORED PF numvfs=0 legacy"; echo EXP_DONE >> "$R"; }
trap restore EXIT

# ---- 4-VF switchdev chain (from suricata_phase) ----
sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x redis-server 2>/dev/null
echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1
sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0))   # 3b:01.3 kernel client
SVFd=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn3))  # 3b:01.6 redis server
CVF_NET=; for n in /sys/class/net/*; do [ "$(basename $(readlink -f $n/device 2>/dev/null))" = "$CVF" ] && CVF_NET=$(basename $n); done
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2) E3=$(rep 3)
sudo -n ip link set $IF vf 0 mac 02:60:00:00:00:01 2>/dev/null
sudo -n ip link set $IF vf 3 mac 02:60:00:00:00:04 2>/dev/null
for i in 0 1 2 3; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2 $E3; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
for e in $E0 $E1 $E2 $E3; do sudo -n tc filter del dev $e ingress 2>/dev/null; done
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0
sudo -n tc filter add dev $E2 ingress protocol all flower skip_sw action mirred egress redirect dev $E3
sudo -n tc filter add dev $E3 ingress protocol all flower skip_sw action mirred egress redirect dev $E2
# client kernel IP on CVF netdev
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null
say "chain: CVF=$CVF($CVF_NET) AVF=3b:01.4 BVF=3b:01.5 SVF=$SVFd reps=$E0/$E1/$E2/$E3"

# ---- f-stack redis on SVF (vf3) ----
sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" "$D/apps/redis/ff_redis.ini" > "$INI"
cd "$D/apps/redis"
sudo -n setsid env -u LD_PRELOAD LD_LIBRARY_PATH="$FFLIB" "$REDIS" "$CONF" --conf "$INI" --proc-type=primary --proc-id=0 > "$OUT/redis.log" 2>&1 </dev/null & disown
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && say "f-stack redis READY on $SVF" || { say "redis NOT ready"; grep -vE "^EAL|Detected|IOVA|Selected|No free|TELEMETRY|sysctl|hpts|rediraccept|forwarding|dad" "$OUT/redis.log"|tail -8|tee -a "$R"; }

# ---- baseline: redis-bench DIRECT (no suricata yet, chain still has hairpins but AVF/BVF unbound -> drop) ----
# NOTE: with AVF/BVF unbound the middle is broken, so we only measure WITH suricata forwarding.

# ---- Suricata DPDK IPS on AVF(3b:01.4) <-> BVF(3b:01.5) ----
st=NO
sudo -n env LD_LIBRARY_PATH=$SURILD setsid "$SURI" -c "$SYAML" --dpdk -l "$OUT" > "$OUT/suri.log" 2>&1 < /dev/null & disown
for j in $(seq 1 50); do grep -qiE "engine started|Threads created|All AFP capture threads|rule files processed" "$OUT/suri.log" 2>/dev/null && { st=YES; break; }; sleep 1; done
say "suricata start=$st : $(grep -aiE 'engine started|error|no supported|mlx5|unable' "$OUT/suri.log"|tail -2|tr '\n' ';')"
[ "$st" != YES ] && { say "SURICATA_FAIL"; grep -aiE 'error|warn|mlx5|dpdk' "$OUT/suri.log"|tail -6|tee -a "$R"; }
sleep 3

# ---- ping check through chain, then redis-benchmark ----
say "ping .1 via chain: $(ping -c2 -W2 -I $CVF_NET $SIP 2>&1 | grep -oE '[0-9]+ received' | head -1)"
say "redis-cli PING: $(timeout 8 /usr/bin/redis-cli -h $SIP -p 6379 ping 2>&1)"
say "===== redis-benchmark THROUGH Suricata ====="
$RB > "$OUT/bench.csv" 2>"$OUT/bench.err"
grep -E '^"(SET|GET)"' "$OUT/bench.csv" | tee -a "$R"
say "===== DIAG: where does traffic flow? ====="
for e in $E0 $E1 $E2 $E3; do
  pk=$(sudo -n tc -s filter show dev $e ingress 2>/dev/null | grep -oE 'Sent [0-9]+ bytes [0-9]+ pkt' | head -1)
  hw=$(sudo -n tc filter show dev $e ingress 2>/dev/null | grep -oE 'in_hw|not_in_hw' | head -1)
  say "  rep $e ingress: ${pk:-nostats}  [$hw]"
done
say "  suricata capture.packets total: $(sudo -n grep -a 'capture.packets' /home/sungwoo/FINAL/results/redis_suri_*/stats.log 2>/dev/null | grep Total | tail -1 | grep -oE '[0-9]+$')"
say "  fdb/direct path check — CVF($CVF) mac $(cat /sys/class/net/$CVF_NET/address 2>/dev/null), SVF mac via redis"
sleep 2
say "DONE OUT=$OUT"

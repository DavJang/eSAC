#!/bin/bash
# DROP test with the BURST_OPT3 loader (the one nginx used) on f-stack Redis 40G switchdev.
set -u
R=/home/sungwoo/eSACfinal
AGENT=/home/sungwoo/eSACfinal/agent/libbpftime-agent.so
SERVER=/home/sungwoo/eSACfinal/agent/libbpftime-syscall-server.so
LOADER=/home/sungwoo/eSACfinal/comm_plane/loaders/comm_loader_cgroup_maskprobe
COMBO=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
REDIS=/home/sungwoo/eSACfinal/apps/redis/redis-server
FFLIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
INI=/home/sungwoo/eSACfinal/apps/redis/ff_redis_sw.ini
PF1=0000:3b:00.1; IF1=enp59s0f1np1; SVF=0000:3b:01.3; CVF_NET=enp59s0f1v1; CIP=192.168.1.2
OUT=/home/sungwoo/eSACfinal/results/esac_burst_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
[ -x "$LOADER" ] || { echo "LOADER missing: $LOADER"; ls -la /home/sungwoo/eSACfinal/comm_plane/loaders/ 2>/dev/null | grep -i comm_loader; exit 1; }

sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" /home/sungwoo/eSACfinal/apps/redis/ff_redis.ini > "$INI"
sudo -n ip link set $IF1 up 2>/dev/null
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null; sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=; crep=; for n in /sys/class/net/*; do p=$(cat $n/phys_port_name 2>/dev/null); [ "$p" = pf1vf0 ] && srep=$(basename $n); [ "$p" = pf1vf1 ] && crep=$(basename $n); done
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

run_case(){ local name=$1 action=$2
  clean; cd /home/sungwoo/eSACfinal/apps/redis
  export BPFTIME_GLOBAL_SHM_NAME=esac_ffredis_$(date +%s%N)
  sudo -n setsid env BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$FFLIB" "$REDIS" /home/sungwoo/eSACfinal/apps/redis/ff_redis.conf --conf "$INI" --proc-type=primary --proc-id=0 > "$OUT/redis_$name.log" 2>&1 </dev/null & disown
  local srv j; for j in $(seq 1 30); do srv=$(pgrep -f "redis-server.*ff_redis_sw"|head -1); [ -n "$srv" ] && grep -q 'Ready to accept' "$OUT/redis_$name.log" 2>/dev/null && break; sleep 1; done
  local CG=/sys/fs/cgroup/esac_ffredis_${srv}; sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$srv"|sudo -n tee "$CG/cgroup.procs">/dev/null
  local CGID=$(stat -c %i "$CG")
  printf '{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"%s"}]}\n' "$CGID" "$action" > "$OUT/pol_$name.json"
  sudo -n env BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$SERVER" "$LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "/home/sungwoo/eSACfinal/comm_plane/offsets.json" --policy "$OUT/pol_$name.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader_$name.log" 2>&1 &
  for j in $(seq 1 45); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader_$name.log" 2>/dev/null && break; sleep 1; done
  say "[$name] action=$action redis=$srv cgid=$CGID (loader=burst_mask_probe)"
  local bench; bench=$(timeout 12 /usr/bin/redis-benchmark -h 192.168.1.1 -p 6379 -t set -n 2000 -c 5 -q 2>&1 | head -1)
  say "[$name] benchmark SET => '${bench:-<none>}'"
  local r; r=$(timeout 6 /usr/bin/redis-cli -h 192.168.1.1 -p 6379 ping 2>&1)
  say "[$name] redis-cli ping => '${r:-<empty/timeout>}'"
  local lp; lp=$(pgrep -f "[c]omm_loader_cgroup_burst"|head -1); sudo -n kill -USR1 "$lp" 2>/dev/null; sleep 2
  say "[$name] STATS:"; tail -4 "$OUT/loader_$name.log" | grep -E "^[0-9]|policy_hits" | tail -2
  sudo -n kill -9 "$srv" 2>/dev/null; clean; }

say "===== burst_mask_probe | ALLOW 6379 (expect PONG) ====="; run_case allow ALLOW
say "===== burst_mask_probe | DROP 6379 (expect blocked) ====="; run_case drop DROP
say "DONE OUT=$OUT"

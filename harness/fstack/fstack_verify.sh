#!/bin/bash
# eSAC enforcement verification on REAL app (f-stack Redis, 40G mlx5 switchdev):
#  (A) L4 DROP: ALLOW-6379 policy -> redis PONG; deny-6379 policy -> connection DROPPED.
#  (B) Tamper KILL: arm event sentinel on redis PID, inject openat(/proc/self/mem) -> SIGKILL.
set -u
R=/home/sungwoo/eSACfinal
AGENT=/home/sungwoo/eSACfinal/agent/libbpftime-agent.so
SERVER=/home/sungwoo/eSACfinal/agent/libbpftime-syscall-server.so
COMBO=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
REDIS=/home/sungwoo/eSACfinal/apps/redis/redis-server
FFLIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
INI=/home/sungwoo/eSACfinal/apps/redis/ff_redis_sw.ini
SENTINEL=/home/sungwoo/eSACfinal/tamper_sentinel/tamper_sentinel_event.sh
PF1=0000:3b:00.1; IF1=enp59s0f1np1; SVF=0000:3b:01.3; CVF_NET=enp59s0f1v1; CIP=192.168.1.2
SIP=192.168.1.1
OUT=/home/sungwoo/eSACfinal/results/esac_verify40_$(date +%s); mkdir -p "$OUT"
LOG=$OUT/log; say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ---- switchdev + hairpin + client IP (idempotent) ----
sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" /home/sungwoo/eSACfinal/apps/redis/ff_redis.ini > "$INI"
sudo -n ip link set $IF1 up 2>/dev/null
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null
sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=; crep=
for n in /sys/class/net/*; do p=$(cat $n/phys_port_name 2>/dev/null); [ "$p" = pf1vf0 ] && srep=$(basename $n); [ "$p" = pf1vf1 ] && crep=$(basename $n); done
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null
say "switchdev ready"

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null; sudo -n pkill -9 -f '[b]pftrace' 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

# boot_gown <policy_json_file> -> echoes redis pid (attached+enforcing)
boot_gown(){ local POL=$1; cd /home/sungwoo/eSACfinal/apps/redis
  export BPFTIME_GLOBAL_SHM_NAME=esac_ffredis_$(date +%s%N)
  sudo -n setsid env BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$FFLIB" "$REDIS" /home/sungwoo/eSACfinal/apps/redis/ff_redis.conf --conf "$INI" --proc-type=primary --proc-id=0 > "$OUT/redis.log" 2>&1 </dev/null & disown
  local srv j; for j in $(seq 1 30); do srv=$(pgrep -f "redis-server.*ff_redis_sw"|head -1); [ -n "$srv" ] && grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
  [ -z "$srv" ] && { echo ""; return; }
  local CG=/sys/fs/cgroup/esac_ffredis_${srv}; sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$srv"|sudo -n tee "$CG/cgroup.procs" >/dev/null
  local CGID=$(stat -c %i "$CG"); sed "s/__CGID__/$CGID/g" "$POL" > "$OUT/policy_active.json"
  sudo -n env BPFTIME_LOG_OUTPUT=console BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$SERVER" "/home/sungwoo/eSACfinal/comm_plane/loaders/comm_loader_cgroup" --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "/home/sungwoo/eSACfinal/comm_plane/offsets.json" --policy "$OUT/policy_active.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 &
  for j in $(seq 1 45); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
  grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null || say "  (warn: attach summary not seen)"
  echo $srv; }

ping_redis(){ timeout 6 /usr/bin/redis-cli -h $SIP -p 6379 ping 2>&1; }

# policy templates (cgroup id substituted)
printf '{"rules":[{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":6379,"action":"ALLOW"}]}\n' > "$OUT/pol_allow6379.json"
printf '{"rules":[{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.1","proto":6,"dst_port":7000,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":7000,"action":"ALLOW"}]}\n' > "$OUT/pol_deny6379.json"

say "===================== (A) L4 DROP TEST ====================="
clean; pid=$(boot_gown "$OUT/pol_allow6379.json"); say "A1 ALLOW-6379 policy, redis pid=$pid"
r=$(ping_redis); say "A1 redis-cli ping => '$r'  (expect PONG = ALLOWED)"
sudo -n kill -9 "$pid" 2>/dev/null; clean
pid=$(boot_gown "$OUT/pol_deny6379.json"); say "A2 DENY-6379 (allow only 7000) policy, redis pid=$pid"
r=$(ping_redis); say "A2 redis-cli ping => '$r'  (expect timeout/empty = DROPPED)"
sudo -n kill -9 "$pid" 2>/dev/null; clean

say "===================== (B) TAMPER-SENTINEL KILL TEST ====================="
pid=$(boot_gown "$OUT/pol_allow6379.json"); say "B1 redis+eSAC up, pid=$pid"
r=$(ping_redis); say "B1 pre-tamper ping => '$r' (alive)"
sudo -n bash "$SENTINEL" "$pid" 12 > "$OUT/sentinel.log" 2>&1 &
for j in $(seq 1 15); do grep -qi 'Attaching' "$OUT/sentinel.log" 2>/dev/null && break; sleep 1; done
say "B2 sentinel armed on pid=$pid: $(grep -i Attaching "$OUT/sentinel.log" | head -1)"
sleep 2; kill -0 "$pid" 2>/dev/null && say "B2 redis still alive after arming (good, no false-fire)" || say "B2 WARN redis died on arming"
say "B3 injecting openat(/proc/self/mem) into redis via gdb ..."
sudo -n timeout 25 gdb -p "$pid" -batch -ex 'call (int)open("/proc/self/mem", 2)' -ex detach -ex quit > "$OUT/gdb.log" 2>&1
sleep 3
if kill -0 "$pid" 2>/dev/null; then say "B3 RESULT: redis STILL ALIVE (tamper NOT killed) -- FAIL"; else say "B3 RESULT: redis pid=$pid KILLED by sentinel -- PASS"; fi
say "B3 sentinel log: $(grep -i EVWD "$OUT/sentinel.log" | head -2)"
clean
say "DONE OUT=$OUT"; touch "$OUT/.done"

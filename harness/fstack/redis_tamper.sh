#!/bin/bash
# eSAC GROUP3 — TAMPER attacker vs f-stack Redis (FINAL-only, Tamper Sentinel).
# Plain f-stack redis (NO comm loader / NO bpftime agent, so no JIT-mprotect warmup false-positive).
# 1) boot redis on mlx5 VF via switchdev, verify PING served.
# 2) arm Tamper Sentinel (tamper_sentinel_run.sh) on redis pid in steady state -> transparent (still serves).
# 3) TAMPER: attacker injects an RO-bypass syscall INTO redis' context (gdb call open("/proc/self/mem")),
#    simulating an in-process exploit re-opening RO hook/policy memory for write.
# 4) Sentinel SIGKILLs redis -> integrity violation neutralized.
set -u
D=/home/sungwoo/FINAL
REDIS=$D/apps/redis/redis-server
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf
INI=$D/apps/redis/ff_redis_sw.ini
SENT=$D/tamper_sentinel/tamper_sentinel_run.sh
IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1; SVF=0000:3b:01.3
OUT=$D/results/redis_tamper_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" "$D/apps/redis/ff_redis.ini" > "$INI"
sudo -n ip link set $IF1 up 2>/dev/null
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null; sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=; crep=; for n in /sys/class/net/*; do p=$(cat $n/phys_port_name 2>/dev/null); [ "$p" = pf1vf0 ] && srep=$(basename $n); [ "$p" = pf1vf1 ] && crep=$(basename $n); done
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null
say "switchdev+hairpin ready (srep=$srep crep=$crep)"

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f 'tamper_sentinel' 2>/dev/null; sudo -n pkill -9 -f 'bpftrace' 2>/dev/null; sleep 2; }
trc(){ timeout 5 /usr/bin/redis-cli -h $SIP -p 6379 "$@" 2>/dev/null; }
alive(){ local p=$1; [ -d /proc/$p ] || { echo DEAD; return; }; local s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo DEAD || echo ALIVE; }

clean
cd "$D/apps/redis"
RPID=$OUT/rpid
sudo -n setsid bash -c "echo \$\$ > $RPID; exec env LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
PID=$(cat $RPID); say "redis up pid=$PID  (plain f-stack, no eSAC agent)"
say "  PING (pre-sentinel)  -> $(trc PING)"
say "  SET/GET              -> SET=$(trc SET tk VALUE)  GET=$(trc GET tk)"

say "arming Tamper Sentinel on pid=$PID ..."
sudo -n bash "$SENT" "$PID" 11 > "$OUT/sentinel.log" 2>&1 &
for j in $(seq 1 15); do grep -qi "Attaching .* probe" "$OUT/sentinel.log" 2>/dev/null && break; sleep 1; done
say "  sentinel: $(grep -ai 'Attaching' "$OUT/sentinel.log" | head -1)"
say "  PING (sentinel armed, expect still served = transparent) -> $(trc PING)"
say "  redis state = $(alive $PID)"

say "===== TAMPER ATTACK: inject open(/proc/self/mem) into redis context via gdb ====="
sudo -n gdb -p "$PID" -batch -nx -ex 'call (int)open("/proc/self/mem", 2)' -ex 'detach' -ex 'quit' > "$OUT/attack.log" 2>&1
sleep 2
say "  sentinel hit: $(grep -aiE 'TAMPER_SENTINEL|procmem|mprotect|signal' "$OUT/sentinel.log" | tail -2 | tr '\n' '|')"
say "  redis state AFTER tamper = $(alive $PID)   (expect DEAD = killed by sentinel)"
say "  PING (after tamper, expect no reply) -> $(trc PING)"
echo "--- redis.log tail ---"; tail -3 "$OUT/redis.log" | grep -vE "^EAL:|TELEMETRY"

clean
say "DONE OUT=$OUT"

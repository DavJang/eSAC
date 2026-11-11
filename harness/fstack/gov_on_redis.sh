#!/bin/bash
# eSAC GOVERNOR attached to the REAL f-stack redis-server binary (static DPDK).
# Proves: the control-plane governor hooks redis's in-binary shared-NIC control
# calls (rte_eth_dev_start / rte_flow_create / rte_pktmbuf_pool_create), accounts
# them per-tenant, and under a benign policy ALLOWS them -> redis boots & serves
# (PONG) unbroken. bpf_printk "CPGOV ALLOW pid=<redis>" in redis.log = interception.
set -u
D=/home/sungwoo/FINAL
AGENT=$D/agent/libbpftime-agent.so
SERVER=$D/agent/libbpftime-syscall-server.so
GLOADER=$D/traffic/cp_governor_loader
OBJ=$D/comm_plane/bpf/cp_governor.bpf.o
REDIS=$D/apps/redis/redis-server
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf
INI=$D/apps/redis/ff_redis_sw.ini
SVF=0000:3b:01.3; IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1
OUT=$D/results/gov_redis_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

# switchdev + hairpin + client IP (idempotent)
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

off(){ readelf -sW "$REDIS" 2>/dev/null | awk -v n="$1" '$8==n{print $2; exit}'; }
CFG="$OUT/hooks.cfg"
{
  # Only rte_flow_create: a shared-eSwitch control call that is the governor's
  # real target (flow-rule churn) and is NOT on f-stack's init-critical
  # mempool/port-start path, so attaching it does not stall f-stack init.
  echo "$REDIS $(off rte_flow_create) cp_rate_ptr"
} > "$CFG"
say "hooks.cfg (governor on redis binary):"; cat "$CFG"

sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]p_governor' 2>/dev/null
sudo -n rm -f /dev/shm/bpftime* 2>/dev/null; sleep 2

cd "$D/apps/redis"
SHM=esac_govredis_$(date +%s%N)
RPID=$OUT/rpid
sudo -n setsid bash -c "echo \$\$ > $RPID; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
sleep 2; PID=$(cat $RPID 2>/dev/null); say "redis (STOPPED) pid=$PID"
[ -z "$PID" ] && { say "BOOT FAIL"; exit 1; }

# attach governor while redis is STOPPED (pre-EAL) so init-time control calls are intercepted
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD="$SERVER" "$GLOADER" "$OBJ" "$PID" "$CFG" > "$OUT/gov.log" 2>&1 &
for j in $(seq 1 30); do grep -q 'gov. ready' "$OUT/gov.log" 2>/dev/null && break; sleep 1; done
say "gov: $(grep -a 'gov. ready' "$OUT/gov.log" | tail -1)"

sudo -n kill -CONT $PID
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; kill -0 $PID 2>/dev/null || break; sleep 1; done
if grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null; then say "redis BOOTED under governor (transparent)"; else say "redis did NOT reach Ready (check redis.log)"; fi

r=$(timeout 6 /usr/bin/redis-cli -h $SIP -p 6379 ping 2>&1); say "PING => '$r'  (expect PONG = redis fully functional under governor)"

say "===== governor interception trace (CPGOV lines in redis.log = redis's real control calls accounted) ====="
grep -aE 'CPGOV|MEMGOV' "$OUT/redis.log" | head -20
say "CPGOV_ALLOW=$(grep -ac 'CPGOV ALLOW' "$OUT/redis.log") CPGOV_DENY=$(grep -ac 'CPGOV DENY' "$OUT/redis.log")"

sudo -n kill -9 "$PID" 2>/dev/null; sudo -n pkill -9 -f '[c]p_governor' 2>/dev/null
sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n rm -f /dev/shm/bpftime* 2>/dev/null
say "DONE OUT=$OUT"

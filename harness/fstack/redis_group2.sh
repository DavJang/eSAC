#!/bin/bash
# eSAC GROUP2 — co-tenant resource attackers vs a protected f-stack Redis victim (FINAL-only).
# redis runs on mlx5 VF 3b:01.3 (victim, holds its hugepages + NIC). Attackers use NO VF (no conflict):
#   (A) RESOURCE OVER-CONSUMPTION attacker: control_churn2 --socket-mem=28000 (--no-pci) tries to grab
#       28 GB hugepages. resource_loader (kernel uprobe rte_eal_init, default cap 10 GB KILL) SIGKILLs it
#       at ADMISSION (before the grab) -> node0 free unchanged -> redis unharmed.
#   (B) API OVERCALL attacker: control_churn2 (--vdev=net_null0) hammers NIC control-plane APIs
#       (rte_flow_create / promiscuous / mtu / mac / vlan / xstats + malloc/zmalloc/memzone).
#       cp_governor (bpftime override) THROTTLES: rate-limited calls -> CPGOV/MEMGOV DENY, attacker
#       keeps running but its calls are refused -> redis unharmed.
set -u
D=/home/sungwoo/FINAL
REDIS=$D/apps/redis/redis-server
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf; INI=$D/apps/redis/ff_redis_sw.ini
IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1; SVF=0000:3b:01.3
# resource plane (KILL)
RLOADER=$D/comm_plane/loaders/resource_loader
RBPF=$D/comm_plane/bpf/resource_monitor.bpf.o
EALSO=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
# governor (throttle)
SRV=$D/agent/libbpftime-syscall-server.so; AGENT=$D/agent/libbpftime-agent.so
GLOADER=$D/traffic/cp_governor_loader; GOBJ=$D/comm_plane/bpf/cp_governor.bpf.o
CHURN=$D/traffic/control_churn2
DD=/usr/local/lib/x86_64-linux-gnu; ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
OUT=$D/results/redis_group2_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
n0free(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null; }
trc(){ timeout 5 /usr/bin/redis-cli -h $SIP -p 6379 "$@" 2>/dev/null; }
alive(){ local p=$1; [ -d /proc/$p ] || { echo DEAD; return; }; local s=$(awk "{print \$3}" /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo DEAD || echo ALIVE; }

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

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f 'control_churn2' 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'cp_governor' 2>/dev/null; sleep 2; }
clean
# ---- boot redis victim ----
cd "$D/apps/redis"; RPID=$OUT/rpid
sudo -n setsid bash -c "echo \$\$ > $RPID; exec env LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
RP=$(cat $RPID); FREE0=$(n0free)
say "redis victim up pid=$RP  PING=$(trc PING)  node0free=$FREE0"

echo ""; say "############ (A) RESOURCE OVER-CONSUMPTION attacker (--socket-mem=28000 > cap 10000) ############"
echo '{"default":{"max_socket_mem_mb":10000,"action_on_violation":"KILL"}}' > "$OUT/res_pol.json"
sudo -n setsid bash -c "echo \$\$ > $OUT/pidG; kill -STOP \$\$; exec env LD_LIBRARY_PATH=$DD $CHURN -l 2 -n 4 --no-pci --in-memory --socket-mem=28000,0 --file-prefix=greedyA -- 3" > "$OUT/greedy.log" 2>&1 </dev/null & disown
sleep 2; G=$(cat "$OUT/pidG")
sudo -n "$RLOADER" --bpf "$RBPF" --lib "$EALSO" --policy "$OUT/res_pol.json" -v > "$OUT/res_loader.log" 2>&1 & RL=$!
sleep 3; sudo -n kill -CONT "$G"; sleep 5
say "  attacker pid=$G state=$(alive $G)   (expect DEAD = admission-KILL before grab)"
say "  resource_loader: $(grep -aE 'VIOLATION|KILL|eal_init' "$OUT/res_loader.log" | grep -a "$G" | head -1)"
say "  node0free now=$(n0free)  (expect ~=$FREE0 = grab prevented)"
say "  redis victim state=$(alive $RP)  PING=$(trc PING)   (expect ALIVE/PONG)"
sudo -n kill -9 $RL 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'control_churn2' 2>/dev/null; sleep 2

echo ""; say "############ (B) API OVERCALL attacker (control-plane churn) -> governor THROTTLE ############"
CFG="$OUT/hooks.cfg"
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
{ echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr"
  echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_set_mtu) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_vlan_filter) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_xstats_get) cp_rate_int"
  echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr"; } > "$CFG"
SHM=esac_$(date +%s%N)
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=Warn LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$DD" bash -c "kill -STOP \$\$; exec $CHURN -l 2 -n 4 --no-pci --vdev=net_null0 --file-prefix=churnB --in-memory -- 12" > "$OUT/churn.log" 2>&1 &
sleep 2; CP=$(pgrep -f 'control_churn2.*churnB' | head -1)
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=Warn LD_PRELOAD="$SRV" "$GLOADER" "$GOBJ" "$CP" "$CFG" > "$OUT/gov_loader.log" 2>&1 & GL=$!
for j in $(seq 1 30); do grep -qi "gov. ready" "$OUT/gov_loader.log" 2>/dev/null && break; sleep 1; done
sudo -n kill -CONT "$CP" 2>/dev/null
for j in $(seq 1 25); do grep -q "CTLCHURN2 done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$CP" 2>/dev/null || break; sleep 1; done
sleep 1
say "  attacker pid=$CP state=$(alive $CP)   (expect ALIVE/finished = throttled not killed)"
say "  governor denials: cp_denials=$(grep -ac 'CPGOV DENY' "$OUT/churn.log") mem_denials=$(grep -ac 'MEMGOV DENY' "$OUT/churn.log")"
say "  churn sample (NULL/-11 = throttled calls): $(grep -aE '^\[' "$OUT/churn.log" | tail -2 | tr '\n' '|')"
say "  redis victim state=$(alive $RP)  PING=$(trc PING)   (expect ALIVE/PONG)"
sudo -n kill -9 $GL 2>/dev/null; sudo -n pkill -9 -f 'control_churn2' 2>/dev/null; sudo -n pkill -9 -f 'cp_governor' 2>/dev/null

echo ""; say "===== redis victim FINAL state = $(alive $RP)  PING=$(trc PING) ====="
clean
say "node0free final=$(n0free)"
say "DONE OUT=$OUT"

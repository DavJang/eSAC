#!/bin/bash
# CAPSTONE: defend f-stack Redis (mlx5) from an API-OVERCALL attacker via the governor THROTTLE.
# redis = protected workload on mlx5 VF 3b:01.3 (plain f-stack, serving). attacker = control_churn2
# on an idle 82599 PF (vfio) hammering NIC control-plane APIs; cp_governor (bpftime override) throttles
# its calls (CPGOV/MEMGOV DENY, -11/NULL) while redis keeps serving. Runs DETACHED; ALWAYS restores NIC.
set -u
D=/home/sungwoo/FINAL; PCI=0000:5e:00.0; DD=/usr/local/lib/x86_64-linux-gnu
ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
REDIS=$D/apps/redis/redis-server; FFLIB=$D/lib/fstack-dpdk:$DD
CONF=$D/apps/redis/ff_redis.conf; INI=$D/apps/redis/ff_redis_sw.ini
IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1; SVF=0000:3b:01.3
OUT=$D/results/redis_apidefend_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
trc(){ timeout 5 /usr/bin/redis-cli -h $SIP -p 6379 "$@" 2>/dev/null; }
alive(){ local p=$1; [ -d /proc/$p ] || { echo DEAD; return; }; local s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo DEAD || echo ALIVE; }

restore(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f control_churn2 2>/dev/null; sudo -n pkill -9 -f cp_governor 2>/dev/null; sleep 1
  sudo -n /usr/local/bin/dpdk-devbind.py -u $PCI 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PCI 2>/dev/null
  say "RESTORED $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null)); redis/churn/gov killed"; echo EXP_DONE >> "$R"; }
trap restore EXIT

# ---- mlx5 switchdev + redis victim ----
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
sudo -n pkill -9 -x redis-server 2>/dev/null; sleep 2
cd "$D/apps/redis"; RPID=$OUT/rpid
sudo -n setsid bash -c "echo \$\$ > $RPID; exec env LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
RP=$(cat $RPID); say "redis victim (mlx5 VF $SVF) pid=$RP  PING(before)=$(trc PING)"

# ---- 82599 attacker under governor (full 7 hooks) ----
sudo -n modprobe vfio-pci 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=vfio-pci $PCI 2>/dev/null
say "attacker NIC $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))"
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
CFG="$OUT/hooks.cfg"
{ echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr"
  echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_set_mtu) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_vlan_filter) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_xstats_get) cp_rate_int"
  echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr"; } > "$CFG"
SHM=esac_apidef_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/cpid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$D/agent/libbpftime-agent.so LD_LIBRARY_PATH=$DD $D/traffic/control_churn2 -l 2 -n 4 -a $PCI --file-prefix=apidef82 --in-memory -- 20" > "$OUT/churn.log" 2>&1 &
sleep 3; CP=$(cat "$OUT/cpid")
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$D/agent/libbpftime-syscall-server.so $D/traffic/cp_governor_loader $D/comm_plane/bpf/cp_governor.bpf.o "$CP" "$CFG" > "$OUT/loader.log" 2>&1 &
for j in $(seq 1 30); do grep -qi 'gov. ready' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
say "governor: $(grep -a ready "$OUT/loader.log" | tail -1)"
sudo -n kill -CONT "$CP"
for j in $(seq 1 30); do grep -q 'CTLCHURN2 done' "$OUT/churn.log" 2>/dev/null && break; kill -0 "$CP" 2>/dev/null || break; sleep 1; done
sleep 1
say "===== RESULT ====="
say "attacker churn: reached-loop=$(grep -ac 'CTLCHURN2 start' "$OUT/churn.log") done=$(grep -ac 'CTLCHURN2 done' "$OUT/churn.log") alive=$([ -d /proc/$CP ] && echo yes||echo no) (throttle must NOT kill)"
say "  CPGOV DENY=$(grep -ac 'CPGOV DENY' "$OUT/churn.log")  MEMGOV DENY=$(grep -ac 'MEMGOV DENY' "$OUT/churn.log")  CPGOV ALLOW=$(grep -ac 'CPGOV ALLOW' "$OUT/churn.log")"
say "  promisc: $(grep -aoE 'promisc=[0-9-]+' "$OUT/churn.log"|sort|uniq -c|tr '\n' ' ')  malloc: $(grep -aoE 'malloc=[A-Z]+' "$OUT/churn.log"|sort|uniq -c|tr '\n' ' ')"
say "redis victim: state=$(alive $RP)  PING(after)=$(trc PING)  SET/GET=$(trc SET z 1)/$(trc GET z)  (expect ALIVE/PONG = unharmed)"
say "OUT=$OUT"

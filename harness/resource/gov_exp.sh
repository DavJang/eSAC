#!/bin/bash
# Robust governor-override isolation experiment. Runs DETACHED (setsid) so an SSH drop can't
# interrupt it; ALWAYS restores 82599 PF to ixgbe via trap. Writes a RESULT file.
# arg1 = tag ; arg2 = hook spec, one of: malloc | promisc | flow | all
set -u
F=/home/sungwoo/FINAL; PCI=0000:5e:00.0; DD=/usr/local/lib/x86_64-linux-gnu
ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
TAG=${1:-malloc}; HOOK=${2:-malloc}
OUT=$F/results/govexp_${TAG}_$(date +%s); mkdir -p "$OUT"
R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }

restore(){ sudo -n pkill -9 -f 'control_churn2' 2>/dev/null; sudo -n pkill -9 -f 'cp_governor' 2>/dev/null; sleep 1
  sudo -n /usr/local/bin/dpdk-devbind.py -u $PCI 2>/dev/null
  sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PCI 2>/dev/null
  say "RESTORED $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))"
  echo "EXP_DONE" >> "$R"; }
trap restore EXIT

sudo -n modprobe vfio-pci 2>/dev/null
sudo -n /usr/local/bin/dpdk-devbind.py --bind=vfio-pci $PCI 2>/dev/null
say "bound $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))  HOOK=$HOOK"
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
CFG="$OUT/hooks.cfg"; : > "$CFG"
case "$HOOK" in
  malloc)  echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr" >> "$CFG";;
  promisc) echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int" >> "$CFG";;
  flow)    echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr" >> "$CFG";;
  all)     echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr" >> "$CFG"
           echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr" >> "$CFG";;
  full7)   echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr" >> "$CFG"
           echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int" >> "$CFG"
           echo "$ETH $(off $ETH rte_eth_dev_set_mtu) cp_rate_int" >> "$CFG"
           echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add) cp_rate_int" >> "$CFG"
           echo "$ETH $(off $ETH rte_eth_dev_vlan_filter) cp_rate_int" >> "$CFG"
           echo "$ETH $(off $ETH rte_eth_xstats_get) cp_rate_int" >> "$CFG"
           echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr" >> "$CFG";;
esac
say "hooks.cfg: $(cat $CFG | tr '\n' '|')"

SHM=esac_${TAG}_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/cpid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$F/agent/libbpftime-agent.so LD_LIBRARY_PATH=$DD $F/traffic/control_churn2 -l 2 -n 4 -a $PCI --file-prefix=${TAG}82 --in-memory -- 20" > "$OUT/churn.log" 2>&1 &
sleep 3; CP=$(cat "$OUT/cpid" 2>/dev/null)
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$F/agent/libbpftime-syscall-server.so \
  $F/traffic/cp_governor_loader $F/comm_plane/bpf/cp_governor.bpf.o "$CP" "$CFG" > "$OUT/loader.log" 2>&1 &
for j in $(seq 1 30); do grep -qi 'gov. ready' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
say "loader: $(grep -a ready "$OUT/loader.log" | tail -1)"
sudo -n kill -CONT "$CP" 2>/dev/null
for j in $(seq 1 30); do grep -q 'CTLCHURN2 done' "$OUT/churn.log" 2>/dev/null && break; kill -0 "$CP" 2>/dev/null || break; sleep 1; done
sleep 1
say "churn reached-loop(CTLCHURN2 start)=$(grep -ac 'CTLCHURN2 start' "$OUT/churn.log")  done=$(grep -ac 'CTLCHURN2 done' "$OUT/churn.log")  alive=$([ -d /proc/$CP ] && echo yes || echo no)"
for col in malloc zmalloc memzone promisc mtu mac vlan xstats; do
  say "$col col: $(grep -aoE "$col=[A-Z0-9-]+" "$OUT/churn.log" | sort | uniq -c | tr '\n' ' ')"
done
say "CPGOV DENY=$(grep -ac 'CPGOV DENY' "$OUT/churn.log")  MEMGOV DENY=$(grep -ac 'MEMGOV DENY' "$OUT/churn.log")  CPGOV ALLOW=$(grep -ac 'CPGOV ALLOW' "$OUT/churn.log")"
say "churn loop sample:"; grep -aE '^\[ *[0-9]+ t=' "$OUT/churn.log" | sed -n '1p;8p;12p;20p' | tee -a "$R"
say "OUT=$OUT"

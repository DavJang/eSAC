#!/bin/bash
# API-OVERCALL attacker -> governor THROTTLE, on an idle 82599 PF (ixgbe DPDK works; mlx5 VF TIS fails).
# Binds 0000:5e:00.0 (idle, link-down, iommu grp 1 solo, no IP) to vfio-pci, runs control_churn2 under
# cp_governor (bpftime override), collects CPGOV/MEMGOV DENY, then ALWAYS rebinds to ixgbe (trap).
set -u
F=/home/sungwoo/FINAL
SRV=$F/agent/libbpftime-syscall-server.so; AGENT=$F/agent/libbpftime-agent.so
GLOADER=$F/traffic/cp_governor_loader; OBJ=$F/comm_plane/bpf/cp_governor.bpf.o
APP=$F/traffic/control_churn2
DD=/usr/local/lib/x86_64-linux-gnu; ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
PCI=0000:5e:00.0
OUT=$F/results/gov82599_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

restore(){ sudo -n pkill -9 -f control_churn2 2>/dev/null; sudo -n pkill -9 -f cp_governor 2>/dev/null
  sudo -n /usr/local/bin/dpdk-devbind.py -u $PCI 2>/dev/null
  sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PCI 2>/dev/null
  say "RESTORED $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))"; }
trap restore EXIT

sudo -n pkill -9 -f control_churn2 2>/dev/null; sudo -n pkill -9 -f cp_governor 2>/dev/null; sleep 1
sudo -n modprobe vfio-pci 2>/dev/null
sudo -n /usr/local/bin/dpdk-devbind.py --bind=vfio-pci $PCI 2>/dev/null
say "bound $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null)) (expect vfio-pci)"

off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
CFG="$OUT/hooks.cfg"
{ echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr"
  echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_set_mtu) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_vlan_filter) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_xstats_get) cp_rate_int"
  echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr"; } > "$CFG"

SHM=esac_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/cpid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=Warn LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$DD $APP -l 2 -n 4 -a $PCI --file-prefix=gov82 --in-memory -- 12" > "$OUT/churn.log" 2>&1 &
sleep 3; CP=$(cat "$OUT/cpid")
say "churn pid=$CP (stopped)"
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=Warn LD_PRELOAD="$SRV" "$GLOADER" "$OBJ" "$CP" "$CFG" > "$OUT/loader.log" 2>&1 &
for j in $(seq 1 30); do grep -qi "gov. ready" "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
say "gov loader: $(grep -a 'ready' "$OUT/loader.log" | tail -1)"
sudo -n kill -CONT "$CP"
for j in $(seq 1 30); do grep -q "CTLCHURN2 done" "$OUT/churn.log" 2>/dev/null && break; kill -0 "$CP" 2>/dev/null || break; sleep 1; done
sleep 1
echo ""; say "===== RESULT ====="
say "churn alive=$([ -d /proc/$CP ] && echo yes || echo no) (throttle must NOT kill)"
say "cp_denials(CPGOV DENY)=$(grep -ac 'CPGOV DENY' "$OUT/churn.log")  mem_denials(MEMGOV DENY)=$(grep -ac 'MEMGOV DENY' "$OUT/churn.log")"
say "cp_allows(CPGOV ALLOW)=$(grep -ac 'CPGOV ALLOW' "$OUT/churn.log")"
echo "--- churn loop lines (flow=NULL / mtu=-11 etc = throttled calls) ---"
grep -aE '^\[ *[0-9]+ t=' "$OUT/churn.log" | head -14
echo "--- CPGOV sample ---"; grep -aE 'CPGOV|MEMGOV' "$OUT/churn.log" | head -6
say "DONE OUT=$OUT"

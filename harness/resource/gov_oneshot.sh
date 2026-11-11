#!/bin/bash
# ONE-SHOT governor test on idle 82599 PF (vfio). control_churn2 calls dev_start once
# (at setup) then churns promiscuous/mtu/mac/vlan/flow in a loop. Expect per-(pid,api):
#  - dev_start: ALLOW(first) once -> CTLCHURN2 starts (init survives the hook)
#  - promiscuous/mtu/mac/flow: 1st call ALLOW (real val), 2nd+ DENY (-11/NULL)
# Verifies PT_REGS_IP discriminates per API (distinct ip in CPGOV lines). Detached; trap-restore.
set +u
F=/home/sungwoo/FINAL; PCI=0000:5e:00.0; DD=/usr/local/lib/x86_64-linux-gnu
ETH=$DD/librte_ethdev.so; EALS=$DD/librte_eal.so
OUT=$F/results/gov_oneshot_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -f control_churn2 2>/dev/null; sudo -n pkill -9 -f cp_governor 2>/dev/null; sleep 1
  sudo -n /usr/local/bin/dpdk-devbind.py -u $PCI 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PCI 2>/dev/null
  say "RESTORED $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))"; echo EXP_DONE >> "$R"; }
trap restore EXIT
sudo -n modprobe vfio-pci 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=vfio-pci $PCI 2>/dev/null
say "bound $PCI -> $(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null))"
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
CFG="$OUT/hooks.cfg"
{ echo "$ETH $(off $ETH rte_flow_create) cp_rate_ptr"
  echo "$ETH $(off $ETH rte_flow_destroy) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_start) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_stop) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_promiscuous_enable) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_promiscuous_disable) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_set_mc_addr_list) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_set_mtu) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_mac_addr_add) cp_rate_int"
  echo "$ETH $(off $ETH rte_eth_dev_vlan_filter) cp_rate_int"
  echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr"; } > "$CFG"
say "hooks: $(wc -l < $CFG) APIs (prof set: flow_create/destroy, dev_start/stop, promisc en/dis, mc_addr_list + mtu/mac/vlan + malloc)"

SHM=esac_os_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/cpid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$F/agent/libbpftime-agent.so LD_LIBRARY_PATH=$DD $F/traffic/control_churn2 -l 2 -n 4 -a $PCI --file-prefix=os82 --in-memory -- 20" > "$OUT/churn.log" 2>&1 &
sleep 3; CP=$(cat "$OUT/cpid")
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$F/agent/libbpftime-syscall-server.so $F/traffic/cp_governor_loader $F/comm_plane/bpf/cp_governor.bpf.o "$CP" "$CFG" > "$OUT/loader.log" 2>&1 &
for j in $(seq 1 30); do grep -qi 'gov. ready' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
say "loader: $(grep -a ready "$OUT/loader.log" | tail -1)"
sudo -n kill -CONT "$CP"
for j in $(seq 1 30); do grep -q 'CTLCHURN2 done' "$OUT/churn.log" 2>/dev/null && break; kill -0 "$CP" 2>/dev/null || break; sleep 1; done
sleep 1
echo "" ; say "===== ONE-SHOT RESULT ====="
say "init survived dev_start hook? CTLCHURN2 start=$(grep -ac 'CTLCHURN2 start' "$OUT/churn.log") done=$(grep -ac 'CTLCHURN2 done' "$OUT/churn.log")"
say "promisc col (expect 1x0 then rest -11): $(grep -aoE 'promisc=[0-9-]+' "$OUT/churn.log"|sort|uniq -c|tr '\n' ' ')"
say "mtu col:  $(grep -aoE 'mtu=[0-9-]+' "$OUT/churn.log"|sort|uniq -c|tr '\n' ' ')"
say "mac col:  $(grep -aoE 'mac=[0-9-]+' "$OUT/churn.log"|sort|uniq -c|tr '\n' ' ')"
say "ALLOW(first) count=$(grep -ac 'CPGOV ALLOW(first)' "$OUT/churn.log")  DENY(oneshot) count=$(grep -ac 'CPGOV DENY(oneshot)' "$OUT/churn.log")"
say "distinct APIs allowed-once (unique ip in ALLOW(first)): $(grep -aoE 'ALLOW\(first\) pid=[0-9]+ ip=[0-9a-f]+' "$OUT/churn.log"|grep -oE 'ip=[0-9a-f]+'|sort -u|wc -l)"
echo "--- CPGOV ALLOW(first) lines (one per API) ---"; grep -a 'CPGOV ALLOW(first)' "$OUT/churn.log" | head -12
say "OUT=$OUT"

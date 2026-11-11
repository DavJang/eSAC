#!/bin/bash
# eSAC resource-plane validation: QUEUE-COUNT axis (max_rx_queues / max_tx_queues) -> KILL.
# NO NIC NEEDED: use the virtual PMD --vdev=net_null0 so port 0 exists under --no-pci.
# mbuf_stress --queue-test --rxq R --txq T calls rte_eth_dev_configure(0, R, T) directly.
# BPF uprobe rte_eth_dev_configure reads nb_rx_queue/nb_tx_queue -> compares to policy caps.
#
# Step 0 (no loader): confirm net_null0 itself ACCEPTS rxq=8/txq=8 (so an ALLOW verdict
#                     isn't confounded by a PMD-side queue limit).
# Step 1 matrix (loader on), all request on net_null0:
#   A  rxq=8 txq=8 | cap rx=2            -> VIOLATION (rx arm)  -> KILL
#   B  rxq=8 txq=8 | cap rx=64 tx=64     -> ALLOW               -> success
#   C  rxq=1 txq=8 | cap rx=64 tx=2      -> VIOLATION (tx arm)  -> KILL   (rx passes, tx trips)
#   D  rxq=1 txq=1 | cap rx=2  tx=2      -> ALLOW (neg. control)-> success
set +e
D=/home/sungwoo/FINAL
libdir=/usr/local/lib/x86_64-linux-gnu/librte_eal.so   # loader resolves eth_dev_configure in librte_ethdev.so (same dir)
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
MB=/home/sungwoo/old/dpdk_ebpf_work/DPDK_eBPF/stress/mbuf_stress
OUT=$D/results/res_queue_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
EAL="-n 4 --no-pci --in-memory --socket-mem=512,0 --vdev=net_null0"
APPBASE="--rounds 1 --pool-n 1024 --rooms 2048 --queue-test"

sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sleep 1

echo "================ STEP 0: net_null0 accepts rxq=8/txq=8 WITHOUT loader? ================"
sudo -n $MB -l 0 $EAL --file-prefix=qprobe -- $APPBASE --rxq 8 --txq 8 > "$OUT/probe.log" 2>&1
say "probe: $(grep -aE 'QUEUE TEST|success|failed|invalid' "$OUT/probe.log" | tr '\n' '|')"
sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sleep 1

run(){  # $1=tag $2=rxq $3=txq $4=policyJSON $5=expect
  local tag=$1 RX=$2 TX=$3 POL=$4 EXP=$5
  sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sleep 1
  sudo -n setsid bash -c "echo \$\$ > $OUT/pid_$tag; kill -STOP \$\$; exec $MB -l 0 $EAL --file-prefix=q_$tag -- $APPBASE --rxq $RX --txq $TX" > "$OUT/t_$tag.log" 2>&1 < /dev/null & disown
  sleep 2; local P=$(cat "$OUT/pid_$tag")
  echo "$POL" > "$OUT/pol_$tag.json"
  sudo -n "$loader" --bpf "$bpf" --lib "$libdir" --policy "$OUT/pol_$tag.json" -v > "$OUT/loader_$tag.log" 2>&1 & local L=$!
  sleep 3; sudo -n kill -CONT "$P"; sleep 5
  local verdict
  if grep -aq "pid=$P .*\[VIOLATION\].*eth_dev_configure" "$OUT/loader_$tag.log"; then verdict=VIOLATION/KILL
  elif grep -aq "QUEUE TEST] rte_eth_dev_configure success" "$OUT/t_$tag.log"; then verdict=ALLOW/success
  else verdict=UNCLEAR; fi
  say "  $tag: rxq=$RX txq=$TX  policy=$POL"
  say "     => $verdict   (expect $EXP)   $([ "${verdict%%/*}" = "${EXP%%/*}" ] && echo MATCH || echo CHECK)"
  echo "     loader eth_dev_configure line: $(grep -aE "pid=$P.*eth_dev_configure" "$OUT/loader_$tag.log" | head -1)"
  echo "     tenant QUEUE TEST line:        $(grep -aE 'QUEUE TEST' "$OUT/t_$tag.log" | tail -1)"
  sudo -n pkill -9 -f 'mbuf_stres[s]' 2>/dev/null; sudo -n kill -9 $L 2>/dev/null; sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sleep 1
}

echo ""; echo "================ STEP 1: policy matrix ================"
run A 8 8 '{"default":{"max_rx_queues":2,"action_on_violation":"KILL"}}'                      VIOLATION
run B 8 8 '{"default":{"max_rx_queues":64,"max_tx_queues":64,"action_on_violation":"KILL"}}'  ALLOW
run C 1 8 '{"default":{"max_rx_queues":64,"max_tx_queues":2,"action_on_violation":"KILL"}}'   VIOLATION
run D 1 1 '{"default":{"max_rx_queues":2,"max_tx_queues":2,"action_on_violation":"KILL"}}'    ALLOW

n0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages)
say "node0 free (final) = $n0 (baseline 15872 = no leak)"
say "DONE OUT=$OUT"

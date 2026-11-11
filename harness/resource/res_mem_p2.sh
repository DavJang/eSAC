#!/bin/bash
# eSAC resource-plane validation PART 2: HUGEPAGE over-consumption DoS -> eSAC mitigation.
#  2a (no eSAC): greedy hp_hold grabs 28000MB node0 hugepages -> victim's rte_eal_init FAILS
#                ("Not enough memory"). SR-IOV cannot prevent this (host-RAM resource).
#  2b (eSAC on): default policy max_socket_mem_mb=10000 KILL. greedy requests 28000 > 10000
#                -> KILLED at rte_eal_init BEFORE the grab -> node0 stays full -> victim SUCCEEDS.
# All tenants root + --in-memory (anon hugepages: no /dev/hugepages perm, freed on exit, no wedge).
set +e
D=/home/sungwoo/FINAL
lib=/usr/local/lib/x86_64-linux-gnu/librte_eal.so
loader=$D/comm_plane/loaders/resource_loader
bpf=$D/comm_plane/bpf/resource_monitor.bpf.o
HP=/home/sungwoo/old/dpdk_policy_demo/hp_hold
VIC=/home/sungwoo/old/dpdk_policy_demo/hp_victim
OUT=$D/results/res_mem_p2_$(date +%s); mkdir -p "$OUT"; chmod 777 "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }
n0free(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null; }
alive(){ local p=$1; [ -d /proc/$p ] || { echo KILLED; return; }; local s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = "Z" ] && echo KILLED || echo ALIVE; }
GRAB=28000; VICREQ=8000; CAP=10000

cleanup_all(){ sudo -n pkill -9 -f 'resource_loade[r]' 2>/dev/null; sudo -n pkill -9 -f 'hp_hol[d]' 2>/dev/null; sudo -n pkill -9 -f 'hp_victi[m]' 2>/dev/null; sleep 2; }
cleanup_all
say "node0 free (baseline) = $(n0free) pages (x2MB); greedy will request ${GRAB}MB, victim ${VICREQ}MB"

echo ""; say "############ 2a: DoS WITHOUT eSAC ############"
sudo -n setsid bash -c "echo \$\$ > $OUT/pidH1; exec $HP -l 0 -n 4 --no-pci --in-memory --socket-mem=${GRAB},0 --file-prefix=hpDoS" > "$OUT/hold1.log" 2>&1 < /dev/null & disown
for j in $(seq 1 20); do grep -q GREEDY_EAL_OK "$OUT/hold1.log" 2>/dev/null && break; sleep 1; done
H1=$(cat "$OUT/pidH1"); say "greedy pid=$H1 state=$(alive $H1)  node0 free AFTER grab = $(n0free)  (greedy holding ${GRAB}MB)"
sudo -n "$VIC" -l 0 -n 4 --no-pci --in-memory --socket-mem=${VICREQ},0 --file-prefix=hpVic1 > "$OUT/vic1.log" 2>&1
say "2a victim(${VICREQ}MB) => $(grep -aE 'VICTIM_EAL' "$OUT/vic1.log" | tail -1)  (expect FAIL = DoS confirmed)"
grep -aE 'Not enough|Cannot init' "$OUT/vic1.log" | tail -1
sudo -n kill -9 $H1 2>/dev/null; sudo -n pkill -9 -f 'hp_hol[d]' 2>/dev/null; sleep 3
say "after releasing greedy: node0 free = $(n0free)  (should return to baseline)"

echo ""; say "############ 2b: WITH eSAC (admission KILL caps greedy) ############"
cat > "$OUT/policy.json" <<EOF
{"default":{"max_socket_mem_mb":${CAP},"action_on_violation":"KILL"}}
EOF
say "policy: default max_socket_mem_mb=${CAP} KILL (greedy ${GRAB}>${CAP} -> KILL; victim ${VICREQ}<${CAP} -> ALLOW)"
# greedy STOPPED so loader attaches before its eal_init
sudo -n setsid bash -c "echo \$\$ > $OUT/pidH2; kill -STOP \$\$; exec $HP -l 0 -n 4 --no-pci --in-memory --socket-mem=${GRAB},0 --file-prefix=hpDoS2" > "$OUT/hold2.log" 2>&1 < /dev/null & disown
sleep 2; H2=$(cat "$OUT/pidH2")
sudo -n "$loader" --bpf "$bpf" --lib "$lib" --policy "$OUT/policy.json" -v > "$OUT/loader.log" 2>&1 & L=$!
sleep 3
fb=$(n0free); say "node0 free before greedy release = $fb"
sudo -n kill -CONT $H2; sleep 4
say "greedy pid=$H2 state=$(alive $H2)  node0 free AFTER (should ~= $fb = grab PREVENTED, no leak) = $(n0free)"
say "loader: $(grep -aE 'VIOLATION|KILL|ALLOW|eal_init' "$OUT/loader.log" | grep -i "$H2\|eal_init" | head -3 | tr '\n' '|')"
# victim now tries under eSAC
sudo -n "$VIC" -l 0 -n 4 --no-pci --in-memory --socket-mem=${VICREQ},0 --file-prefix=hpVic2 > "$OUT/vic2.log" 2>&1
say "2b victim(${VICREQ}MB) => $(grep -aE 'VICTIM_EAL' "$OUT/vic2.log" | tail -1)  (expect OK = DoS mitigated)"

cleanup_all
say "node0 free (final) = $(n0free)  (baseline = no leak)"
say "DONE OUT=$OUT"

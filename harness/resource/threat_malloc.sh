#!/bin/bash
# THROTTLE threat-model validation (rte_malloc / host hugepage heap):
# Tenant A churns rte_malloc (grows DPDK heap from the SHARED node0 hugepage pool);
# Tenant B (victim) then needs 10 GB at EAL init. SR-IOV does NOT isolate host RAM.
#   Phase 1 (no throttle): A grabs the pool -> B's rte_eal_init FAILS (cross-tenant DoS).
#   Phase 2 (governor mem_quota on A's rte_malloc): A denied after quota -> pool preserved -> B OK.
# No NIC needed (--no-pci --in-memory, anonymous hugepages, freed on exit).
set +u
F=/home/sungwoo/FINAL; DD=/usr/local/lib/x86_64-linux-gnu; EALS=$DD/librte_eal.so
AGENT=$F/agent/libbpftime-agent.so; SRV=$F/agent/libbpftime-syscall-server.so
GLOADER=$F/traffic/cp_governor_loader; GOBJ=$F/comm_plane/bpf/cp_governor.bpf.o
MX=/home/sungwoo/old/dpdk_ebpf_work/DPDK_eBPF/stress/malloc_exhaust
VIC=/home/sungwoo/old/dpdk_policy_demo/hp_victim
OUT=$F/results/threat_malloc_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
n0(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages; }
alive(){ [ -d /proc/$1 ] || { echo DEAD; return; }; local s=$(awk '{print $3}' /proc/$1/stat 2>/dev/null); [ "$s" = Z ] && echo DEAD || echo ALIVE; }
clean(){ sudo -n pkill -9 -f malloc_exhaus 2>/dev/null; sudo -n pkill -9 -f hp_victi 2>/dev/null; sudo -n pkill -9 -f cp_governor 2>/dev/null; sleep 2; }
trap clean EXIT
STEP=256; LOOPS=120   # A tries 256MB x120 = 30GB; VICTIM needs 10GB; node0 ~31GB
clean; say "node0 free start = $(n0) pages (x2MB ~ $(( $(n0)*2/1024 ))GB); A step=${STEP}MB loops=$LOOPS; victim needs 10GB"

echo ""; say "############ PHASE 1 — NO throttle (cross-tenant DoS) ############"
sudo -n setsid env -u LD_PRELOAD LD_LIBRARY_PATH=$DD $MX --no-pci --in-memory --file-prefix=mcA -- --step $STEP --loops $LOOPS > "$OUT/a1.log" 2>&1 </dev/null & disown
for j in $(seq 1 25); do grep -qa "MEMCHURN\|holding\|done\|total=" "$OUT/a1.log" 2>/dev/null && break; sleep 1; done; sleep 3
A1=$(pgrep -f 'malloc_exhaus.*mcA' | head -1)
say "  A grabbed: $(grep -aoE 'total=[0-9]+ ?MB' "$OUT/a1.log" | tail -1)  node0 free now=$(n0) (~$(( $(n0)*2/1024 ))GB)"
sudo -n env -u LD_PRELOAD LD_LIBRARY_PATH=$DD $VIC -l 0 -n 4 --no-pci --in-memory --socket-mem=10000,0 --file-prefix=vic1 > "$OUT/b1.log" 2>&1
say "  VICTIM(10GB) => $(grep -aoE 'VICTIM_EAL_(OK|FAIL)' "$OUT/b1.log" | tail -1)  $(grep -aoE 'Not enough|Cannot init' "$OUT/b1.log" | tail -1)"
sudo -n kill -9 $A1 2>/dev/null; sudo -n pkill -9 -f malloc_exhaus 2>/dev/null; sleep 3
say "  after releasing A: node0 free = $(n0)"

echo ""; say "############ PHASE 2 — WITH throttle (governor mem_quota on A's rte_malloc) ############"
CFG="$OUT/hooks.cfg"; off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print $2; exit}'; }
echo "$EALS $(off $EALS rte_malloc) mem_quota_ptr" > "$CFG"
say "  hooks: rte_malloc -> mem_quota (count quota, deny after ~8 allocs)"
SHM=esac_thr_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/pidA; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$DD $MX --no-pci --in-memory --file-prefix=mcA2 -- --step $STEP --loops $LOOPS" > "$OUT/a2.log" 2>&1 & disown
sleep 2; A2=$(cat "$OUT/pidA")
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$SRV $GLOADER $GOBJ "$A2" "$CFG" > "$OUT/gov.log" 2>&1 &
for j in $(seq 1 30); do grep -qi 'gov. ready' "$OUT/gov.log" 2>/dev/null && break; sleep 1; done
sudo -n kill -CONT "$A2"; sleep 5
say "  A(throttled) grabbed: $(grep -aoE 'total=[0-9]+ ?MB' "$OUT/a2.log" | tail -1)  MEMGOV_DENY=$(grep -ac 'MEMGOV DENY' "$OUT/a2.log")  node0 free now=$(n0) (~$(( $(n0)*2/1024 ))GB)"
sudo -n env -u LD_PRELOAD LD_LIBRARY_PATH=$DD $VIC -l 0 -n 4 --no-pci --in-memory --socket-mem=10000,0 --file-prefix=vic2 > "$OUT/b2.log" 2>&1
say "  VICTIM(10GB) => $(grep -aoE 'VICTIM_EAL_(OK|FAIL)' "$OUT/b2.log" | tail -1)"
clean; say "node0 free final=$(n0)"
say "===== VERDICT ====="
say "  Phase1 (no throttle): A grabs pool -> victim $(grep -aoE 'VICTIM_EAL_(OK|FAIL)' "$OUT/b1.log"|tail -1) = cross-tenant harm"
say "  Phase2 (throttle):    A capped     -> victim $(grep -aoE 'VICTIM_EAL_(OK|FAIL)' "$OUT/b2.log"|tail -1) = protected"
say "DONE OUT=$OUT"

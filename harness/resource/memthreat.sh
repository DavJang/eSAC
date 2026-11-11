#!/bin/bash
# NEW threat (memory alloc/free CHURN = rate axis on shared host hugepage pool), distinct from
# (a) prof's firmware-steering churn and (b) the HOLD/quota->SIGKILL over-allocation threat.
# Attacker churns rte_malloc(64MB)+free (NET-ZERO held) -> kernel hugepage mmap/munmap on the
# SHARED node0 pool (hugetlb_lock + zeroing) -> a co-located victim doing its own hugepage allocs
# sees inflated latency. HOLD/quota gate sees nothing (0 held). Governor RATE-LIMIT on rte_malloc
# throttles the churn -> victim recovers. 3 phases: baseline / attack / defended. No NIC.
set +u
F=/home/sungwoo/FINAL; DD=/usr/local/lib/x86_64-linux-gnu; EALS=$DD/librte_eal.so
HR=$F/harness/resource; PROBE=$HR/hp_probe; ATK=$HR/mem_churn
AGENT=$F/agent/libbpftime-agent.so; SRV=$F/agent/libbpftime-syscall-server.so
GLOADER=$F/traffic/cp_governor_loader; RLOBJ=$F/comm_plane/bpf/flow_ratelimit.bpf.o
VCPU=6; ACPU=20; MB=64; ADUR=14; PDUR=9; PWARM=1
OUT=$F/results/memchurn_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
N0(){ cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages; }
off(){ readelf -sW "$1" 2>/dev/null | awk -v s="$2" '$8==s || $8 ~ ("^" s "@"){print "0x"$2; exit}'; }
clean(){ sudo -n pkill -9 -f mem_churn 2>/dev/null; sudo -n pkill -9 -f hp_probe 2>/dev/null
  sudo -n pkill -9 -f cp_governor_loader 2>/dev/null; sleep 1; }
trap 'clean; say "node0 free end=$(N0)"; echo EXP_DONE>>"$R"' EXIT
clean
say "node0 free start=$(N0) (x2MB ~ $(( $(N0)*2/1024 ))GB); victim cpu=$VCPU attacker cpu=$ACPU block=${MB}MB"

# sample node0 oscillation for N*0.2s, print min/max amplitude
osc(){ local mn=99999999 mx=0 f; for i in $(seq 1 $1); do f=$(N0); [ $f -lt $mn ]&&mn=$f; [ $f -gt $mx ]&&mx=$f; sleep 0.2; done; echo "$((mx-mn))"; }

echo "" ; say "########## PHASE 1 — BASELINE (victim alone) ##########"
P1=$(taskset -c $VCPU "$PROBE" $PDUR $PWARM 2>&1 | grep -a hp_probe); say "  $P1"

echo "" ; say "########## PHASE 2 — ATTACK (victim + churn, NO governor) ##########"
sudo -n setsid env LD_LIBRARY_PATH=$DD "$ATK" -l $ACPU -n 4 --no-pci --in-memory --file-prefix=mcA -- --mb $MB --dur $ADUR > "$OUT/atk2.log" 2>&1 </dev/null & disown
sleep 2; ( osc 10 > "$OUT/osc2" ) & OSCPID=$!
P2=$(taskset -c $VCPU "$PROBE" $PDUR $PWARM 2>&1 | grep -a hp_probe); say "  $P2"
wait $OSCPID 2>/dev/null; A2=$(grep -a 'MEMCHURN done' "$OUT/atk2.log")
say "  attacker: $A2 | node0 oscillation=$(cat $OUT/osc2 2>/dev/null) pages"
sudo -n pkill -9 -f mem_churn 2>/dev/null; sleep 2

echo "" ; say "########## PHASE 3 — DEFENDED (victim + churn + governor rate-limit on rte_malloc) ##########"
CFG="$OUT/hooks.cfg"; echo "$EALS $(off $EALS rte_malloc) rl_flow_create" > "$CFG"
say "  hook: rte_malloc@$(off $EALS rte_malloc) -> rl_flow_create (token-bucket rate-limit); cfg=$(cat $CFG)"
SHM=esac_mem_$(date +%s%N)
sudo -n bash -c "echo \$\$ > $OUT/apid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$DD $ATK -l $ACPU -n 4 --no-pci --in-memory --file-prefix=mcB -- --mb $MB --dur $ADUR" > "$OUT/atk3.log" 2>&1 </dev/null & disown
sleep 2; AP=$(cat "$OUT/apid")
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM SPDLOG_LEVEL=warn LD_PRELOAD=$SRV "$GLOADER" "$RLOBJ" "$AP" "$CFG" > "$OUT/gov.log" 2>&1 & disown
for j in $(seq 1 30); do grep -qi 'ready' "$OUT/gov.log" 2>/dev/null && break; sleep 1; done
say "  governor: $(grep -ai ready "$OUT/gov.log" | tail -1 | head -c 120)"
sudo -n kill -CONT "$AP" 2>/dev/null; sleep 1
( osc 10 > "$OUT/osc3" ) & OSCPID=$!
P3=$(taskset -c $VCPU "$PROBE" $PDUR $PWARM 2>&1 | grep -a hp_probe); say "  $P3"
wait $OSCPID 2>/dev/null; A3=$(grep -a 'MEMCHURN done' "$OUT/atk3.log")
say "  attacker(throttled): $A3 | node0 oscillation=$(cat $OUT/osc3 2>/dev/null) pages"

echo "" ; say "########## SUMMARY ##########"
say "P1 baseline : $P1"
say "P2 attack   : $P2"
say "P3 defended : $P3"
say "OUT=$OUT"

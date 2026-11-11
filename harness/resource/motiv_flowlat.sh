#!/bin/bash
# EXP A (independent): flow-rule ADD/DELETE per-rule latency. Add N skip_sw flower rules to a VF rep
# ONE AT A TIME, timing each add (us); then delete ONE AT A TIME, timing each. No victim traffic -
# this measures the per-operation cost itself. Look for spikes (HW steering reprogram / table-grow boundary).
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1
OUT=$D/results/flowlat_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  say "RESTORED PF numvfs=0 legacy"; echo EXP_DONE >> "$R"; }
trap restore EXIT

echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
E2=$(rep 2)
sudo -n ip link set $IF vf 2 trust on 2>/dev/null; sudo -n ip link set $E2 up 2>/dev/null; sudo -n tc qdisc add dev $E2 ingress 2>/dev/null
say "attacker rep=$E2 ; adding/deleting flower rules one-by-one, timing each (us)"

N=2500
sudo -n bash -c '
REP="'$E2'"; N='$N'
for ((i=1;i<=N;i++)); do
  a=$(((i>>16)&255)); b=$(((i>>8)&255)); c=$((i&255))
  t0=$EPOCHREALTIME
  tc filter add dev $REP ingress pref $((i+1)) protocol ip flower skip_sw dst_ip 10.$a.$b.$c action drop 2>/dev/null
  t1=$EPOCHREALTIME
  awk -v x=$t0 -v y=$t1 -v i=$i "BEGIN{printf \"A %d %.0f\n\", i, (y-x)*1000000}"
done
for ((i=1;i<=N;i++)); do
  t0=$EPOCHREALTIME
  tc filter del dev $REP ingress pref $((i+1)) 2>/dev/null
  t1=$EPOCHREALTIME
  awk -v x=$t0 -v y=$t1 -v i=$i "BEGIN{printf \"F %d %.0f\n\", i, (y-x)*1000000}"
done
' > "$OUT/lat.txt" 2>/dev/null

say "===== ADD per-rule latency (us) ====="
awk '$1=="A"&&$3~/^[0-9]+$/{v[n++]=$3;s+=$3;if(min==""||$3<min)min=$3;if($3>max){max=$3;mi=$2}}
  END{if(n==0){print "  none";exit} asort(v); printf "  n=%d min=%d median=%d p90=%d p99=%d max=%d(@rule %s) mean=%.0f\n",n,min,v[int(n*0.5)],v[int(n*0.9)],v[int(n*0.99)],max,mi,s/n}' "$OUT/lat.txt" | tee -a "$R"
say "  10 slowest ADDs (rule#:us) -> periodic boundary or random?"
grep '^A ' "$OUT/lat.txt" | awk '$3~/^[0-9]+$/{print $2":"$3}' | sort -t: -k2 -nr | head -10 | tr '\n' ' ' | tee -a "$R"; echo "" | tee -a "$R"
say "  per-500-rule-bucket mean ADD us (does cost grow as table grows?)"
awk '$1=="A"&&$3~/^[0-9]+$/{b=int(($2-1)/500); s[b]+=$3; c[b]++} END{for(k=0;k<=int(2500/500);k++) if(c[k]) printf "    rules %d-%d: mean=%.0fus (n=%d)\n",k*500+1,(k+1)*500,s[k]/c[k],c[k]}' "$OUT/lat.txt" | tee -a "$R"

say "===== DELETE per-rule latency (us) ====="
awk '$1=="F"&&$3~/^[0-9]+$/{v[n++]=$3;s+=$3;if(min==""||$3<min)min=$3;if($3>max){max=$3;mi=$2}}
  END{if(n==0){print "  none";exit} asort(v); printf "  n=%d min=%d median=%d p90=%d p99=%d max=%d(@rule %s) mean=%.0f\n",n,min,v[int(n*0.5)],v[int(n*0.9)],v[int(n*0.99)],max,mi,s/n}' "$OUT/lat.txt" | tee -a "$R"
say "  10 slowest DELETEs (rule#:us)"
grep '^F ' "$OUT/lat.txt" | awk '$3~/^[0-9]+$/{print $2":"$3}' | sort -t: -k2 -nr | head -10 | tr '\n' ' ' | tee -a "$R"; echo "" | tee -a "$R"
say "DONE OUT=$OUT"

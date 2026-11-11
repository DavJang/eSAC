#!/bin/bash
# mlx5 extra-threat hunt (beyond paper): does an attacker's flow activity starve a VICTIM's OWN
# control plane (its ability to INSTALL its policy rules)? Distinct from T1 (datapath collapse).
#   baseline      : victim installs 600 rules one-by-one on its rep; per-add latency + success count
#   contend_churn : attacker add+del churn (count~1) on its rep, max rate; victim installs 600
#   contend_fill  : attacker PRE-FILLS 1200 rules on its rep (near/over the ~1k eSwitch threshold);
#                   victim installs 600 -> do victim adds slow down or FAIL (shared cmd-if / table)?
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1
OUT=$D/results/cmdif_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -f 'atkcmd' 2>/dev/null; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
  sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null; say "RESTORED PF numvfs=0 legacy"; echo EXP_DONE >> "$R"; }
trap restore EXIT

echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
EV=$(rep 0) EA=$(rep 2)   # victim rep, attacker rep
for i in 0 2; do sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
sudo -n ip link set $EV up 2>/dev/null; sudo -n ip link set $EA up 2>/dev/null
sudo -n tc qdisc add dev $EV ingress 2>/dev/null; sudo -n tc qdisc add dev $EA ingress 2>/dev/null
say "victim rep=$EV  attacker rep=$EA"

VN=600   # victim rules per trial
# victim: install VN rules one-by-one on EV, time each (us); report latency stats + in_hw success
victim_install(){ local tag=$1
  sudo -n bash -c '
   REP="'$EV'"; N='$VN'
   for ((i=1;i<=N;i++)); do a=$(((i>>16)&255)); b=$(((i>>8)&255)); c=$((i&255))
     t0=$EPOCHREALTIME
     tc filter add dev $REP ingress pref $((i+1)) protocol ip flower skip_sw dst_ip 172.$a.$b.$c action drop 2>/dev/null
     t1=$EPOCHREALTIME
     awk -v x=$t0 -v y=$t1 -v i=$i "BEGIN{printf \"%d %.0f\n\", i, (y-x)*1000000}"
   done' > "$OUT/vlat_$tag.txt" 2>/dev/null
  local inhw=$(sudo -n tc filter show dev $EV ingress 2>/dev/null | grep -c 'in_hw')
  local stat=$(awk '$2~/^[0-9]+$/{v[n++]=$2;s+=$2;if($2>mx)mx=$2} END{if(n==0){print "none";exit} asort(v); printf "n=%d median=%dus p99=%dus max=%dus mean=%.0fus",n,v[int(n*0.5)],v[int(n*0.99)],mx,s/n}' "$OUT/vlat_$tag.txt")
  say "  [$tag] victim-install: $stat  in_hw_success=$inhw/$VN"
  sudo -n tc filter del dev $EV ingress 2>/dev/null; sudo -n tc qdisc del dev $EV ingress 2>/dev/null; sudo -n tc qdisc add dev $EV ingress 2>/dev/null; }

# attacker churn add+del same rule at max rate (count ~1) on EA
atkcmd_churn(){ while :; do
    sudo -n tc filter add dev $EA ingress pref 1 protocol ip flower skip_sw dst_ip 10.9.9.9 action drop 2>/dev/null
    sudo -n tc filter del dev $EA ingress pref 1 2>/dev/null; done; }

say "===== baseline (no attacker) ====="
victim_install baseline

say "===== contend_churn (attacker add/del churn on its rep, max rate) ====="
( exec -a atkcmd bash -c "$(declare -f atkcmd_churn); atkcmd_churn" ) & AP=$!
sleep 1; victim_install contend_churn; kill $AP 2>/dev/null; sudo -n pkill -9 -f atkcmd 2>/dev/null
sudo -n tc filter del dev $EA ingress 2>/dev/null; sudo -n tc qdisc del dev $EA ingress 2>/dev/null; sudo -n tc qdisc add dev $EA ingress 2>/dev/null; sleep 1

say "===== contend_fill (attacker pre-fills 1200 rules on its rep) ====="
BF="$OUT/fill.txt"; : > "$BF"
for i in $(seq 1 1200); do printf 'filter add dev %s ingress pref %d protocol ip flower skip_sw dst_ip 10.%d.%d.%d action drop\n' \
  "$EA" "$((i+1))" "$(((i>>16)&255))" "$(((i>>8)&255))" "$((i&255))" >> "$BF"; done
sudo -n tc -batch "$BF" 2>/dev/null
say "  attacker pre-fill: in_hw=$(sudo -n tc filter show dev $EA ingress 2>/dev/null | grep -c 'in_hw')"
victim_install contend_fill
say "DONE OUT=$OUT"

#!/bin/bash
# MOTIVATION hugepage-transient: prof's claim = the victim rate SPIKES at the MOMENT a flow-rule add
# allocates / a flow-rule delete frees the backing memory (hugepage). Stay BELOW the ~700-rule death
# threshold (use 600) so the victim otherwise runs at 100k; oscillate ADD600/DEL600 bursts at known
# times; sample node0/node1/sys HugePages_Free every 100ms with wall timestamps; log each burst's
# wall time. Then align: does the victim dip at add & at delete, and do the hugepage counters move there?
set +u
D=/home/sungwoo/FINAL; PF=0000:3b:00.1; IF=enp59s0f1np1; DPERF=$D/traffic/dperf; LIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
OUT=$D/results/motiv_hp_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"; EV="$OUT/events.txt"; : > "$EV"; SAMP="$OUT/samp.txt"; : > "$SAMP"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f 'HPSAMPLER' 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
  sudo -n find /dev/hugepages -maxdepth 1 -name 'dperf-*' -delete 2>/dev/null
  say "RESTORED PF numvfs=0 legacy node0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages)"; echo EXP_DONE >> "$R"; }
trap restore EXIT

sudo -n pkill -9 -x dperf 2>/dev/null; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1; sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn3 ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
rep(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0)); CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1))
E0=$(rep 0) E1=$(rep 1) E2=$(rep 2)
sudo -n ip link set $IF vf 0 mac 02:70:00:00:00:01 2>/dev/null; sudo -n ip link set $IF vf 1 mac 02:70:00:00:00:02 2>/dev/null
for i in 0 1 2 3; do sudo -n ip link set $IF vf $i spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $i trust on 2>/dev/null; done
for e in $E0 $E1 $E2; do sudo -n ip link set $e up 2>/dev/null; sudo -n tc qdisc add dev $e ingress 2>/dev/null; done
sudo -n tc filter add dev $E0 ingress protocol all flower skip_sw action mirred egress redirect dev $E1 2>/dev/null
sudo -n tc filter add dev $E1 ingress protocol all flower skip_sw action mirred egress redirect dev $E0 2>/dev/null
say "probe: server=$SVF client=$CVF (hairpin $E0<->$E1); attacker rep=$E2"

NR=600  # peak attacker rules per burst (below ~700 death threshold)
BF="$OUT/add$NR.txt"; : > "$BF"
for i in $(seq 1 $NR); do printf 'filter add dev %s ingress pref %d protocol ip flower skip_sw dst_ip 10.%d.%d.%d action drop\n' \
  "$E2" "$((i+1))" "$(((i>>16)&255))" "$(((i>>8)&255))" "$((i&255))" >> "$BF"; done

cat > "$OUT/server.conf" <<C
mode server
tx_burst 32
cpu 6
duration 50s
payload_size 64
protocol tcp
keepalive 1ms
socket_mem 1024
port $SVF 192.168.1.1 192.168.0.1 02:70:00:00:00:02
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
cat > "$OUT/client.conf" <<C
mode client
tx_burst 32
cpu 16
duration 35s
payload_size 64
protocol tcp
cps 100
cc 100
keepalive 1ms
socket_mem 0,2048
port $CVF 192.168.0.1 192.168.1.1 02:70:00:00:00:01
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C

# 100ms hugepage sampler (HPSAMPLER tag so restore can pkill it)
sampler(){ while :; do printf '%s n0=%s n1=%s hpf=%s\n' "$(date +%s.%N)" \
  "$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null)" \
  "$(cat /sys/devices/system/node/node1/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null)" \
  "$(awk '/HugePages_Free/{print $2}' /proc/meminfo)"; sleep 0.1; done; }
ev(){ echo "$(date +%s.%N) $1 n0=$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages) hpf=$(awk '/HugePages_Free/{print $2}' /proc/meminfo)" >> "$EV"; }

# attacker oscillation, aligned to CLIENT start (passed as arg = client_start epoch)
atkosc(){ local cs=$1
  waituntil(){ local tgt=$1; while awk -v n="$(date +%s.%N)" -v c="$cs" -v t="$tgt" 'BEGIN{exit !((n-c)<t)}'; do sleep 0.05; done; }
  waituntil 8;  ev ADD600_a; sudo -n tc -batch "$BF" 2>/dev/null; ev ADD600_a_done
  waituntil 14; ev DEL600_a; sudo -n tc filter del dev $E2 ingress 2>/dev/null; ev DEL600_a_done
  waituntil 20; ev ADD600_b; sudo -n tc -batch "$BF" 2>/dev/null; ev ADD600_b_done
  waituntil 26; ev DEL600_b; sudo -n tc filter del dev $E2 ingress 2>/dev/null; ev DEL600_b_done
  echo HPSAMPLER_marker_in_argv >/dev/null; }

series(){ sed 's/\x1b\[[0-9;]*m//g' "$1" | grep -aoE 'tcpRsp +[0-9,]+' | sed 's/tcpRsp//; s/[ ,]//g' | nl | sed -n '1,40p'; }

say "===== hugepage-transient: ADD600/DEL600 bursts, 100ms hugepage sampling ====="
sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1
( exec -a HPSAMPLER bash -c "$(declare -f sampler); sampler" ) >> "$SAMP" 2>/dev/null & SP=$!
sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/server.conf" > "$OUT/srv.log" 2>&1 & sleep 6
CS=$(date +%s.%N); echo "CLIENT_START=$CS" >> "$EV"
( atkosc "$CS" ) & AP=$!
sudo -n env LD_LIBRARY_PATH=$LIB $DPERF -c "$OUT/client.conf" > "$OUT/cli.log" 2>&1
kill $AP $SP 2>/dev/null; sudo -n pkill -9 -f 'HPSAMPLER' 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 1

say "--- EVENTS (wall, offset from client start) ---"; CS=$(grep CLIENT_START "$EV"|cut -d= -f2)
awk -v c="$CS" '/EVENT|ADD|DEL/{printf "  +%5.2fs  %s\n",$1-c,$2}' "$EV" | tee -a "$R"
say "--- hugepage counter CHANGES during run (sample where a value differs from previous) ---"
awk -v c="$CS" 'NR==1{p0=$2;p1=$3;p2=$4} {sub("n0=","",$2);sub("n1=","",$3);sub("hpf=","",$4)}
  (pv2!=""&&($2!=pv2||$3!=pv3||$4!=pv4)){printf "  +%6.2fs  n0=%s n1=%s hpf=%s  (was n0=%s n1=%s hpf=%s)\n",$1-c,$2,$3,$4,pv2,pv3,pv4}
  {pv2=$2;pv3=$3;pv4=$4}' "$SAMP" | tee -a "$R"
say "  (hugepage sample count=$(wc -l <"$SAMP"); if NO change lines above -> flow add/delete does NOT move system hugepages)"
say "--- VICTIM per-second tcpRsp (line N ~= client second N-1) ---"; series "$OUT/cli.log" | tee -a "$R"
say "DONE OUT=$OUT"

#!/bin/bash
IF=enp59s0f0np0; PF=0000:3b:00.0
RF=/home/sungwoo/eSACfinal/suricata/rules/dns.rules
RES=/home/sungwoo/ce11_suri_intra_results.txt; : > "$RES"
# --- f0 4-VF switchdev setup ---
sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null
sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs"; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev; sleep 1
sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
sudo -n sh -c "echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs"; sleep 3
sudo -n ip link set $IF vf 0 mac 02:60:00:00:00:01
sudo -n ip link set $IF vf 3 mac 02:60:00:00:00:04
for v in 0 1 2 3; do sudo -n ip link set $IF vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $v trust on 2>/dev/null; done
echo "f0 numvfs=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs)" | tee -a "$RES"
genrules(){ local N=$1; : > "$RF"; local i=0; while [ $i -lt $N ]; do
  printf 'alert dns any any -> any any (msg:"r%d"; dns.query; content:"e%d.su"; nocase; sid:%d; rev:1;)\n' "$i" "$i" $((9000000+i)) >> "$RF"; i=$((i+1)); done; }
for N in 2 100 1000 10000; do
  genrules "$N"
  echo "[$(date +%H:%M:%S)] N=$N rules=$(grep -c '^alert' "$RF")" | tee -a "$RES"
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 6
    line=$(PB=512 sudo -n -E bash /home/sungwoo/eSACfinal/harness/l7/sfc_suri_f0.sh pass 2>&1 | grep -aoE 'server_pps_median=[0-9]+')
    v=$(echo "$line" | grep -oE '[0-9]+')
    echo "  att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "CE11_SURI_INTRA N=$N server_pps=${v:-0}" | tee -a "$RES"
done
cp /home/sungwoo/eSACfinal/suricata/rules/dns.rules.orig "$RF" 2>/dev/null
echo "CE11_SURI_INTRA_DONE" | tee -a "$RES"

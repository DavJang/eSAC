#!/bin/bash
IF=enp59s0f0np0; PF=0000:3b:00.0
RES=/home/sungwoo/ce8_suri_intra_1k_results.txt; : > "$RES"
sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null
sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs"; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev; sleep 1
sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
sudo -n sh -c "echo 4 > /sys/bus/pci/devices/$PF/sriov_numvfs"; sleep 3
sudo -n ip link set $IF vf 0 mac 02:60:00:00:00:01
sudo -n ip link set $IF vf 3 mac 02:60:00:00:00:04
for v in 0 1 2 3; do sudo -n ip link set $IF vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $v trust on 2>/dev/null; done
echo "f0 numvfs=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs)" | tee -a "$RES"
# ---- DROP sanity (IPS inline must block malicious .su) @KA=20 ----
sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 6
dout=$(CC=1000 KA=20 PB=512 sudo -n -E bash /home/sungwoo/FINAL/harness/l7/sfc_suri_f0.sh drop 2>&1)
ds=$(echo "$dout" | grep -aoE "server_pps_median=[0-9]+" | grep -oE "[0-9]+")
dfl=$(echo "$dout" | grep -aoE "^[0-9]+ .*fast.log" | grep -oE "^[0-9]+")
dev=$(echo "$dout" | grep -aA1 "eve alerts" | tail -1)
echo "CE8_SURI_INTRA_DROPCHK drop_server_pps=${ds:-0} fastlog_alerts=${dfl:-NA} eve_alerts=${dev:-NA}" | tee -a "$RES"
# ---- pass throughput KA sweep @CC=1000 PB=512 ----
for KA in 20 100 500 1000; do
  echo "[$(date +%H:%M:%S)] KA=${KA}us" | tee -a "$RES"
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 6
    line=$(CC=1000 KA=$KA PB=512 sudo -n -E bash /home/sungwoo/FINAL/harness/l7/sfc_suri_f0.sh pass 2>&1 | grep -aoE "server_pps_median=[0-9]+")
    v=$(echo "$line" | grep -oE "[0-9]+")
    echo "  att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "CE8_SURI_INTRA KA=${KA}us server_pps=${v:-0}" | tee -a "$RES"
done
echo "CE8_SURI_INTRA_DONE" | tee -a "$RES"

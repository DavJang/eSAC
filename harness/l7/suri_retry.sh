#!/bin/bash
IF=enp59s0f0np0
sudo -n ip link set $IF vf 0 mac 02:60:00:00:00:01 2>/dev/null
sudo -n ip link set $IF vf 3 mac 02:60:00:00:00:04 2>/dev/null
for v in 0 1 2 3; do sudo -n ip link set $IF vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $v trust on 2>/dev/null; done
RES=/home/sungwoo/suri_retry.txt; : > "$RES"
for PB in 256 1400; do
  v=0
  for att in 1 2 3 4; do
    sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 suricata 2>/dev/null; sleep 8
    line=$(PB=$PB sudo -n -E bash /home/sungwoo/FINAL/harness/l7/sfc_suri_f0.sh pass 2>&1 | grep -aoE "server_pps_median=[0-9]+")
    v=$(echo "$line" | grep -oE "[0-9]+")
    echo "[$(date +%H:%M:%S)] PB=$PB att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "SURI_INTRA_FINAL PB=$PB server_pps=${v:-0}" | tee -a "$RES"
done
echo "RETRY_DONE" | tee -a "$RES"

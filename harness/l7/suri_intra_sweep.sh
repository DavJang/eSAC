#!/bin/bash
IF=enp59s0f0np0
sudo -n ip link set $IF vf 0 mac 02:60:00:00:00:01 2>/dev/null
sudo -n ip link set $IF vf 3 mac 02:60:00:00:00:04 2>/dev/null
for v in 0 1 2 3; do sudo -n ip link set $IF vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $v trust on 2>/dev/null; done
RES=/home/sungwoo/suri_intra_results.txt; : > "$RES"
for PB in 64 128 256 512 1400; do
  echo "[$(date +%H:%M:%S)] PB=$PB start" | tee -a "$RES"
  line=$(PB=$PB sudo -n -E bash /home/sungwoo/FINAL/harness/l7/sfc_suri_f0.sh pass 2>&1 | grep -aE "CASE=pass server_pps")
  echo "SURI_INTRA PB=$PB $line" | tee -a "$RES"
done
echo "SWEEP_DONE" | tee -a "$RES"

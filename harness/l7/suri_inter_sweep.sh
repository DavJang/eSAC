#!/bin/bash
RES=/home/sungwoo/suri_inter_results.txt; : > "$RES"
for PB in 64 128 256 512 1400; do
  Q=/home/sungwoo/FINAL/l7/payloads/dnsq_com_$(printf %04d $PB).bin
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 5
    line=$(QCOM=$Q sudo -n -E bash /home/sungwoo/FINAL/harness/l7/suri_inter_rx_v4.sh 2>&1 | grep -aoE "decoder.pkts: peak/s=[0-9]+")
    v=$(echo "$line" | grep -oE "[0-9]+")
    echo "[$(date +%H:%M:%S)] PB=$PB att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "SURI_INTER_FINAL PB=$PB decoder_pps=${v:-0}" | tee -a "$RES"
done
echo "INTER_SURI_DONE" | tee -a "$RES"

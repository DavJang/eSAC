#!/bin/bash
Q=/home/sungwoo/FINAL/l7/payloads/dnsq_com_0512.bin
RES=/home/sungwoo/ce8_suri_inter_1k_results.txt; : > "$RES"
for KA in 20 100 500 1000; do
  echo "[$(date +%H:%M:%S)] KA=${KA}us" | tee -a "$RES"
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 5
    line=$(CC=1000 KA=$KA QCOM=$Q sudo -n -E bash /home/sungwoo/FINAL/harness/l7/suri_inter_rx_v4.sh 2>&1 | grep -aoE "decoder.pkts: peak/s=[0-9]+")
    v=$(echo "$line" | grep -oE "[0-9]+")
    echo "  att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "CE8_SURI_INTER KA=${KA}us decoder_pps=${v:-0}" | tee -a "$RES"
done
echo "CE8_SURI_INTER_DONE" | tee -a "$RES"

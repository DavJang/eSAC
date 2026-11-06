#!/bin/bash
Q=/home/sungwoo/eSACfinal/l7/payloads/dnsq_com_0512.bin
RES=/home/sungwoo/ce9_suri_inter_results.txt; : > "$RES"
for CC in 1000 2000 4000 8000; do
  echo "[$(date +%H:%M:%S)] cc=$CC" | tee -a "$RES"
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 5
    line=$(CC=$CC KA=1000 QCOM=$Q sudo -n -E bash /home/sungwoo/eSACfinal/harness/l7/suri_inter_rx_v4.sh 2>&1 | grep -aoE 'decoder.pkts: peak/s=[0-9]+')
    v=$(echo "$line" | grep -oE '[0-9]+')
    echo "  att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "CE9_SURI_INTER cc=$CC decoder_pps=${v:-0}" | tee -a "$RES"
done
echo "CE9_SURI_INTER_DONE" | tee -a "$RES"

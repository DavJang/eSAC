#!/bin/bash
RF=/home/sungwoo/FINAL/suricata/rules/dns.rules
Q=/home/sungwoo/FINAL/l7/payloads/dnsq_com_0512.bin
RES=/home/sungwoo/ce11_suri_inter_results.txt; : > "$RES"
genrules(){ local N=$1; : > "$RF"; local i=0; while [ $i -lt $N ]; do
  printf 'alert dns any any -> any any (msg:"r%d"; dns.query; content:"e%d.su"; nocase; sid:%d; rev:1;)\n' "$i" "$i" $((9000000+i)) >> "$RF"; i=$((i+1)); done; }
for N in 2 100 1000 10000; do
  genrules "$N"
  echo "[$(date +%H:%M:%S)] N=$N rules=$(grep -c '^alert' "$RF")" | tee -a "$RES"
  v=0
  for att in 1 2 3; do
    sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 5
    line=$(QCOM=$Q sudo -n -E bash /home/sungwoo/FINAL/harness/l7/suri_inter_rx_v4.sh 2>&1 | grep -aoE 'decoder.pkts: peak/s=[0-9]+')
    v=$(echo "$line" | grep -oE '[0-9]+')
    echo "  att=$att -> ${v:-0}" | tee -a "$RES"
    [ "${v:-0}" -gt 1000 ] && break
  done
  echo "CE11_SURI_INTER N=$N decoder_pps=${v:-0}" | tee -a "$RES"
done
cp /home/sungwoo/FINAL/suricata/rules/dns.rules.orig "$RF" 2>/dev/null
echo "CE11_SURI_INTER_DONE" | tee -a "$RES"

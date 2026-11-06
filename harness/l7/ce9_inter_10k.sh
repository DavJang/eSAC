#!/bin/bash
RES=/home/sungwoo/ce9_inter_10k_results.txt; : > "$RES"
# eSAC/none @10k
R=$(SAT_CC_PER=10000 PAYONLY=1 DIRS=rx LAYERS=l7 CORES=1 PAYS=512 sudo -n -E bash /home/sungwoo/eSACfinal/harness/pps/esac_pps_inter.sh 2>&1 | grep -aoE 'root=[^ ]+' | head -1 | cut -d= -f2)
e=$(grep -aoE 'inter_rx_l7_c1_p512_cc10000_pass .*deliv=[0-9]+' "$R"/*.txt 2>/dev/null|grep -oE 'deliv=[0-9]+'|tail -1|cut -d= -f2)
n=$(grep -aoE 'inter_rx_none_c1_p512_cc10000 .*deliv=[0-9]+' "$R"/*.txt 2>/dev/null|grep -oE 'deliv=[0-9]+'|tail -1|cut -d= -f2)
pr=$(grep -ahc ENFORCE_PROVEN "$R"/*.txt 2>/dev/null)
echo "CE9_INTER cc=10000 none=${n:-0} eSAC=${e:-0} proven=$pr" | tee -a "$RES"
# Suricata @10k (retry)
Q=/home/sungwoo/eSACfinal/l7/payloads/dnsq_com_0512.bin; v=0
for att in 1 2 3; do
  sudo -n pkill -9 suricata 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sleep 5
  line=$(CC=10000 KA=1000 QCOM=$Q sudo -n -E bash /home/sungwoo/eSACfinal/harness/l7/suri_inter_rx_v4.sh 2>&1 | grep -aoE 'decoder.pkts: peak/s=[0-9]+')
  v=$(echo "$line" | grep -oE '[0-9]+'); echo "  suri att=$att -> ${v:-0}" | tee -a "$RES"
  [ "${v:-0}" -gt 1000 ] && break
done
echo "CE9_SURI_INTER cc=10000 decoder_pps=${v:-0}" | tee -a "$RES"
echo "INTER_10K_DONE" | tee -a "$RES"

#!/bin/bash
RES=/home/sungwoo/ce8_intra_1k_results.txt; : > "$RES"
for KA in 20 100 500 1000; do
  echo "[$(date +%H:%M:%S)] KA=${KA}us start" | tee -a "$RES"
  R=$(KA=$KA SAT_CC_PER=1000 PAYONLY=1 DIRS=rx LAYERS=l7 CORES=1 PAYS=512 sudo -n -E bash /home/sungwoo/eSACfinal/harness/pps/esac_pps_intra_f0.sh 2>&1 | grep -aoE "root=[^ ]+" | head -1 | cut -d= -f2)
  e=$(grep -aoE "intra_rx_l7_c1_p512_cc1000_pass .*deliv=[0-9]+" "$R"/*.txt 2>/dev/null|grep -oE "deliv=[0-9]+"|tail -1|cut -d= -f2)
  n=$(grep -aoE "intra_rx_none_c1_p512_cc1000 .*deliv=[0-9]+" "$R"/*.txt 2>/dev/null|grep -oE "deliv=[0-9]+"|tail -1|cut -d= -f2)
  pr=$(grep -ahc ENFORCE_PROVEN "$R"/*.txt 2>/dev/null)
  echo "CE8_INTRA KA=${KA}us none=${n:-0} eSAC=${e:-0} proven=$pr root=$R" | tee -a "$RES"
done
echo "CE8_INTRA_DONE" | tee -a "$RES"

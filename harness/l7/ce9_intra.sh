#!/bin/bash
RES=/home/sungwoo/ce9_intra_results.txt; : > "$RES"
for CC in 1000 2000 4000 8000; do
  echo "[$(date +%H:%M:%S)] cc=$CC start" | tee -a "$RES"
  R=$(SAT_CC_PER=$CC PAYONLY=1 DIRS=rx LAYERS=l7 CORES=1 PAYS=512 sudo -n -E bash /home/sungwoo/eSACfinal/harness/pps/esac_pps_intra_f0.sh 2>&1 | grep -aoE 'root=[^ ]+' | head -1 | cut -d= -f2)
  e=$(grep -aoE "intra_rx_l7_c1_p512_cc${CC}_pass .*deliv=[0-9]+" "$R"/*.txt 2>/dev/null|grep -oE 'deliv=[0-9]+'|tail -1|cut -d= -f2)
  n=$(grep -aoE "intra_rx_none_c1_p512_cc${CC} .*deliv=[0-9]+" "$R"/*.txt 2>/dev/null|grep -oE 'deliv=[0-9]+'|tail -1|cut -d= -f2)
  pr=$(grep -ahc ENFORCE_PROVEN "$R"/*.txt 2>/dev/null)
  echo "CE9_INTRA cc=$CC none=${n:-0} eSAC=${e:-0} proven=$pr" | tee -a "$RES"
done
echo "CE9_INTRA_DONE" | tee -a "$RES"

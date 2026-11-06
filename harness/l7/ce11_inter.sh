#!/bin/bash
RES=/home/sungwoo/ce11_inter_results.txt; : > "$RES"
for NPOL in 2 100 1000 10000; do
  echo "[$(date +%H:%M:%S)] NPOL=$NPOL start" | tee -a "$RES"
  R=$(NPOL=$NPOL PAYONLY=1 DIRS=rx LAYERS=l7 CORES=1 PAYS=512 sudo -n -E bash /home/sungwoo/eSACfinal/harness/pps/esac_pps_inter.sh 2>&1 | grep -aoE "root=[^ ]+" | head -1 | cut -d= -f2)
  v=$(grep -aoE "inter_rx_l7_c1_p512_cc8000_pass .*deliv=[0-9]+" "$R"/*.txt 2>/dev/null|grep -oE "deliv=[0-9]+"|tail -1|cut -d= -f2)
  pr=$(grep -ahc ENFORCE_PROVEN "$R"/*.txt 2>/dev/null)
  echo "CE11_INTER NPOL=$NPOL eSAC_l7_512=${v:-0} proven=$pr" | tee -a "$RES"
done
echo "CE11_INTER_DONE" | tee -a "$RES"

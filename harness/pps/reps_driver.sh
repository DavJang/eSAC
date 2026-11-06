#!/bin/bash
# n=3 median driver: PAYONLY payload-sweep reps for intra then inter.
LOG=/home/sungwoo/reps_driver.log; : > "$LOG"
echo "ROOTS:" > /home/sungwoo/reps_roots.txt
run(){ local script=$1 tag=$2
  for r in 1 2 3; do
    echo "[$(date +%T)] $tag rep$r start" >> "$LOG"
    PAYONLY=1 bash "/home/sungwoo/$script" >/dev/null 2>&1
    d=$(ls -dt /home/sungwoo/${tag}_2* 2>/dev/null | head -1)
    echo "$tag rep$r $d" >> /home/sungwoo/reps_roots.txt
    echo "[$(date +%T)] $tag rep$r done -> $d" >> "$LOG"
  done; }
run esac_pps_intra.sh esac_pps_intra
run esac_pps_inter.sh esac_pps_inter
touch /home/sungwoo/ALLREPS.done
echo "[$(date +%T)] ALL REPS DONE" >> "$LOG"

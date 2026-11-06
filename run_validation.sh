#!/bin/bash
# eSACfinal acceptance test: proves the self-contained tree runs WITHOUT any other /home/sungwoo dir.
#   1) CE-L4 intra microbench : none vs eSAC(ALLOW) vs eSAC(DROP)  [dperf + comm-plane]
#   2) fstack real-app        : ALLOW->PONG / DROP->blocked / tamper->SIGKILL  [unmodified Redis]
# Run as:  bash /home/sungwoo/eSACfinal/run_validation.sh
set -u
D=/home/sungwoo/eSACfinal
echo "########################################################################"
echo "# eSACfinal validation  $(date)"
echo "########################################################################"
echo; echo ">>> [1/2] intra switchdev fabric up"
bash "$D/harness/setup/intra_switchdev_up.sh"
echo; echo ">>> [1/2] CE-L4 intra (dperf microbenchmark)"
bash "$D/harness/ce_l4/validate_ce_intra.sh"
echo; echo ">>> [2/2] fstack real-app enforcement (STOP/CONT pre-attach)"
bash "$D/harness/fstack/fstack_verify_stopcont.sh"
echo; echo "########################################################################"
echo "# validation finished — review the PASS/VERDICT lines above"
echo "########################################################################"

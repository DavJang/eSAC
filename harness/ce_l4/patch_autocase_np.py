#!/usr/bin/env python3
# Build auto_case_hist_np.sh from the original: point at the NPOL harness + forward NPOL.
import sys
src='/home/sungwoo/eSACfinal/harness/ce_l4/auto_case_hist.sh'
dst='/home/sungwoo/eSACfinal/harness/ce_l4/auto_case_hist_np.sh'
s=open(src).read()
def rep(old,new,n=1):
    c=s.count(old)
    if c!=n: sys.exit("MISMATCH count=%d exp=%d: %r"%(c,n,old[:70]))
    return s.replace(old,new)
# point at NPOL harness
s=rep('server=/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode.sh',
      'server=/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode_np.sh')
# forward NPOL into the sudo env that launches the server
s=rep('sudo -n env MODE="$mode" OUT="$out" DUR="$dur"',
      'sudo -n env NPOL="${NPOL:-2}" MODE="$mode" OUT="$out" DUR="$dur"')
open(dst,'w').write(s)
print("WROTE",dst)

#!/usr/bin/env python3
# Build server_harness_4mode_np.sh (NPOL-aware) from the original, via exact replacements.
import sys
src='/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode.sh'
dst='/home/sungwoo/eSACfinal/harness/ce_l4/server_harness_4mode_np.sh'
s=open(src).read()

def rep(old,new,n=1):
    c=s.count(old)
    if c!=n:
        sys.exit("MISMATCH count=%d expected=%d for: %r"%(c,n,old[:60]))
    return s.replace(old,new)

# 1) NPOL default
s=rep('ACTION=${ACTION:-ALLOW}\n','ACTION=${ACTION:-ALLOW}\nNPOL=${NPOL:-2}\n')

# 2) kernel policy -> N rules (no cgroup_id)
old_k='  printf \'{"rules":[{"layer":"L2","dst_ip":"192.168.1.1","proto":6,"dst_port":9,"action":"%s"},{"layer":"L2","dst_ip":"192.168.0.1","proto":6,"action":"ALLOW"}]}\\n\' "$ACTION" > "$OUT/policy.json"'
new_k='  python3 /home/sungwoo/eSACfinal/policy/gen_policy_kern.py "$SIP" "$SPEER" "$ACTION" "$NPOL" 6 > "$OUT/policy.json"'
s=rep(old_k,new_k)

# 3) bpftime policy -> gen_policy_n with NPOL
old_b='  printf \'{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.1","proto":6,"dst_port":9,"action":"%s"},{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.0.1","proto":6,"action":"ALLOW"}]}\\n\' "$CGID" "$ACTION" "$CGID" > "$OUT/policy.json"'
new_b='  python3 /home/sungwoo/eSACfinal/policy/gen_policy_n.py "$CGID" "$SIP" "$SPEER" "$ACTION" "$NPOL" 6 > "$OUT/policy.json"'
s=rep(old_b,new_b)

# 4) readiness: drop the "=2" so any rule count passes
s=rep("L2 rules loaded=2","L2 rules loaded=")

open(dst,'w').write(s)
print("WROTE",dst)

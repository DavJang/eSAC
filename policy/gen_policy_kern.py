#!/usr/bin/env python3
# Kernel-mode N-rule policy (no cgroup_id). args: sip speer action n [proto]
import sys
sip,speer,act,n = sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4])
proto = int(sys.argv[5]) if len(sys.argv)>5 else 6
o3=int(sip.split('.')[2])
r=['{"layer":"L2","dst_ip":"%s","proto":%d,"dst_port":9,"action":"%s"}'%(sip,proto,act)]
for i in range(max(0,n-2)):
    ip="10.%d.%d.%d"%(o3,(i>>8)&255,(i&255)+1)
    r.append('{"layer":"L2","dst_ip":"%s","proto":%d,"dst_port":9,"action":"ALLOW"}'%(ip,proto))
r.append('{"layer":"L2","dst_ip":"%s","proto":%d,"action":"ALLOW"}'%(speer,proto))
print('{"rules":['+",".join(r)+']}')

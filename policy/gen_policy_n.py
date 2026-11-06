import sys
cg,sip,speer,act,n = sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5])
proto = int(sys.argv[6]) if len(sys.argv)>6 else 6
o3=int(sip.split('.')[2])
r=['{"layer":"L2","cgroup_id":%s,"dst_ip":"%s","proto":%d,"dst_port":9,"action":"%s"}'%(cg,sip,proto,act)]
for i in range(max(0,n-2)):
    ip="10.%d.%d.%d"%(o3,(i>>8)&255,(i&255)+1)
    r.append('{"layer":"L2","cgroup_id":%s,"dst_ip":"%s","proto":%d,"dst_port":9,"action":"ALLOW"}'%(cg,ip,proto))
r.append('{"layer":"L2","cgroup_id":%s,"dst_ip":"%s","proto":%d,"action":"ALLOW"}'%(cg,speer,proto))
print('{"rules":['+",".join(r)+']}')

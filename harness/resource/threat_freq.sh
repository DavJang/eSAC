#!/bin/bash
# THROTTLE threat-model (call FREQUENCY / shared PF-VF mailbox contention):
# Two VFs on one 82599 PF. Tenant B issues control-plane API calls and we measure its per-iter
# latency. Tenant A floods the SAME control APIs on its VF. If A's churn inflates B's per-call
# latency/jitter -> the shared mailbox is a cross-tenant channel -> cp_rate throttle justified.
# If B's latency is unchanged -> per-VF isolated (no frequency harm).
set +u
F=/home/sungwoo/FINAL; DD=/usr/local/lib/x86_64-linux-gnu; PF=0000:5e:00.0
CH=$F/traffic/control_churn2
OUT=$F/results/threat_freq_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
restore(){ sudo -n pkill -9 -f control_churn2 2>/dev/null; sleep 1
  echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
  sudo -n /usr/local/bin/dpdk-devbind.py -u $PF 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PF 2>/dev/null
  say "RESTORED $PF -> $(basename $(readlink /sys/bus/pci/devices/$PF/driver 2>/dev/null))"; echo EXP_DONE >> "$R"; }
trap restore EXIT

# PF must be on ixgbe to create VFs
sudo -n pkill -9 -f control_churn2 2>/dev/null
sudo -n /usr/local/bin/dpdk-devbind.py -u $PF 2>/dev/null; sudo -n /usr/local/bin/dpdk-devbind.py --bind=ixgbe $PF 2>/dev/null; sleep 1
echo 2 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 2
VFA=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn0 2>/dev/null))
VFB=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn1 2>/dev/null))
say "VFs: A=$VFA B=$VFB (numvfs=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs))"
[ -z "$VFA" ] && { say "VF CREATE FAILED"; exit 1; }
sudo -n modprobe vfio-pci 2>/dev/null
sudo -n /usr/local/bin/dpdk-devbind.py --bind=vfio-pci $VFA $VFB 2>/dev/null
say "bound: A=$(basename $(readlink /sys/bus/pci/devices/$VFA/driver)) B=$(basename $(readlink /sys/bus/pci/devices/$VFB/driver))"

# per-iter latency of B = deltas of its '[i t=Xms]' timestamps
runB(){ local tag=$1 file=$2
  sudo -n env LD_LIBRARY_PATH=$DD $CH -l 2 -n 4 -a $VFB --file-prefix=fqB$tag --in-memory -- 40 > "$file" 2>&1
  awk 'match($0,/t=[ ]*[0-9]+ms/){t=substr($0,RSTART+2); gsub(/[^0-9]/,"",t); if(prev!=""){d=t-prev; a[n++]=d} prev=t}
       END{if(n==0){print "noiter";exit} for(i=0;i<n;i++)s+=a[i]; for(i=0;i<n;i++)for(j=i+1;j<n;j++)if(a[i]>a[j]){x=a[i];a[i]=a[j];a[j]=x}
           printf "n=%d mean=%.1fms p50=%dms max=%dms", n, s/n, a[int(n/2)], a[n-1]}' "$file"; }

echo ""; say "===== B ALONE (baseline per-iter latency) ====="
say "  B: $(runB alone "$OUT/b_alone.log")"

echo ""; say "===== B WITH A flooding control APIs on its VF ====="
sudo -n env LD_LIBRARY_PATH=$DD $CH -l 3 -n 4 -a $VFA --file-prefix=fqA --in-memory -- 100000 > "$OUT/a_flood.log" 2>&1 &
APID=$!; sleep 3
say "  A flooding (pid=$APID, iters=100000): $(grep -aoE '\[ *[0-9]+ t=' "$OUT/a_flood.log" | tail -1)"
say "  B under contention: $(runB contend "$OUT/b_contend.log")"
sudo -n kill -9 $APID 2>/dev/null; sudo -n pkill -9 -f control_churn2 2>/dev/null

echo ""; say "===== VERDICT ====="
say "  B alone     : $(runB_res=$(grep -a 'B: ' "$R"|head -1); echo "$runB_res" | sed 's/.*B: //')"
say "  (compare mean/max: if contention >> alone, mailbox is a shared cross-tenant channel -> cp_rate throttle justified; if ~equal, per-VF isolated)"
say "DONE OUT=$OUT"

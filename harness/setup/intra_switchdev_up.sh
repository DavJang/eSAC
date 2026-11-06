#!/bin/bash
# eSACfinal shared setup: bring up PF1 switchdev + 2 VFs + tc hairpin (intra fabric).
# Idempotent. Echoes SVF/CVF bdfs. Needed by CE-intra and fstack real-app validation.
set -u
PF1=0000:3b:00.1; IF1=enp59s0f1np1
rep_of1(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }

# (re)create 2 VFs in switchdev
if [ ! -e /sys/bus/pci/devices/$PF1/virtfn1 ]; then
  sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null; sleep 2
  sudo -n devlink dev eswitch set pci/$PF1 mode switchdev 2>/dev/null; sleep 1
  sudo -n ethtool -K $IF1 hw-tc-offload on 2>/dev/null
  sudo -n sh -c "echo 2 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF1/virtfn1 ] && break; sleep 1; done; sleep 3
fi
sudo -n ip link set $IF1 up 2>/dev/null
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn0))
CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn1))
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null
sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=$(rep_of1 0); crep=$(rep_of1 1)
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
hw=$(sudo -n tc filter show dev $srep ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1)
echo "INTRA_SVF=$SVF"; echo "INTRA_CVF=$CVF"; echo "SREP=$srep CREP=$crep TC=$hw"

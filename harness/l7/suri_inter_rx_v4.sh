#!/bin/bash
# v4: Suricata single-iface IDS (copy-mode none + copy-iface none) + default template. reuse none=8264880.
set +u
PF=0000:3b:00.0
PREP=/home/sungwoo/FINAL/harness/setup/host1_vf_prepare.sh
SURI=/home/sungwoo/FINAL/suricata/bin/suricata
SYAML=/home/sungwoo/FINAL/suricata/conf/suri_ips.yaml
SURILIB=/usr/local/lib/x86_64-linux-gnu
H1VFMAC=02:40:00:00:00:11
H2KEY=/home/sungwoo/FINAL/secrets/host2_key
H2=(ssh -i "$H2KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 9022 sungwoo@143.248.57.12)
QCOM=${QCOM:-/home/sungwoo/FINAL/l7/payloads/dnsq_com.bin}
NONE=8264880
R=/home/sungwoo/suri_inter_v4_$(date +%H%M%S); mkdir -p "$R"
log(){ echo "[$(date +%T)] $*" | tee -a "$R/log"; }

pkill -9 suricata 2>/dev/null; pkill -9 -x dperf 2>/dev/null; sleep 1
echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null; sleep 1
env VF_TTL=9000 bash "$PREP" > "$R/vf.log" 2>&1
VF=$(sed -n 's/^VF_BDF=//p' "$R/vf.log" | head -1)
IF=$(for n in /sys/bus/pci/devices/$PF/net/*; do basename "$n"; break; done 2>/dev/null)
ip link set "$IF" up 2>/dev/null
log "VF=$VF IF=$IF"
[ -z "$VF" ] && { log NOVF; exit 1; }

h2flood(){ "${H2[@]}" "env DUR=$1 CPU=18 PROTO=udp PAYLOAD_FILE=$QCOM KEEPALIVE=${KA:-20}us CPS=4000 CC=${CC:-10000} SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=/home/sungwoo/FINAL/traffic/dperf HIST_START=3 bash /home/sungwoo/FINAL/harness/setup/host2_auto_client_hist.sh"; }

Y="$R/suri_rx.yaml"
head -77 "$SYAML" > "$Y"   # through "  interfaces:"
blk(){
  echo "    - interface: $1"
  echo "      threads: 1"
  echo "      promisc: true"
  echo "      multicast: true"
  echo "      checksum-checks: false"
  echo "      checksum-checks-offload: false"
  echo "      mtu: 1500"
  echo "      mempool-size: 65535"
  echo "      mempool-cache-size: 257"
  echo "      rx-descriptors: 1024"
  echo "      tx-descriptors: 1024"
  echo "      copy-mode: none"
  echo "      copy-iface: none"
}
{ blk "$VF"; blk default; } >> "$Y"

pkill -9 suricata 2>/dev/null; sleep 1
log "launch suricata on $VF"
env LD_LIBRARY_PATH=$SURILIB timeout 75 "$SURI" -c "$Y" --dpdk -l "$R" > "$R/suri.log" 2>&1 &
st=NO
for j in $(seq 1 50); do grep -qiE "engine started|Threads created" "$R/suri.log" 2>/dev/null && { st=YES; break; }; grep -qiE "could not be parsed|FATAL|initialization failed" "$R/suri.log" 2>/dev/null && break; sleep 1; done
log "started=$st"
if [ "$st" != YES ]; then grep -iE "error|fatal|parsed|mlx5|interface|eal|probe|rss" "$R/suri.log" | tail -12 | tee -a "$R/log"; pkill -9 suricata; echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs; log "SURI=FAIL"; exit 0; fi
sleep 3; log "host2 flood 30s"; h2flood 30 > "$R/h2c.out" 2>&1; sleep 2
pkill -9 suricata; sleep 3
python3 - "$R/stats.log" <<'PY' | tee -a "$R/log"
import sys,re
try: t=open(sys.argv[1]).read()
except: print("NO_STATS"); sys.exit()
def series(name):
    v=[]
    for ln in t.splitlines():
        if re.search(r'\b'+re.escape(name)+r'\b',ln) and 'Total' in ln:
            m=re.findall(r'(\d+)\s*$',ln.strip())
            if m: v.append(int(m[0]))
    return v
for nm in ("decoder.pkts","capture.kernel_packets","dpdk.pkts","decoder.udp","app_layer.tx.dns_udp","app_layer.flow.dns_udp"):
    v=series(nm)
    if len(v)>=2:
        d=[(v[i+1]-v[i])/5.0 for i in range(len(v)-1)]
        print(f"{nm}: peak/s={max(d):.0f} last={v[-1]} n={len(v)}")
    elif v: print(f"{nm}: {v}")
PY
AL=$(grep -ac '"event_type":"alert"' "$R/eve.json" 2>/dev/null); log "alerts=$AL"
echo "=== stats.log raw (decoder.pkts/capture) ===" | tee -a "$R/log"
grep -aE "decoder.pkts|kernel_packets|dpdk.pkts" "$R/stats.log" 2>/dev/null | tail -12 | tee -a "$R/log"
echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs 2>/dev/null
log "DONE dir=$R NONE_RX=$NONE"

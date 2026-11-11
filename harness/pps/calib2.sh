#!/bin/bash
PF_INTRA=0000:3b:00.1; IF_INTRA=enp59s0f1np1
DNS=/home/sungwoo/FINAL/traffic/dperf_dns
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
ROOT=/home/sungwoo/calib2_$(date +%H%M%S); mkdir -p "$ROOT"; RES="$ROOT/RES.txt"; : > "$RES"
KILL1(){ sudo pkill -9 -x dperf 2>/dev/null; sleep 1; }
SVF=0000:3b:01.3; CVF=0000:3b:01.4   # reuse VFs already up from prior calib
SIP=192.168.91.1; CIP=192.168.91.2; SMAC=02:50:00:00:01:01; CMAC=02:50:00:00:01:02
ss_avg(){ # average of non-zero pktRx seconds after ramp (skip first 5 data secs)
  grep -aE "^pktRx" "$1" | awk "{v=\$2; gsub(/,/,\"\",v); a[n++]=v} END{s=0;c=0; for(i=5;i<n;i++){s+=a[i];c++} if(c>0) printf \"%d\", s/c; else print \"NA\"}"; }
mx(){ grep -aoE "$2 +[0-9,]+" "$1"|grep -oE "[0-9,]+$"|tr -d ,|sort -n|tail -1; }
cell(){ KA=$1; d="$ROOT/ka${KA}"; mkdir -p "$d"; KILL1
  cat > "$d/server.conf" <<C
mode server
tx_burst 128
cpu 6
duration 30s
payload_size 1400
protocol udp
keepalive ${KA}us
socket_mem 2048
port $SVF $SIP $CIP $CMAC
client $CIP 1
server $SIP 1
listen 9 1
C
  cat > "$d/client.conf" <<C
mode client
tx_burst 128
cpu 16
duration 26s
payload_size 1400
protocol udp
cps 4000
cc 10000
keepalive ${KA}us
socket_mem 0,2048
port $CVF $CIP $SIP $SMAC
client $CIP 1
server $SIP 1
listen 9 1
C
  sudo env LD_LIBRARY_PATH=$LIB timeout 40 "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 2
  sudo env LD_LIBRARY_PATH=$LIB timeout 32 "$DNS" -c "$d/client.conf" > "$d/client.log" 2>&1 & sleep 30
  KILL1
  echo "ka=${KA}us offered_max=$(mx "$d/client.log" pktTx) delivered_max=$(mx "$d/server.log" pktRx) delivered_ssavg=$(ss_avg "$d/server.log")" | tee -a "$RES"
}
echo "=== CALIB2 (25s steady-state) $(date) ===" | tee -a "$RES"
cell 20     # saturate
cell 800    # expect offered ~2M (1.6e9/800)
KILL1
echo "=== DONE ===" | tee -a "$RES"

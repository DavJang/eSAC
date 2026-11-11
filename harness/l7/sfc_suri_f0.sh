#!/bin/bash
set +u
CASE=${1:-pass}
SURI=/home/sungwoo/FINAL/suricata/bin/suricata
YAML=/home/sungwoo/FINAL/suricata/conf/suri_ips_f0.yaml
DSRV=/home/sungwoo/FINAL/traffic/dperf_probe
DCLI=/home/sungwoo/FINAL/traffic/dperf_dns
CLL=/home/sungwoo/FINAL/lib/dpdk-24.11/lib:/home/sungwoo/FINAL/lib/dpdk-24.11/drivers
SURILIB=/usr/local/lib/x86_64-linux-gnu
V0=0000:3b:00.3; V3=0000:3b:00.6
CMAC=02:60:00:00:00:01; SMAC=02:60:00:00:00:04
PB=${PB:-64}; Q=/home/sungwoo/FINAL/l7/payloads/dnsq_com_$(printf %04d $PB).bin; [ "$CASE" = drop ] && Q=/home/sungwoo/FINAL/l7/payloads/dnsq_su_$(printf %04d $PB).bin
R=/home/sungwoo/suri_run_${CASE}_$(date +%H%M%S); mkdir -p "$R"
sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 suricata 2>/dev/null; sleep 2
for r in eth0 eth1 eth2 eth3; do sudo -n tc qdisc del dev $r ingress 2>/dev/null; sudo -n tc qdisc add dev $r ingress 2>/dev/null; done
sudo -n tc filter add dev eth0 ingress protocol all flower skip_sw action mirred egress redirect dev eth1
sudo -n tc filter add dev eth1 ingress protocol all flower skip_sw action mirred egress redirect dev eth0
sudo -n tc filter add dev eth2 ingress protocol all flower skip_sw action mirred egress redirect dev eth3
sudo -n tc filter add dev eth3 ingress protocol all flower skip_sw action mirred egress redirect dev eth2
cat > "$R/server.conf" <<C
mode server
tx_burst 32
cpu 6
duration 50s
payload_size ${PB:-64}
protocol udp
keepalive ${KA:-20}us
socket_mem 1024
port $V3 192.168.1.1 192.168.0.1 $CMAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
rss
C
cat > "$R/client.conf" <<C
mode client
tx_burst 32
cpu 16
duration 28s
payload_file $Q
protocol udp
cps 4000
cc ${CC:-10000}
keepalive ${KA:-20}us
socket_mem 0,512
port $V0 192.168.0.1 192.168.1.1 $SMAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
rss
C
# ---- launch Suricata DPDK IPS (binds vf1=nfA, vf2=nfB) ----
sudo -n env LD_LIBRARY_PATH=$SURILIB timeout 75 $SURI -c $YAML --dpdk -l "$R" >"$R/suri.log" 2>&1 &
rdy=NO
for j in $(seq 1 45); do grep -qiE "engine started" "$R/suri.log" 2>/dev/null && { rdy=YES; break; }; sleep 1; done
echo "suri_ready=$rdy"
grep -iE "mlx5|ethdev|no supported|error|warning: dpdk" "$R/suri.log" | head -5
[ "$rdy" != YES ] && { echo "SURI_FAIL"; tail -20 "$R/suri.log"; echo "RDIR=$R"; exit 1; }
# ---- server ----
sudo -n timeout 55 $DSRV -c "$R/server.conf" >"$R/server.log" 2>&1 &
sleep 8
# ---- client ----
sudo -n env LD_LIBRARY_PATH=$CLL timeout 32 $DCLI -c "$R/client.conf" >"$R/client.log" 2>&1 &
sleep 30
sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -INT suricata 2>/dev/null; sleep 4
spps=$(grep -aE "^pktRx" "$R/server.log" 2>/dev/null|awk "{print \$2}"|tr -d ,|awk "\$1>0"|sort -n|awk "{a[NR]=\$1} END{if(NR)print a[int((NR+1)/2)]; else print 0}")
cpt=$(grep -aE "^pktTx" "$R/client.log" 2>/dev/null|awk "{print \$2}"|tr -d ,|awk "\$1>0"|sort -n|tail -1)
echo "CASE=$CASE server_pps_median=${spps:-0} client_pktTx_peak=${cpt:-0}"
echo "--- suricata capture/drop stats ---"
grep -aE "capture.packets|capture.kernel_drops|dpdk.*packets|decoder.pkts|detect.alert|drop" "$R/stats.log" 2>/dev/null | tail -20
echo "--- fast.log alerts (count + sample) ---"
wc -l "$R/fast.log" 2>/dev/null; head -3 "$R/fast.log" 2>/dev/null
echo "--- eve alerts ---"
grep -c "\"event_type\":\"alert\"" "$R/eve.json" 2>/dev/null
echo "RDIR=$R"
echo SURIRUNDONE

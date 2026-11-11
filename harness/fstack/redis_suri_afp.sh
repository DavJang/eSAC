#!/bin/bash
# Suricata af-packet IPS inline on kernel redis (reliable: netns+veth, NO HW offload so Suricata
# sees EVERY packet). Two netns connected ONLY through the host's two veth ends:
#   rcli(redis-benchmark, 10.9.0.1) -vc_ns-|-vc_host- [Suricata af-packet ips] -vs_host-|-vs_ns- rsrv(redis, 10.9.0.2)
# Modes: none = Linux bridge joins vc_host+vs_host (direct). suri = Suricata bridges them (inline IPS).
# Shows: (1) throughput none vs suri, (2) Suricata DETECTS+DROPS a bad command ("badkey"), serves normal.
set +u
SURILD=/home/sungwoo/FINAL/suricata/lib:/usr/local/lib/x86_64-linux-gnu
SURI=/home/sungwoo/FINAL/suricata/bin/suricata
OUT=/home/sungwoo/FINAL/results/redis_suri_afp_$(date +%s); mkdir -p "$OUT"; R="$OUT/RESULT.txt"; : > "$R"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$R"; }
SIP=10.9.0.2; CIP=10.9.0.1
RBOPTS="-h $SIP -p 6379 -t set,get -n 50000 -c 50 -P 16 -d 32 --csv"

cleanup(){ sudo -n pkill -9 -i suricata 2>/dev/null; sudo -n ip netns pids rsrv 2>/dev/null | xargs -r sudo -n kill -9 2>/dev/null
  sudo -n ip link del br_rs 2>/dev/null; sudo -n ip link del vc_host 2>/dev/null; sudo -n ip link del vs_host 2>/dev/null
  sudo -n ip netns del rcli 2>/dev/null; sudo -n ip netns del rsrv 2>/dev/null
  sudo -n find /dev/hugepages -maxdepth 1 -name "surimap_*" -delete 2>/dev/null
  say "cleanup done"; echo EXP_DONE >> "$R"; }
trap cleanup EXIT
cleanup 2>/dev/null; sleep 1

# ---- build the two-netns + 2 veth topology ----
sudo -n ip netns add rcli; sudo -n ip netns add rsrv
sudo -n ip link add vc_host type veth peer name vc_ns
sudo -n ip link add vs_host type veth peer name vs_ns
sudo -n ip link set vc_ns netns rcli; sudo -n ip link set vs_ns netns rsrv
sudo -n ip netns exec rcli ip addr add $CIP/24 dev vc_ns; sudo -n ip netns exec rcli ip link set vc_ns up; sudo -n ip netns exec rcli ip link set lo up
sudo -n ip netns exec rsrv ip addr add $SIP/24 dev vs_ns; sudo -n ip netns exec rsrv ip link set vs_ns up; sudo -n ip netns exec rsrv ip link set lo up
sudo -n ip link set vc_host up; sudo -n ip link set vs_host up
# disable all offloads (veth placeholder checksums break af-packet IPS forwarding -> redis drops frames)
for IFX in vc_host vs_host; do sudo -n ethtool -K $IFX tx off rx off tso off gso off gro off lro off 2>/dev/null; done
sudo -n ip netns exec rcli ethtool -K vc_ns tx off rx off tso off gso off gro off 2>/dev/null
sudo -n ip netns exec rsrv ethtool -K vs_ns tx off rx off tso off gso off gro off 2>/dev/null
# static ARP both ways (so no ARP needed; peers resolve through the bridge/suricata)
CMAC=$(sudo -n ip netns exec rcli cat /sys/class/net/vc_ns/address); SMAC=$(sudo -n ip netns exec rsrv cat /sys/class/net/vs_ns/address)
sudo -n ip netns exec rcli ip neigh replace $SIP lladdr $SMAC dev vc_ns
sudo -n ip netns exec rsrv ip neigh replace $CIP lladdr $CMAC dev vs_ns
say "topology up: rcli($CIP/$CMAC) <-vc-> [mid] <-vs-> rsrv($SIP/$SMAC)"

# ---- redis-server in rsrv ----
sudo -n ip netns exec rsrv /usr/bin/redis-server --bind $SIP --port 6379 --save '' --appendonly no --daemonize yes --logfile "$OUT/redis.log" --protected-mode no
sleep 2; say "redis in rsrv: $(sudo -n ip netns exec rsrv /usr/bin/redis-cli -h $SIP ping 2>&1)"

bench(){ sudo -n ip netns exec rcli /usr/bin/redis-benchmark $RBOPTS 2>/dev/null | grep -E '^"(SET|GET)"'; }
setk(){ timeout 5 sudo -n ip netns exec rcli /usr/bin/redis-cli -h $SIP set "$1" V 2>&1; }

# ================= MODE none: Linux bridge (direct) =================
sudo -n ip link add br_rs type bridge; sudo -n ip link set vc_host master br_rs; sudo -n ip link set vs_host master br_rs; sudo -n ip link set br_rs up
sleep 1
say "===== none (Linux bridge, no inspection) ====="
say "  badkey set (expect OK, no block): $(setk badkey)"
say "  throughput: $(bench | tr '\n' ' ')"
sudo -n ip link set vc_host nomaster 2>/dev/null; sudo -n ip link set vs_host nomaster 2>/dev/null; sudo -n ip link del br_rs 2>/dev/null; sleep 1

# ================= MODE suri: Suricata af-packet IPS =================
cat > "$OUT/suri.yaml" <<YAML
%YAML 1.1
---
default-log-dir: $OUT
outputs:
  - stats: {enabled: yes, filename: stats.log, interval: 5}
af-packet:
  - interface: vc_host
    threads: 1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    copy-mode: ips
    copy-iface: vs_host
  - interface: vs_host
    threads: 1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    copy-mode: ips
    copy-iface: vc_host
default-rule-path: $OUT
rule-files:
  - redis.rules
YAML
# rule: DROP any TCP payload to redis containing "badkey"; everything else passes.
echo 'drop tcp any any -> any 6379 (msg:"BLOCK redis badkey"; content:"badkey"; sid:1000001; rev:1;)' > "$OUT/redis.rules"
sudo -n env LD_LIBRARY_PATH=$SURILD setsid "$SURI" -c "$OUT/suri.yaml" --af-packet > "$OUT/suri.log" 2>&1 < /dev/null & disown
for j in $(seq 1 40); do grep -qiE "Engine started|All AFP capture threads" "$OUT/suri.log" 2>/dev/null && break; sleep 1; done
say "===== Suricata af-packet IPS (inline) ====="
say "  suricata: $(grep -aiE 'Engine started|rules.*loaded|1 rule|error' "$OUT/suri.log" | tail -2 | tr '\n' ';')"
sleep 2
say "  goodkey set (expect OK, served): $(setk goodkey)"
say "  badkey set  (expect BLOCKED/timeout by Suricata): $(setk badkey)"
say "  throughput (normal SET/GET through Suricata): $(bench | tr '\n' ' ')"
say "  suricata: processed=$(grep -a 'capture.packets' "$OUT/stats.log" 2>/dev/null | grep Total | tail -1 | grep -oE '[0-9]+$')  drops(alert)=$(grep -a 'detect.alert' "$OUT/stats.log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')"
say "DONE OUT=$OUT"

#!/bin/bash
# eSAC L7 on real f-stack Redis: GET vs SET discrimination by PAYLOAD CONTENT (Hyperscan).
# Same 5-tuple / same L4 ALLOW policy -> only L7 (RESP verb) decides ALLOW/DROP.
# INLINE redis commands (start w/ uppercase -> existing hs_gate HTTP-shape branch scans them; no recompile).
set -u
D=/home/sungwoo/FINAL
AGENT=$D/agent/libbpftime-agent-hs.so
HS_LIB=$D/l7/ctl/esac_hs_ufunc.so
SERVER=$D/agent/libbpftime-syscall-server.so
LOADER=$D/comm_plane/loaders/comm_loader_rxonly
COMBO=$D/comm_plane/bpf/comm_filter_maskprobe_16k_hs_gate.bpf.o
REDIS=$D/apps/redis/redis-server
OFFS=$D/comm_plane/offsets.json
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf
INI=$D/apps/redis/ff_redis_sw.ini
SVF=0000:3b:01.3; IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1
OUT=$D/results/fstack_l7rx_$(date +%s); mkdir -p "$OUT"; say(){ echo "[$(date +%H:%M:%S)] $*"; }
PATFILE=$OUT/redis_patterns.txt; printf 'SET:drop
' > "$PATFILE"

sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" "$D/apps/redis/ff_redis.ini" > "$INI"
sudo -n ip link set $IF1 up 2>/dev/null
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null; sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=; crep=; for n in /sys/class/net/*; do p=$(cat $n/phys_port_name 2>/dev/null); [ "$p" = pf1vf0 ] && srep=$(basename $n); [ "$p" = pf1vf1 ] && crep=$(basename $n); done
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null
say "switchdev+hairpin ready (srep=$srep crep=$crep); pattern=SET:drop"

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

boot_sc(){ local POL=$1; local RPID=$OUT/rpid
  cd "$D/apps/redis"; local SHM=esac_ffredis_$(date +%s%N)
  sudo -n setsid bash -c "echo \$\$ > $RPID; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM ESAC_HS_PATTERNS=$PATFILE LD_PRELOAD=$AGENT:$HS_LIB LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
  sleep 2; local PID=$(cat $RPID 2>/dev/null); [ -z "$PID" ] && { echo ""; return; }
  local CG=/sys/fs/cgroup/esac_ffredis_$PID; sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$PID"|sudo -n tee "$CG/cgroup.procs">/dev/null
  local CGID=$(stat -c %i "$CG"); sed "s/__CGID__/$CGID/g" "$POL" > "$OUT/policy_active.json"; python3 "$D/tamper_sentinel/esac_pidcg_verify.py" init "$PID" "$CG" "$OUT/identity.json" >> "$OUT/idlog" 2>&1 || true
  sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" "$LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "$OFFS" --policy "$OUT/policy_active.json" --no-pin --enforcement --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
  local j; for j in $(seq 1 45); do grep -q 'attach summary: RX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
  sudo -n kill -CONT $PID
  for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
  echo $PID; }

pyc(){ python3 -c "
import socket,sys
cmd=sys.argv[1]+'\r\n'
s=socket.socket(); s.settimeout(5)
try:
  s.connect((sys.argv[2],6379)); s.sendall(cmd.encode())
  try: print('REPLY',repr(s.recv(256)))
  except socket.timeout: print('TIMEOUT(blocked)')
except Exception as e: print('ERR',e)
" "$1" "$SIP"; }
drops(){ grep -aE '^[0-9]+ +[0-9]+ ' "$OUT/loader.log"|tail -1; }

printf '{"rules":[{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":6379,"action":"ALLOW"}]}\n' > "$OUT/pol_allow.json"

say "===== L7 GET/SET on f-stack Redis (L4=ALLOW 6379 both; L7 pattern SET:drop) ====="
clean; pid=$(boot_sc "$OUT/pol_allow.json"); say "redis+eSAC-L7 up pid=$pid"
[ -z "$pid" ] && { say "BOOT FAILED"; tail -8 "$OUT/loader.log" 2>/dev/null; tail -8 "$OUT/redis.log" 2>/dev/null; exit 1; }
say "attach: $(grep -a 'attach summary' "$OUT/loader.log"|tail -1)"
say "--- GET (expect REPLY = ALLOWED) ---"; say "GET  => $(pyc 'GET democtl')"
say "--- SET (expect TIMEOUT = BLOCKED by L7) ---"; say "SET  => $(pyc 'SET democtl v1')"
say "--- GET again (still ALLOWED) ---"; say "GET  => $(pyc 'GET democtl')"
sudo -n kill -USR1 $(pgrep -f '[c]omm_loader'|head -1) 2>/dev/null; sleep 1; say "loader L7 stats: $(drops)"
sudo -n kill -9 "$pid" 2>/dev/null; clean
say "DONE OUT=$OUT"

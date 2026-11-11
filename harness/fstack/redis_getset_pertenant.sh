#!/bin/bash
# eSACfinal: PER-TENANT Redis GET/SET L7 enforcement on REAL f-stack Redis (intra switchdev).
#   Tenant WEB   = GET-only  -> comm_filter_opt3_16k_blockset.bpf.o : SET dropped at RX, GET served
#   Tenant CACHE = full      -> comm_filter_maskprobe_16k.bpf.o      : both served
#   Tenant LOG   = SET-only  -> comm_filter_opt3_16k_blockget.bpf.o : GET dropped at RX, SET served
# STOP/CONT pre-attach per PID (attach while redis STOPPED, before EAL/PMD poll).
# Client = kernel redis-cli over client VF (enp59s0f1v1 192.168.1.2) -> switchdev hairpin -> server VF.
# Verb scan is CASE-SENSITIVE on upper 'SET'/'GET' -> client must send UPPERCASE verbs.
set -u
D=/home/sungwoo/FINAL
AGENT=$D/agent/libbpftime-agent.so
SERVER=$D/agent/libbpftime-syscall-server.so
LOADER=$D/comm_plane/loaders/comm_loader_cgroup_maskprobe
BASE=$D/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
BLOCKSET=$D/comm_plane/bpf/comm_filter_opt3_16k_blockset.bpf.o
BLOCKGET=$D/comm_plane/bpf/comm_filter_opt3_16k_blockget.bpf.o
REDIS=$D/apps/redis/redis-server
OFFS=$D/comm_plane/offsets.json
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf
INI=$D/apps/redis/ff_redis_sw.ini
SVF=0000:3b:01.3; IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1
OUT=$D/results/redis_getset_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

# ---- switchdev + hairpin + client IP (idempotent) ----
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
say "switchdev+hairpin ready (srep=$srep crep=$crep)"

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

# ALLOW-6379 policy template (verb-drop is additive inside the filter)
printf '{"rules":[{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":6379,"action":"ALLOW"}]}\n' > "$OUT/pol_allow.json"

# boot_sc <combo.bpf.o> -> echoes redis pid (STOP/CONT pre-attached + enforcing)
boot_sc(){ local COMBO=$1; local RPID=$OUT/rpid
  cd "$D/apps/redis"
  local SHM=esac_ffredis_$(date +%s%N)
  sudo -n setsid bash -c "echo \$\$ > $RPID; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=$AGENT LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
  sleep 2; local PID=$(cat $RPID 2>/dev/null); [ -z "$PID" ] && { echo ""; return; }
  local CG=/sys/fs/cgroup/esac_ffredis_$PID; sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$PID"|sudo -n tee "$CG/cgroup.procs">/dev/null
  local CGID=$(stat -c %i "$CG"); sed "s/__CGID__/$CGID/g" "$OUT/pol_allow.json" > "$OUT/policy_active.json"
  sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD="$SERVER" "$LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "$OFFS" --policy "$OUT/policy_active.json" --no-pin --enforcement --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
  local j; for j in $(seq 1 45); do grep -q 'attach summary: RX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
  sudo -n kill -CONT $PID
  for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
  echo $PID; }

rc(){ timeout 6 /usr/bin/redis-cli -h $SIP -p 6379 "$@" 2>&1; }
drops(){ sudo -n kill -USR1 $(pgrep -f '[c]omm_loader'|head -1) 2>/dev/null; sleep 1; grep -aE '^[0-9]+ +[0-9]+ ' "$OUT/loader.log"|tail -1; }

run_tenant(){ local NAME=$1 COMBO=$2 EXPGET=$3 EXPSET=$4
  clean; local pid=$(boot_sc "$COMBO")
  say "===== TENANT $NAME (combo=$(basename $COMBO)) redis pid=$pid ====="
  [ -z "$pid" ] && { say "  BOOT FAIL"; return; }
  local rping=$(rc PING)
  local rget=$(rc GET gkey)
  local rsetv=$(rc SET skey vval)
  say "  PING => '$rping'"
  say "  GET gkey => '$rget'    (expect: $EXPGET)"
  say "  SET skey vval => '$rsetv'    (expect: $EXPSET)"
  say "  loader stats: $(drops)"
  grep -aE 'ACT_DROP|insp_drop|DROP .*TCP|6379' "$OUT/loader.log" 2>/dev/null | tail -3 | sed 's/^/    log: /'
  sudo -n kill -9 "$pid" 2>/dev/null; clean
  echo "KEY tenant=$NAME combo=$(basename $COMBO) ping='$rping' get='$rget' set='$rsetv'"; }

say "################ PER-TENANT GET/SET ENFORCEMENT (real f-stack Redis) ################"
run_tenant WEB   "$BLOCKSET" "served(value or nil)" "BLOCKED(timeout/empty)"
run_tenant CACHE "$BASE"     "served(value or nil)" "served(OK)"
run_tenant LOG   "$BLOCKGET" "BLOCKED(timeout/empty)" "served(OK)"
say "################ DONE OUT=$OUT ################"

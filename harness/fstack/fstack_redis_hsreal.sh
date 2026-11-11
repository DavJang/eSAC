#!/bin/bash
# REAL Hyperscan L7 on f-stack Redis: in-BPF payload scan via the agent's BUILT-IN esac_hs_scan ufunc.
# comm_filter_opt3_16k_hsreal.bpf.o calls esac_hs_scan(payload_ptr,len) at RX; match(ESAC_HS_PATTERNS) -> ACT_DROP.
# RX-only loader (responses never hooked -> no TX-leg drop). Pattern = "SET" (inline redis cmd).
# Expect: PING/GET served; SET blocked (timeout) by Hyperscan.
set -u
D=/home/sungwoo/FINAL
AGENT=$D/agent/libbpftime-agent-hs.so        # HS-enabled agent
HS_LIB=$D/l7/ctl/esac_hs_ufunc.so            # external .so provides esac_hs1 (we control + ESAC_HS_PATTERNS)
SERVER=$D/agent/libbpftime-syscall-server.so
LOADER=$D/comm_plane/loaders/comm_loader_cgroup_burst   # burst loader enables the ufunc dispatcher
COMBO=$D/comm_plane/bpf/comm_filter_opt3_16k_hsreal.bpf.o
REDIS=$D/apps/redis/redis-server
OFFS=$D/comm_plane/offsets.json
FFLIB=$D/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
CONF=$D/apps/redis/ff_redis.conf; INI=$D/apps/redis/ff_redis_sw.ini
SVF=0000:3b:01.3; IF1=enp59s0f1np1; CVF_NET=enp59s0f1v1; CIP=192.168.1.2; SIP=192.168.1.1
PAT=${PAT:-SET}
OUT=$D/results/redis_hsreal_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

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
say "switchdev+hairpin ready; Hyperscan pattern=\"$PAT\""

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f '[c]omm_loader' 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }
trc(){ local t0=$(date +%s%3N); local v; v=$(timeout 6 /usr/bin/redis-cli -h $SIP -p 6379 "$@" 2>/dev/null); local ec=$?; local t1=$(date +%s%3N); printf 'val="%s"|exit=%s|ms=%s' "$v" "$ec" "$((t1-t0))"; }

printf '{"rules":[{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":__CGID__,"dst_ip":"192.168.1.2","proto":6,"dst_port":0,"action":"ALLOW"}]}\n' > "$OUT/pol_allow.json"

clean
cd "$D/apps/redis"; SHM=esac_ffredis_$(date +%s%N); RPID=$OUT/rpid
sudo -n setsid bash -c "echo \$\$ > $RPID; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM ESAC_HS_PATTERNS=$PAT LD_PRELOAD=$AGENT:$HS_LIB LD_LIBRARY_PATH=$FFLIB $REDIS $CONF --conf $INI --proc-type=primary --proc-id=0" > "$OUT/redis.log" 2>&1 </dev/null & disown
sleep 2; PID=$(cat $RPID)
CG=/sys/fs/cgroup/esac_ffredis_$PID; sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$PID"|sudo -n tee "$CG/cgroup.procs">/dev/null
CGID=$(stat -c %i "$CG"); sed "s/__CGID__/$CGID/g" "$OUT/pol_allow.json" > "$OUT/policy_active.json"
sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD="$SERVER" "$LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "$OFFS" --policy "$OUT/policy_active.json" --no-pin --enforcement --attach-pid "$PID" -v > "$OUT/loader.log" 2>&1 &
for j in $(seq 1 45); do grep -q 'attach summary: RX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
sudo -n kill -CONT $PID
for j in $(seq 1 30); do grep -q 'Ready to accept' "$OUT/redis.log" 2>/dev/null && break; sleep 1; done
say "redis+eSAC-HS up pid=$PID  attach=$(grep -a 'attach summary' "$OUT/loader.log"|tail -1)"
say "hs compiled: $(grep -a 'esac_hs' "$OUT/redis.log" | tail -1)"
say "  PING        -> $(trc PING)       (expect served)"
say "  GET k       -> $(trc GET k)      (expect served, no SET in payload)"
say "  SET k HELLO -> $(trc SET k HELLO)(expect BLOCKED ~6000ms/exit124 by Hyperscan)"
say "  GET k again -> $(trc GET k)      (expect served; if nil, SET never stored = blocked)"
sudo -n kill -USR1 $(pgrep -f '[c]omm_loader'|head -1) 2>/dev/null; sleep 1
say "  drops6379: $(grep -ac 'ACT_DROP.*6379' "$OUT/loader.log" 2>/dev/null) sample: $(grep -a 'ACT_DROP.*6379' "$OUT/loader.log"|tail -1|sed 's/.*tuple=/tuple=/')"
sudo -n kill -9 "$PID" 2>/dev/null; clean
say "DONE OUT=$OUT"

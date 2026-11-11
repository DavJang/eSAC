#!/bin/bash
# Q4 Redis on mlx5 40G SWITCHDEV (PF1), none vs eSAC(esac). Client = LOCAL kernel redis-benchmark
# on CVF enp59s0f1v1 (192.168.1.2), reaching f-stack redis on SVF 3b:01.3 (192.168.1.1) via HW tc hairpin.
set -u
R=/home/sungwoo/FINAL
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent.so
SERVER=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
COMBO=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
REDIS=/home/sungwoo/FINAL/apps/redis/redis-server
FFLIB=/home/sungwoo/FINAL/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
INI=/home/sungwoo/FINAL/apps/redis/ff_redis_sw.ini
RBOPTS="-h 192.168.1.1 -p 6379 -t set,get -n 300000 -c 50 -P 16 -d 32 --csv"
RB="/usr/bin/redis-benchmark $RBOPTS"
PF1=0000:3b:00.1; IF1=enp59s0f1np1; SVF=0000:3b:01.3; CVF_NET=enp59s0f1v1; CIP=192.168.1.2
OUT=/home/sungwoo/FINAL/results/l7perf40_$(date +%s); mkdir -p "$OUT"; echo "$OUT">/home/sungwoo/FINAL/results/.l7perf40_dir
RES=$OUT/results.tsv; printf 'mode\trep\ttest\trps\tavg_ms\tp50_ms\tp99_ms\n' > "$RES"
LOG=$OUT/log; echo "start $(date) OUT=$OUT" > "$LOG"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ---- ensure switchdev VFs + macs + HW hairpin + client IP (idempotent) ----
sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" /home/sungwoo/FINAL/apps/redis/ff_redis.ini > "$INI"
sudo -n ip link set $IF1 up 2>/dev/null
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null
sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=; crep=
for n in /sys/class/net/*; do p=$(cat $n/phys_port_name 2>/dev/null); [ "$p" = pf1vf0 ] && srep=$(basename $n); [ "$p" = pf1vf1 ] && crep=$(basename $n); done
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
hw=$(sudo -n tc filter show dev $srep ingress 2>/dev/null | grep -oE 'in_hw|not_in_hw' | head -1)
sudo -n ip addr flush dev $CVF_NET 2>/dev/null; sudo -n ip addr add $CIP/24 dev $CVF_NET 2>/dev/null; sudo -n ip link set $CVF_NET up 2>/dev/null
say "switchdev ready: srep=$srep crep=$crep hairpin=$hw client=$CVF_NET/$CIP"

clean(){ sudo -n pkill -9 -x redis-server 2>/dev/null; sudo -n pkill -9 -f comm_loader 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ffredis_*; do sudo -n rmdir "$cg" 2>/dev/null; done
  sudo -n rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

boot_none(){ cd /home/sungwoo/FINAL/apps/redis
  sudo -n setsid env -u LD_PRELOAD LD_LIBRARY_PATH="$FFLIB" "$REDIS" /home/sungwoo/FINAL/apps/redis/ff_redis.conf --conf "$INI" --proc-type=primary --proc-id=0 > "$OUT/redis_none.log" 2>&1 </dev/null & echo $!; }

boot_esac(){ cd /home/sungwoo/FINAL/apps/redis
  export BPFTIME_GLOBAL_SHM_NAME=esac_ffredis_$(date +%s%N)
  # boot redis (root, mlx5 needs root) with agent; wait until it is serving, then attach loader.
  sudo -n setsid env BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$FFLIB" "$REDIS" /home/sungwoo/FINAL/apps/redis/ff_redis.conf --conf "$INI" --proc-type=primary --proc-id=0 > "$OUT/redis_esac.log" 2>&1 </dev/null & disown
  local srv j; for j in $(seq 1 30); do srv=$(pgrep -f "redis-server.*ff_redis_sw"|head -1); [ -n "$srv" ] && grep -q 'Ready to accept' "$OUT/redis_esac.log" 2>/dev/null && break; sleep 1; done
  [ -z "$srv" ] && { say "eSAC redis pid not found"; echo ""; return; }
  local CG=/sys/fs/cgroup/esac_ffredis_${srv}
  sudo -n mkdir -- "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$srv"|sudo -n tee "$CG/cgroup.procs" >/dev/null
  local CGID=$(stat -c %i "$CG")
  printf '{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.1","proto":6,"dst_port":6379,"action":"ALLOW"},{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.2","proto":6,"dst_port":6379,"action":"ALLOW"}]}\n' "$CGID" "$CGID" > "$OUT/policy.json"
  sudo -n env BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info BPFTIME_GLOBAL_SHM_NAME="$BPFTIME_GLOBAL_SHM_NAME" LD_PRELOAD="$SERVER" "/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup" --bpf "$COMBO" --lib "$REDIS" --pmd-lib "$REDIS" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$srv" -v > "$OUT/loader.log" 2>&1 &
  for j in $(seq 1 45); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
  grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && say "esac attach OK" || say "eSAC_ATTACH_FAIL (see loader.log)"
  echo $srv; }

wait_ready(){ local lg=$1 j; for j in $(seq 1 30); do grep -q 'Ready to accept' "$lg" 2>/dev/null && return 0; sleep 1; done; return 1; }

bench(){ local mode=$1 rep=$2
  $RB > "$OUT/bench_${mode}_${rep}.csv" 2>"$OUT/bench_${mode}_${rep}.err"
  grep -E '^"(SET|GET)"' "$OUT/bench_${mode}_${rep}.csv" | while IFS=',' read t rps avg mn p50 p95 p99 mx; do
    t=${t//\"/}; rps=${rps//\"/}; avg=${avg//\"/}; p50=${p50//\"/}; p99=${p99//\"/}
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$rep" "$t" "$rps" "$avg" "$p50" "$p99" >> "$RES"
  done
  say "[$mode r$rep] $(grep -E '^\"(SET|GET)\"' "$OUT/bench_${mode}_${rep}.csv" | tr '\n' ' ')"; }

for mode in none esac; do
  clean
  if [ "$mode" = none ]; then srv=$(boot_none); LG=$OUT/redis_none.log; else srv=$(boot_esac); LG=$OUT/redis_esac.log; fi
  if wait_ready "$LG"; then sleep 2
    for rep in 1 2 3; do bench "$mode" "$rep"; sleep 1; done
  else say "[$mode] REDIS_NOT_READY"; tail -15 "$LG" >> "$LOG"; fi
  sudo -n kill -9 "$srv" 2>/dev/null; clean
done
say "=== RESULTS (median rps) ==="
awk -F'\t' 'NR>1{k=$1"_"$3; a[k]=a[k]" "$4} END{for(k in a){n=split(a[k],v," ");for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(v[i]+0>v[j]+0){t=v[i];v[i]=v[j];v[j]=t}; m=(n%2)?v[(n+1)/2]:(v[n/2]+v[n/2+1])/2; printf "%-12s median_rps=%s (n=%d)\n",k,m,n}}' "$RES" | tee -a "$LOG"
touch "$OUT/.done"; say "DONE OUT=$OUT"

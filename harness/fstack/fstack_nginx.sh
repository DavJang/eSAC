#!/bin/bash
# Q4 nginx on mlx5 40G SWITCHDEV (PF1), none vs eSAC(esac). Client = LOCAL ab on CVF (192.168.1.2)
# -> f-stack nginx on SVF 3b:01.3 (192.168.1.1) via HW tc hairpin. esac attaches to nginx WORKER.
set -u
R=/home/sungwoo/FINAL
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent.so
SERVER=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
COMBO=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
NGINX=/home/sungwoo/FINAL/apps/nginx/sbin/nginx
BASECONF=/home/sungwoo/FINAL/apps/nginx/conf/nginx.conf
BASEFF=/home/sungwoo/FINAL/apps/nginx/conf/f-stack.conf
CONF=/home/sungwoo/FINAL/apps/nginx/conf/nginx_sw.conf
FFCONF=/home/sungwoo/FINAL/apps/nginx/conf/f-stack-sw.conf
ELOG=/home/sungwoo/FINAL/apps/nginx/logs/error.log
FFLIB=/home/sungwoo/FINAL/lib/fstack-dpdk:/usr/local/lib/x86_64-linux-gnu
AB='/usr/bin/ab -n 30000 -c 50 http://192.168.1.1/'
CURL='curl -s -m3 -o /dev/null -w %{http_code} http://192.168.1.1/'
PF1=0000:3b:00.1; IF1=enp59s0f1np1; SVF=0000:3b:01.3; CVF_NET=enp59s0f1v1; CIP=192.168.1.2
OUT=/home/sungwoo/FINAL/results/nginxperf40_$(date +%s); mkdir -p "$OUT"; echo "$OUT">/home/sungwoo/FINAL/results/.nginxperf40_dir
RES=$OUT/results.tsv; printf 'mode\trep\treq_per_s\tmean_ms\tp50_ms\tp99_ms\tfailed\n' > "$RES"
LOG=$OUT/log; echo "start $(date) OUT=$OUT" > "$LOG"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# --- switchdev config copies (allow mlx5 VF) ---
sed -e "s|--allow=0000:5e:00.1|--allow=$SVF|" "$BASEFF" > "$FFCONF"
sed -e "s|fstack_conf .*;|fstack_conf $FFCONF;|" -e 's/master_process off;/master_process on;/' "$BASECONF" > "$CONF"
grep -q 'master_process on;' "$CONF" || sed -i '1i master_process on;' "$CONF"
# --- ensure switchdev VFs + macs + hairpin + client IP (idempotent) ---
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
say "switchdev ready: hairpin=$hw client=$CVF_NET/$CIP conf=$CONF"

clean(){ sudo -n pkill -9 -x nginx 2>/dev/null; sudo -n pkill -9 -f comm_loader 2>/dev/null
  for cg in /sys/fs/cgroup/esac_ngxw_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/esac_ngx* /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 3; }

boot_none(){ : > "$ELOG"; sudo -n setsid env LD_LIBRARY_PATH="$FFLIB" "$NGINX" -c "$CONF" > "$OUT/nginx_none.log" 2>&1 </dev/null & disown
  echo $(pgrep -f 'nginx: master'|head -1); }

boot_esac(){ : > "$ELOG"; export BPFTIME_GLOBAL_SHM_NAME=esac_ngx_$(date +%s%N)
  sudo -n setsid env LD_PRELOAD="$AGENT" LD_LIBRARY_PATH="$FFLIB" "$NGINX" -c "$CONF" > "$OUT/nginx_esac.log" 2>&1 </dev/null & disown
  local j W; for j in $(seq 1 30); do grep -q 'register dpdk interface' "$ELOG" 2>/dev/null && break; sleep 1; done
  for j in $(seq 1 15); do W=$(pgrep -f 'nginx: worker'|head -1); [ -n "$W" ] && break; sleep 1; done
  say "esac worker=$W"
  local CG=/sys/fs/cgroup/esac_ngxw_$W; sudo -n mkdir "$CG" 2>/dev/null; sudo -n chmod 755 "$CG"; printf '%s\n' "$W"|sudo -n tee "$CG/cgroup.procs" >/dev/null
  local CGID=$(stat -c %i "$CG")
  printf '{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.1","proto":6,"action":"ALLOW"},{"layer":"L2","cgroup_id":%s,"dst_ip":"192.168.1.2","proto":6,"action":"ALLOW"}]}\n' "$CGID" "$CGID" > "$OUT/policy.json"
  sudo -n env BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" /home/sungwoo/FINAL/comm_plane/loaders/comm_loader_cgroup_maskprobe --max-burst-inspect 128 --bpf "$COMBO" --lib "$NGINX" --pmd-lib "$NGINX" --offsets "/home/sungwoo/FINAL/comm_plane/offsets.json" --policy "$OUT/policy.json" --no-pin --enforcement --attach-pid "$W" -v > "$OUT/loader.log" 2>&1 &
  for j in $(seq 1 40); do grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && break; sleep 1; done
  grep -q 'attach summary: RX=OK TX=OK' "$OUT/loader.log" 2>/dev/null && say "esac attach OK" || say "eSAC_ATTACH_FAIL"
  echo $(pgrep -f 'nginx: master'|head -1); }

wait_ready(){ local j; for j in $(seq 1 30); do grep -q 'register dpdk interface' "$ELOG" 2>/dev/null && { sleep 2; [ "$($CURL 2>/dev/null)" = 200 ] && return 0; }; sleep 1; done; return 1; }

bench(){ local mode=$1 rep=$2 O=$OUT/ab_${mode}_${rep}.txt
  $AB > "$O" 2>&1
  local rps=$(grep -oE 'Requests per second:[[:space:]]+[0-9.]+' "$O"|grep -oE '[0-9.]+')
  local mean=$(grep -A1 'Time per request' "$O"|grep -oE '[0-9.]+ \[ms\] \(mean\)'|head -1|grep -oE '[0-9.]+'|head -1)
  local p50=$(awk '/Percentage of the requests/{f=1} f&&/^[[:space:]]*50%/{print $2;exit}' "$O")
  local p99=$(awk '/Percentage of the requests/{f=1} f&&/^[[:space:]]*99%/{print $2;exit}' "$O")
  local failed=$(grep -oE 'Failed requests:[[:space:]]+[0-9]+' "$O"|grep -oE '[0-9]+')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$rep" "${rps:-NA}" "${mean:-NA}" "${p50:-NA}" "${p99:-NA}" "${failed:-NA}" >> "$RES"
  say "[$mode r$rep] rps=${rps:-NA} mean=${mean:-NA}ms p50=${p50:-NA} p99=${p99:-NA} failed=${failed:-NA}"; }

for mode in none esac; do
  clean
  if [ "$mode" = none ]; then srv=$(boot_none); else srv=$(boot_esac); fi
  if wait_ready; then for rep in 1 2 3; do bench "$mode" "$rep"; sleep 1; done
  else say "[$mode] NGINX_NOT_READY"; tail -8 "$ELOG" >> "$LOG" 2>/dev/null; fi
  sudo -n pkill -9 -x nginx 2>/dev/null; clean
done
say "=== RESULTS (median rps) ==="
awk -F'\t' 'NR>1&&$3!="NA"{a[$1]=a[$1]" "$3} END{for(k in a){n=split(a[k],v," ");for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(v[i]+0>v[j]+0){t=v[i];v[i]=v[j];v[j]=t}; m=(n%2)?v[(n+1)/2]:(v[n/2]+v[n/2+1])/2; printf "%-6s median_rps=%s (n=%d)\n",k,m,n}}' "$RES" | tee -a "$LOG"
touch "$OUT/.done"; say "DONE OUT=$OUT"

#!/bin/bash
set +u
PF=0000:3b:00.1; IF=enp59s0f1np1
D=/home/sungwoo/FINAL/traffic/dperf_probe
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
SRV=/home/sungwoo/FINAL/harness/setup/run_server_inter.sh
AGENT_L4=/home/sungwoo/FINAL/agent/libbpftime-agent.so
OBJ_L4=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
APP=/home/sungwoo/FINAL/traffic/dperf_probe
GUARD=/home/sungwoo/FINAL/tamper_sentinel/bin
ROOT=/home/sungwoo/ie3_mt_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"; echo "$ROOT">/home/sungwoo/.ie3mt_dir
RES=/home/sungwoo/FINAL/results/IE3_RESULTS_20261104.txt
LOG=$ROOT/log; HZ=$(getconf CLK_TCK)
CDUR=600; HOLD=650; SRVD=720; MAXN=3
say(){ echo "[$(date +%H:%M:%S)] $*"|tee -a "$LOG"; }
rep_of(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
killall_esac(){ sudo -n pkill -9 -f run_server_inter 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null; sudo -n pkill -9 -f comm_loader 2>/dev/null; sudo -n pkill -9 -x bpftrace 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel_prologue 2>/dev/null; for cg in /sys/fs/cgroup/esac_inter_*; do sudo -n rmdir "$cg" 2>/dev/null; done; sudo -n rm -f /dev/shm/esac_inter_* 2>/dev/null; sudo -n rm -f /dev/hugepages/dperf-*map_* 2>/dev/null; sleep 2; }
srv_pid(){ grep -aoE 'server_pid=[0-9]+' "$1/run.log" 2>/dev/null|tail -1|cut -d= -f2; }
pps_of(){ grep -aE '^(tcpRx|pktRx)' "$1/server.log" 2>/dev/null|tr -d ,|awk '{print $2}'|sort -n|tail -1; }

# ---- one-time fabric: 2*MAXN VFs + MACs + tc hairpins ----
killall_esac
sudo -n sh -c "echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages" 2>/dev/null
sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null; sleep 2
sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1
sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
sudo -n sh -c "echo $((2*MAXN)) > /sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null
for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn$((2*MAXN-1)) ] && break; sleep 1; done; sleep 3
sudo -n ip link set $IF up 2>/dev/null
declare -A SVF CVF
for ((t=1;t<=MAXN;t++)); do xx=$(printf '%02x' $t)
  SVF[$t]=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn$((2*(t-1)))))
  CVF[$t]=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn$((2*(t-1)+1))))
  srep=$(rep_of $((2*(t-1)))); crep=$(rep_of $((2*(t-1)+1)))
  sudo -n ip link set $IF vf $((2*(t-1)))   mac 02:50:00:00:$xx:01 2>/dev/null
  sudo -n ip link set $IF vf $((2*(t-1)+1)) mac 02:50:00:00:$xx:02 2>/dev/null
  sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
  sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
  sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
  sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
done
say "fabric VFs=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs)"

# bring_up <outdir-o> <t> : server + client(3-attempt retry until pps>20000). returns 0 if UP.
bring_up(){ local o=$1 t=$2 xx; xx=$(printf '%02x' "$t"); mkdir -p "$o/t$t"
  sudo -n env OUT="$o/t$t" S_NIC="${SVF[$t]}" S_IP="192.168.$((90+t)).1" C_IP="192.168.$((90+t)).2" GW_MAC="02:50:00:00:$xx:02" \
    SCPU=$((5+t)) SOCKET_MEM=512 PAYLOAD=64 PROTO=tcp POLICY_N=32 POL_PROTO=6 HOLD_SEC=$HOLD SRV_DUR=$SRVD TAMPER_SENTINEL=0 POLCPU=$((30+t)) \
    eSAC_COMBO_OBJ=$OBJ_L4 eSAC_AGENT_PATH=$AGENT_L4 setsid bash "$SRV" > "$o/t$t.srv.log" 2>&1 &
  local w; for w in $(seq 1 50); do [ -e "$o/t$t/.ready" ]&&break; sleep 1; done
  [ -e "$o/t$t/.ready" ] || { say "    t$t NOT ready"; return 1; }
  printf 'mode client\ncpu %s\nduration %ss\ncps 100\ncc 100\nkeepalive 1ms\npayload_size 64\nprotocol tcp\nsocket_mem 512\nport %s 192.168.%s.2 192.168.%s.1 02:50:00:00:%s:01\nclient 192.168.%s.2 1\nserver 192.168.%s.1 1\nlisten 9 1\n' \
    "$((15+t))" "$CDUR" "${CVF[$t]}" "$((90+t))" "$((90+t))" "$xx" "$((90+t))" "$((90+t))" > "$o/t$t/cl.conf"
  local okc=0 cur a
  for a in 1 2 3; do sudo -n pkill -f "$o/t$t/cl.conf" 2>/dev/null; sleep 1
    sudo -n timeout $((CDUR+5)) env LD_LIBRARY_PATH=$LIB $D -c "$o/t$t/cl.conf" > "$o/t$t/cl.log" 2>&1 &
    for w in $(seq 1 30); do cur=$(pps_of "$o/t$t"); cur=${cur:-0}; [ "$cur" -gt 20000 ]&&{ okc=1;break; }; sleep 1; done
    [ "$okc" = 1 ]&&break
  done
  [ "$okc" = 1 ]&&{ say "    t$t UP ($cur)"; return 0; }||{ say "    t$t FAILED flow"; return 1; }
}

measure_event(){ local N=$1 o=$2 t srv bp p; local -a wp a b
  for ((t=1;t<=N;t++)); do srv=$(srv_pid "$o/t$t")
    sudo -n taskset -c $((24+t)) bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$srv && (args->prot & 2)/ { signal(9); } tracepoint:syscalls:sys_enter_openat /pid==$srv/ { if(str(args->filename)==\"/proc/self/mem\"){ signal(9); } }" > "$o/t$t/tamper_sentinel_ev.log" 2>&1 &
  done
  sleep 8
  for ((t=1;t<=N;t++)); do srv=$(srv_pid "$o/t$t"); wp[$t]=""
    for bp in $(pgrep -x bpftrace); do tr '\0' ' ' </proc/$bp/cmdline 2>/dev/null|grep -qE "pid==$srv[^0-9]" && { wp[$t]=$bp; break; }; done
    say "  event t$t srv=$srv wd=${wp[$t]} attached=$(grep -qi Attaching "$o/t$t/tamper_sentinel_ev.log" && echo YES||echo NO) err=$(grep -ciE error "$o/t$t/tamper_sentinel_ev.log")"
  done
  for ((t=1;t<=N;t++)); do p=${wp[$t]}; a[$t]=$([ -n "$p" ]&&[ -e /proc/$p/stat ]&&awk '{print $14+$15}' /proc/$p/stat||echo NA); done
  sleep 10
  for ((t=1;t<=N;t++)); do p=${wp[$t]}; b[$t]=$([ -n "$p" ]&&[ -e /proc/$p/stat ]&&awk '{print $14+$15}' /proc/$p/stat||echo NA); done
  local tot=0 per="" nfk=YES c srv al pa
  for ((t=1;t<=N;t++)); do c=NA
    if [ "${a[$t]}" != NA ]&&[ "${b[$t]}" != NA ]; then c=$(awk -v a="${a[$t]}" -v b="${b[$t]}" -v h="$HZ" 'BEGIN{printf "%.3f",(b-a)/h/10*100}'); tot=$(awk -v a="$tot" -v b="$c" 'BEGIN{printf "%.3f",a+b}'); fi
    srv=$(srv_pid "$o/t$t"); al=$([ -d /proc/$srv ]&&echo Y||echo N); pa=$(pps_of "$o/t$t"); [ "$al" = Y ]||nfk=NO
    per="$per t$t=${c}%(alive=$al,pps=$pa)"
  done
  echo "IE3_EVENT N=$N total_cpu=${tot}% per=[$per ] no_false_kill=$nfk" | tee -a "$RES"
  sudo -n pkill -9 -x bpftrace 2>/dev/null; sleep 2
}

measure_poll(){ local N=$1 o=$2 t srv shm mh cand x y bx by cpol cpro sub; local -a pp qp pa0 qa0
  for ((t=1;t<=N;t++)); do srv=$(srv_pid "$o/t$t")
    shm=$(ls -t /dev/shm/esac_inter_t${t}_* 2>/dev/null|head -1); shm=$(basename "$shm" 2>/dev/null)
    sudo -n taskset -c $((30+t)) env BPFTIME_GLOBAL_SHM_NAME="$shm" "$GUARD/tamper_sentinel_cgroup" "$srv" > "$o/t$t/policy_watch.log" 2>&1 &
    for w in $(seq 1 50); do grep -q "POLICY_READY .* pid=$srv " "$o/t$t/policy_watch.log" 2>/dev/null && break; sleep 0.2; done
    sed -n 's/.*DRIVER level: \([^ ]*\) @ .*offset=0x\([0-9a-fA-F]*\)).*/0x\2 \1/p' "$o/t$t/loader.log" | sort -u -k1,1 > "$o/t$t/manifest.txt"
    mh=$(wc -l < "$o/t$t/manifest.txt")
    sudo -n taskset -c $((35+t)) "$GUARD/tamper_sentinel_prologue" "$srv" "$APP" "$o/t$t/manifest.txt" > "$o/t$t/watch.log" 2>&1 &
    for w in $(seq 1 50); do grep -q "READY .* pid=$srv hooks=" "$o/t$t/watch.log" 2>/dev/null && break; sleep 0.2; done
    say "  poll t$t srv=$srv shm=$shm manifest=$mh policy_rdy=$(grep -c POLICY_READY "$o/t$t/policy_watch.log" 2>/dev/null) prologue=$(grep -oE 'hooks=[0-9]+' "$o/t$t/watch.log" 2>/dev/null|head -1)"
  done
  sleep 3
  for ((t=1;t<=N;t++)); do srv=$(srv_pid "$o/t$t"); pp[$t]=""; qp[$t]=""
    for cand in $(pgrep -f "tamper_sentinel_cgroup $srv"); do [[ "$(cat /proc/$cand/comm 2>/dev/null)" == esac_policy* ]]&&{ pp[$t]=$cand; break; }; done
    for cand in $(pgrep -f "tamper_sentinel_prologue $srv"); do [[ "$(cat /proc/$cand/comm 2>/dev/null)" == esac_prologue* ]]&&{ qp[$t]=$cand; break; }; done
  done
  for ((t=1;t<=N;t++)); do x=${pp[$t]}; y=${qp[$t]}
    pa0[$t]=$([ -n "$x" ]&&[ -e /proc/$x/stat ]&&awk '{print $14+$15}' /proc/$x/stat||echo NA)
    qa0[$t]=$([ -n "$y" ]&&[ -e /proc/$y/stat ]&&awk '{print $14+$15}' /proc/$y/stat||echo NA)
  done
  sleep 10
  local tot=0 per=""
  for ((t=1;t<=N;t++)); do x=${pp[$t]}; y=${qp[$t]}
    bx=$([ -n "$x" ]&&[ -e /proc/$x/stat ]&&awk '{print $14+$15}' /proc/$x/stat||echo NA)
    by=$([ -n "$y" ]&&[ -e /proc/$y/stat ]&&awk '{print $14+$15}' /proc/$y/stat||echo NA)
    cpol=NA; cpro=NA
    [ "${pa0[$t]}" != NA ]&&[ "$bx" != NA ]&&cpol=$(awk -v a="${pa0[$t]}" -v b="$bx" -v h="$HZ" 'BEGIN{printf "%.3f",(b-a)/h/10*100}')
    [ "${qa0[$t]}" != NA ]&&[ "$by" != NA ]&&cpro=$(awk -v a="${qa0[$t]}" -v b="$by" -v h="$HZ" 'BEGIN{printf "%.3f",(b-a)/h/10*100}')
    sub=$(awk -v p="$cpol" -v q="$cpro" 'BEGIN{s=0;if(p!="NA")s+=p;if(q!="NA")s+=q;printf "%.3f",s}')
    tot=$(awk -v a="$tot" -v b="$sub" 'BEGIN{printf "%.3f",a+b}'); per="$per t$t=${sub}%(pol=$cpol,pro=$cpro)"
  done
  echo "IE3_POLL  N=$N total_cpu=${tot}% per=[$per ]" | tee -a "$RES"
  sudo -n pkill -9 -f tamper_sentinel 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel_prologue 2>/dev/null; sleep 2
}

echo "# IE3 tamper-sentinel CPU (concurrent N=1/2/3), 40G mlx5 VF-to-VF, L4 mask_probe 32-policy, ~100k/tenant, $(date)" | tee "$RES"
for N in 1 2 3; do
  o=$ROOT/N$N; mkdir -p "$o"; say "===== N=$N: bringing up $N tenants ====="
  up=0
  for ((t=1;t<=N;t++)); do bring_up "$o" "$t" && up=$((up+1)); done
  if [ "$up" -lt "$N" ]; then
    say "N=$N up=$up/$N -> full retry"; killall_esac; o=$ROOT/N${N}r; mkdir -p "$o"; up=0
    for ((t=1;t<=N;t++)); do bring_up "$o" "$t" && up=$((up+1)); done
  fi
  say "N=$N up=$up/$N (proceeding)"
  for ((t=1;t<=N;t++)); do say "  pre t$t srv=$(srv_pid "$o/t$t") alive=$([ -d /proc/$(srv_pid "$o/t$t") ]&&echo Y||echo N) pps=$(pps_of "$o/t$t")"; done
  measure_event "$N" "$o"
  sleep 3
  measure_poll "$N" "$o"
  killall_esac
done
killall_esac
sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null
sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
say "=== IE3 MT DONE ==="; echo IE3_ALL_DONE | tee -a "$RES"; touch "$ROOT/.done"

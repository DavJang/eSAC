#!/bin/bash
set +u
PF=0000:3b:00.1; IF=enp59s0f1np1
DPROBE=/home/sungwoo/eSACfinal/traffic/dperf_probe
LIB=/home/sungwoo/eSACfinal/lib/fstack-dpdk
SRV=/home/sungwoo/eSACfinal/harness/setup/run_server_inter.sh
OBJ_L4=/home/sungwoo/eSACfinal/comm_plane/bpf/comm_filter_maskprobe_16k.bpf.o
AGENT_L4=/home/sungwoo/eSACfinal/agent/libbpftime-agent.so
APP=/home/sungwoo/eSACfinal/traffic/dperf_probe
GUARD=/home/sungwoo/eSACfinal/tamper_sentinel/bin
ROOT=/home/sungwoo/ie3_40g_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"; echo "$ROOT" > /home/sungwoo/.ie3_dir
RES=/home/sungwoo/eSACfinal/results/IE3_RESULTS_20261104.txt
LOG=$ROOT/log
HZ=$(getconf CLK_TCK)
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
SERVER_CPUS=(0 6 7 8); CLIENT_CPUS=(0 20 21 22)
EVWD_CPUS=(0 30 31 32); POLWD_CPUS=(0 33 34 35); PROWD_CPUS=(0 36 37 38)

killall_(){
  sudo -n pkill -9 -f run_server_inter 2>/dev/null; sudo -n pkill -9 -x dperf 2>/dev/null
  sudo -n pkill -9 -f comm_loader 2>/dev/null; sudo -n pkill -9 -x bpftrace 2>/dev/null
  sudo -n pkill -9 -f tamper_sentinel 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel_prologue 2>/dev/null
  for cg in /sys/fs/cgroup/esac_inter_*; do sudo -n rmdir "$cg" 2>/dev/null; done
  sudo -n rm -f /dev/shm/esac_inter_* 2>/dev/null; sudo -n rm -f /dev/hugepages/dperf-*map_* 2>/dev/null
  sleep 2; }
rep_of(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
srv_pid(){ grep -aoE 'server_pid=[0-9]+' "$ROOT/t$1/run.log" 2>/dev/null | tail -1 | cut -d= -f2; }
pps_of(){ grep -aE '^tcpRx' "$ROOT/t$1/server.log" 2>/dev/null|tr -d ,|awk '{print $2}'|sort -n|tail -1; }
cpu_delta(){ local p=$1; [ -z "$p" ] && { echo NA; return; }; [ -e /proc/$p/stat ] || { echo NA; return; }
  local a=$(awk '{print $14+$15}' /proc/$p/stat); sleep 10; [ -e /proc/$p/stat ] || { echo NA; return; }
  local b=$(awk '{print $14+$15}' /proc/$p/stat); awk -v a=$a -v b=$b -v h=$HZ 'BEGIN{printf "%.3f",(b-a)/h/10*100}'; }

setup_fabric(){ killall_
  sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs"; sleep 2
  sudo -n devlink dev eswitch set pci/$PF mode switchdev 2>/dev/null; sleep 1
  sudo -n ethtool -K $IF hw-tc-offload on 2>/dev/null
  sudo -n sh -c "echo 6 > /sys/bus/pci/devices/$PF/sriov_numvfs"
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF/virtfn5 ] && break; sleep 1; done; sleep 3
  sudo -n ip link set $IF up 2>/dev/null
  for v in 0 1 2 3 4 5; do k=$((v/2+1)); sfx=$((v%2+1)); mac=$(printf '02:50:00:00:0%d:0%d' "$k" "$sfx")
    sudo -n ip link set $IF vf $v mac $mac 2>/dev/null; sudo -n ip link set $IF vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF vf $v trust on 2>/dev/null; done
  sleep 2
  for idx in 1 2 3; do sv=$((2*(idx-1))); cv=$((2*(idx-1)+1)); srep=$(rep_of $sv); crep=$(rep_of $cv)
    sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
    sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
    sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
    sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
    hw=$(sudo -n tc filter show dev $srep ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1); say "fabric tenant$idx srep=$srep crep=$crep tc=$hw"; done; }

start_tenant(){ local idx=$1; local sv=$((2*(idx-1))) cv=$((2*(idx-1)+1))
  local svf=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn$sv))
  local cvf=$(basename $(readlink -f /sys/bus/pci/devices/$PF/virtfn$cv))
  local smac=$(printf '02:50:00:00:0%d:01' "$idx"); local cmac=$(printf '02:50:00:00:0%d:02' "$idx")
  local sip=192.168.9${idx}.1 cip=192.168.9${idx}.2; mkdir -p "$ROOT/t$idx"
  sudo -n env OUT="$ROOT/t$idx" S_NIC="$svf" S_IP=$sip C_IP=$cip GW_MAC=$cmac SCPU=${SERVER_CPUS[$idx]} SOCKET_MEM=512 PAYLOAD=64 PROTO=tcp POLICY_N=32 POL_PROTO=6 HOLD_SEC=240 SRV_DUR=300 WD=0 eSAC_COMBO_OBJ=$OBJ_L4 eSAC_AGENT_PATH=$AGENT_L4 setsid bash "$SRV" > "$ROOT/t$idx.srv.log" 2>&1 &
  local ok=NO; for w in $(seq 1 70); do [ -e "$ROOT/t$idx/.ready" ] && { ok=YES; break; }; sleep 1; done
  if [ "$ok" != YES ]; then say "tenant$idx READY=NO"; grep -aE 'FAIL' "$ROOT/t$idx/run.log" 2>/dev/null|tee -a "$LOG"; return 1; fi
  printf 'mode client\ncpu %s\nduration 240s\ncps 100\ncc 100\nkeepalive 1ms\npayload_size 64\nprotocol tcp\nsocket_mem 512\nport %s %s %s %s\nclient %s 1\nserver %s 1\nlisten 9 1\n' "${CLIENT_CPUS[$idx]}" "$cvf" "$cip" "$sip" "$smac" "$cip" "$sip" > "$ROOT/t$idx/cl.conf"
  sudo -n timeout 230 env LD_LIBRARY_PATH=$LIB $DPROBE -c "$ROOT/t$idx/cl.conf" > "$ROOT/t$idx/cl.log" 2>&1 &
  say "tenant$idx READY svf=$svf cvf=$cvf srv=$(srv_pid $idx)"; return 0; }
echo WROTE_PART1

measure_event(){ local N=$1 idx srv; local -a wp a b
  for idx in $(seq 1 $N); do srv=$(srv_pid $idx)
    sudo -n taskset -c ${EVWD_CPUS[$idx]} bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$srv && (args->prot & 2)/ { signal(9); } tracepoint:syscalls:sys_enter_openat /pid==$srv/ { if(str(args->filename)==\"/proc/self/mem\"){ signal(9); } }" > "$ROOT/t$idx/evwd.log" 2>&1 &
  done
  sleep 8
  for idx in $(seq 1 $N); do srv=$(srv_pid $idx); wp[$idx]=""
    for bp in $(pgrep -x bpftrace); do tr '\0' ' ' </proc/$bp/cmdline 2>/dev/null | grep -qE "pid==$srv[^0-9]" && { wp[$idx]=$bp; break; }; done
    local at=$(grep -qi Attaching "$ROOT/t$idx/evwd.log" && echo YES || echo NO)
    say "  event t$idx srv=$srv wd_pid=${wp[$idx]} attached=$at err=$(grep -ciE 'error' $ROOT/t$idx/evwd.log)"
  done
  for idx in $(seq 1 $N); do local p=${wp[$idx]}; a[$idx]=$([ -n "$p" ]&&[ -e /proc/$p/stat ]&&awk '{print $14+$15}' /proc/$p/stat||echo NA); done
  sleep 10
  for idx in $(seq 1 $N); do local p=${wp[$idx]}; b[$idx]=$([ -n "$p" ]&&[ -e /proc/$p/stat ]&&awk '{print $14+$15}' /proc/$p/stat||echo NA); done
  local tot=0 per="" nfk=YES
  for idx in $(seq 1 $N); do local c=NA
    if [ "${a[$idx]}" != NA ]&&[ "${b[$idx]}" != NA ]; then c=$(awk -v a=${a[$idx]} -v b=${b[$idx]} -v h=$HZ 'BEGIN{printf "%.3f",(b-a)/h/10*100}'); tot=$(awk -v a=$tot -v b=$c 'BEGIN{printf "%.3f",a+b}'); fi
    local srv=$(srv_pid $idx); local al=$([ -d /proc/$srv ]&&echo Y||echo N); local pa=$(pps_of $idx)
    [ "$al" = Y ] || nfk=NO
    per="$per t$idx=${c}%(alive=$al,pps=$pa)"; done
  echo "IE3_EVENT N=$N total_cpu=${tot}% per=[$per ] no_false_kill=$nfk" | tee -a "$RES"
  for idx in $(seq 1 $N); do [ -n "${wp[$idx]}" ] && sudo -n kill -9 ${wp[$idx]} 2>/dev/null; done
  sudo -n pkill -9 -x bpftrace 2>/dev/null; sleep 2; }

measure_poll(){ local N=$1 idx srv shm; local -a pp qp a b
  for idx in $(seq 1 $N); do srv=$(srv_pid $idx)
    shm=$(ls -t /dev/shm/esac_inter_t${idx}_* 2>/dev/null|head -1); shm=$(basename "$shm" 2>/dev/null)
    sudo -n taskset -c ${POLWD_CPUS[$idx]} env BPFTIME_GLOBAL_SHM_NAME="$shm" $GUARD/tamper_sentinel_cgroup $srv > "$ROOT/t$idx/policy_watch.log" 2>&1 &
    for w in $(seq 1 50); do grep -q "POLICY_READY .* pid=$srv " "$ROOT/t$idx/policy_watch.log" 2>/dev/null && break; sleep 0.2; done
    sed -n 's/.*DRIVER level: \([^ ]*\) @ .*offset=0x\([0-9a-fA-F]*\)).*/0x\2 \1/p' "$ROOT/t$idx/loader.log" | sort -u -k1,1 > "$ROOT/t$idx/manifest.txt"
    local mh=$(wc -l < "$ROOT/t$idx/manifest.txt")
    sudo -n taskset -c ${PROWD_CPUS[$idx]} $GUARD/tamper_sentinel_prologue $srv $APP "$ROOT/t$idx/manifest.txt" > "$ROOT/t$idx/watch.log" 2>&1 &
    for w in $(seq 1 50); do grep -q "READY .* pid=$srv hooks=" "$ROOT/t$idx/watch.log" 2>/dev/null && break; sleep 0.2; done
    local pr=$(grep -c POLICY_READY "$ROOT/t$idx/policy_watch.log" 2>/dev/null); local qr=$(grep -oE 'hooks=[0-9]+' "$ROOT/t$idx/watch.log" 2>/dev/null|head -1)
    say "  poll t$idx srv=$srv shm=$shm manifest=$mh policy_rdy=$pr prologue_$qr"
  done
  sleep 3
  for idx in $(seq 1 $N); do srv=$(srv_pid $idx); pp[$idx]=""; qp[$idx]=""
    for cand in $(pgrep -f "tamper_sentinel_cgroup $srv"); do cm=$(cat /proc/$cand/comm 2>/dev/null); [[ "$cm" == esac_policy* ]] && { pp[$idx]=$cand; break; }; done
    for cand in $(pgrep -f "tamper_sentinel_prologue $srv"); do cm=$(cat /proc/$cand/comm 2>/dev/null); [[ "$cm" == esac_prologue* ]] && { qp[$idx]=$cand; break; }; done
  done
  for idx in $(seq 1 $N); do local x=${pp[$idx]} y=${qp[$idx]}
    a[$idx]=$({ [ -n "$x" ]&&[ -e /proc/$x/stat ]&&awk '{print $14+$15}' /proc/$x/stat||echo 0; }; { [ -n "$y" ]&&[ -e /proc/$y/stat ]&&awk '{print $14+$15}' /proc/$y/stat||echo 0; } | tr '\n' ' '); done
  for idx in $(seq 1 $N); do local x=${pp[$idx]}; local ax=$([ -n "$x" ]&&[ -e /proc/$x/stat ]&&awk '{print $14+$15}' /proc/$x/stat||echo NA); a[$idx]=$ax; local y=${qp[$idx]}; local ay=$([ -n "$y" ]&&[ -e /proc/$y/stat ]&&awk '{print $14+$15}' /proc/$y/stat||echo NA); b[$idx]=$ay; done
  sleep 10
  local tot=0 per=""
  for idx in $(seq 1 $N); do local x=${pp[$idx]} y=${qp[$idx]}
    local bx=$([ -n "$x" ]&&[ -e /proc/$x/stat ]&&awk '{print $14+$15}' /proc/$x/stat||echo NA); local by=$([ -n "$y" ]&&[ -e /proc/$y/stat ]&&awk '{print $14+$15}' /proc/$y/stat||echo NA)
    local cpol=NA cpro=NA
    [ "${a[$idx]}" != NA ]&&[ "$bx" != NA ] && cpol=$(awk -v a=${a[$idx]} -v b=$bx -v h=$HZ 'BEGIN{printf "%.3f",(b-a)/h/10*100}')
    [ "${b[$idx]}" != NA ]&&[ "$by" != NA ] && cpro=$(awk -v a=${b[$idx]} -v b=$by -v h=$HZ 'BEGIN{printf "%.3f",(b-a)/h/10*100}')
    local sub=$(awk -v p="$cpol" -v q="$cpro" 'BEGIN{s=0;if(p!="NA")s+=p;if(q!="NA")s+=q;printf "%.3f",s}')
    tot=$(awk -v a=$tot -v b=$sub 'BEGIN{printf "%.3f",a+b}'); per="$per t$idx=${sub}%(pol=$cpol,pro=$cpro)"; done
  echo "IE3_POLL  N=$N total_cpu=${tot}% per=[$per ]" | tee -a "$RES"
  sudo -n pkill -9 -f tamper_sentinel 2>/dev/null; sudo -n pkill -9 -f tamper_sentinel_prologue 2>/dev/null; sleep 2; }

echo "# IE3 tamper-sentinel CPU, 40G mlx5 VF-to-VF, L4 mask_probe 32-policy, steady ~100k/tenant, $(date)" | tee "$RES"
setup_fabric
for N in 1 2 3; do
  say "===== N=$N: bringing up $N tenants ====="; killall_
  okN=YES; for i in $(seq 1 $N); do start_tenant $i || okN=NO; sleep 8; done
  if [ "$okN" != YES ]; then echo "IE3_EVENT N=$N FAILED tenant_bringup"|tee -a "$RES"; echo "IE3_POLL  N=$N FAILED tenant_bringup"|tee -a "$RES"; continue; fi
  say "N=$N steady-state wait 30s (past JIT)"; sleep 30
  for i in $(seq 1 $N); do say "  pre t$i srv=$(srv_pid $i) alive=$([ -d /proc/$(srv_pid $i) ]&&echo Y||echo N) pps=$(pps_of $i)"; done
  measure_event $N
  sleep 3
  measure_poll $N
done
killall_
sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs" 2>/dev/null
sudo -n devlink dev eswitch set pci/$PF mode legacy 2>/dev/null
say "=== IE3 DONE ==="; echo IE3_ALL_DONE | tee -a "$RES"; touch "$ROOT/.done"

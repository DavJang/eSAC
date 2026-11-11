#!/bin/bash
# Focused INTER L7 throughput: none vs eSAC, 1 lcore, 64B, RX (host1=server, host2=client).
# Reuses master.sh recipe verbatim. Runs DETACHED; writes RESULT.txt. Root.
set +u
ROOT=/home/sungwoo/inter_l7_1c64_$(date +%Y%m%d_%H%M%S); mkdir -p "$ROOT"
RES="$ROOT/RESULT.txt"; : > "$RES"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$ROOT/LOG" "$RES"; }
# ---- asset paths (from master.sh) ----
PF_INTER=0000:3b:00.0
PREP=/home/sungwoo/FINAL/harness/setup/host1_vf_prepare.sh
H2KEY=/home/sungwoo/FINAL/secrets/host2_key
H2=(ssh -i "$H2KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 9022 sungwoo@143.248.57.12)
DNS=/home/sungwoo/FINAL/traffic/dperf_dns
LIB=/home/sungwoo/FINAL/lib/fstack-dpdk
AGENT=/home/sungwoo/FINAL/agent/libbpftime-agent-hs.so
BSRV=/home/sungwoo/FINAL/agent/libbpftime-syscall-server.so
UFUNC=/home/sungwoo/FINAL/l7/ctl/esac_suricata_dns_ufunc.so
L7OBJ=/home/sungwoo/FINAL/comm_plane/bpf/comm_filter_maskprobe_16k_hs_gate.bpf.o
L_RX=/home/sungwoo/FINAL/comm_plane/loaders/comm_loader_rxonly
OFFS=/home/sungwoo/FINAL/comm_plane/offsets.json
IDT=/home/sungwoo/FINAL/tamper_sentinel/esac_pidcg_verify.py
GENPOL=/home/sungwoo/FINAL/policy/gen_policy_n.py
HSCTL=/home/sungwoo/FINAL/l7/ctl/esac_hs_ctl_rx_urlhaus
DOMCTL=/home/sungwoo/FINAL/l7/ctl/esac_dom_ctl_bulk
PATS=/home/sungwoo/FINAL/l7/patterns/suricata_dns_patterns.txt
QCOM=/home/sungwoo/FINAL/l7/payloads/dnsq_com.bin
H2MAC=3c:fd:fe:c4:93:38; H1VFMAC=02:40:00:00:00:11
med(){ grep -aE "^pktRx" "$1" 2>/dev/null|awk '{print $2}'|tr -d ,|awk '$1>0'|sort -n|awk '{a[NR]=$1}END{if(NR)print a[int((NR+1)/2)];else print 0}'; }
actsum(){ grep -ahoE "dir=(RX|TX)|ACT_(DROP|KILL)" "$@" 2>/dev/null|sort|uniq -c|tr '\n' ' '; }
KILL1(){ pkill -9 -x dperf 2>/dev/null; pkill -9 -x dperf_dns 2>/dev/null; pkill -9 -f comm_loader_rxonly 2>/dev/null; for cg in /sys/fs/cgroup/esac_*; do rmdir "$cg" 2>/dev/null; done; }
h2_kill(){ "${H2[@]}" "pkill -9 -x dperf 2>/dev/null; sleep 1" 2>/dev/null; }
hsdb(){ rm -f /dev/shm/esac_hs_db /dev/shm/esac_dom_db; "$DOMCTL" /esac_dom_db /dev/null none >/dev/null 2>&1; chmod a+r /dev/shm/esac_dom_db 2>/dev/null; "$HSCTL" /esac_hs_db "$PATS" none >/dev/null 2>&1; chmod a+r /dev/shm/esac_hs_db 2>/dev/null; }
attach(){ local pid=$1 obj=$2 d=$3 shm=$4 act=ALLOW pp=17
  local CG=/sys/fs/cgroup/esac_$pid; mkdir -- "$CG" 2>/dev/null; chmod 755 "$CG"; echo "$pid" > "$CG/cgroup.procs"
  python3 "$IDT" init "$pid" "$CG" "$d/identity.json" > "$d/id.log" 2>&1
  local cgid=$(stat -c %i "$CG")
  python3 "$GENPOL" "$cgid" 192.168.1.1 192.168.0.1 "$act" 2 "$pp" > "$d/policy.json"
  env BPFTIME_GLOBAL_SHM_NAME=$shm BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$BSRV" "$L_RX" --max-burst-inspect 128 --bpf "$obj" --lib "$DNS" --pmd-lib "$DNS" --offsets "$OFFS" --policy "$d/policy.json" --no-pin --attach-pid "$pid" -v > "$d/loader.log" 2>&1 &
  RDY=NO; for j in $(seq 1 55); do grep -qE "attach summary: RX=OK" "$d/loader.log" 2>/dev/null && { RDY=YES; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 1; done; }

cleanup(){ KILL1; h2_kill; echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; log "cleanup done"; echo EXP_DONE >> "$RES"; }
trap cleanup EXIT

# ---- inter VF up ----
echo 0 > /sys/bus/pci/devices/$PF_INTER/sriov_numvfs 2>/dev/null; sleep 1
env VF_TTL=9000 bash "$PREP" > "$ROOT/vf_inter.log" 2>&1
VF_I=$(sed -n 's/^VF_BDF=//p' "$ROOT/vf_inter.log"|head -1)
log "inter VF=$VF_I  (none/eSAC L7 1c 64B RX)"
[ -z "$VF_I" ] && { log "VF bringup FAILED"; cat "$ROOT/vf_inter.log"|tail -5|tee -a "$RES"; exit 1; }

run_inter_rx(){ local REG=$1 d="$ROOT/${REG}_inter_rx_l7_1c_64"; mkdir -p "$d"
  KILL1; h2_kill; sleep 2; hsdb
  cat > "$d/server.conf" <<C
mode server
tx_burst 32
cpu 6
duration 60s
payload_size 64
protocol udp
keepalive 20us
socket_mem 2048
port $VF_I 192.168.1.1 192.168.0.1 $H2MAC
client 192.168.0.1 1
server 192.168.1.1 1
listen 9 1
C
  local SHM=esac_$(date +%s%N)
  if [ "$REG" = none ]; then
    env -u LD_PRELOAD LD_LIBRARY_PATH="$LIB" timeout 56 "$DNS" -c "$d/server.conf" > "$d/server.log" 2>&1 & sleep 8
  else
    bash -c 'kill -STOP "$$"; exec env BPFTIME_GLOBAL_SHM_NAME='"$SHM"' LD_PRELOAD="$1" LD_LIBRARY_PATH="$2" "$3" -c "$4"' _ "$AGENT:$UFUNC" "$LIB" "$DNS" "$d/server.conf" > "$d/server.log" 2>&1 &
    local srv=$!; sleep 1
    [ "$(awk '{print $3}' /proc/$srv/stat 2>/dev/null)" != T ] && { log "$REG NOSTOP"; KILL1; return; }
    attach "$srv" "$L7OBJ" "$d" "$SHM"
    [ "$RDY" != YES ] && { log "$REG ATTACHFAIL: $(grep -aE 'rror|summary' "$d/loader.log"|tail -1)"; kill -9 $srv 2>/dev/null; KILL1; return; }
    kill -CONT "$srv"; sleep 8
  fi
  "${H2[@]}" "env DUR=24 CPU=16 PROTO=udp PAYLOAD=64 KEEPALIVE=20us CPS=4000 CC=10000 SERVER_MAC=$H1VFMAC SOCKET_MEM=0,2048 CLIENT_BIN=/home/sungwoo/eSACfinal/traffic/dperf HIST_START=3 bash /home/sungwoo/eSACfinal/harness/setup/host2_auto_client_hist.sh" > "$d/h2client.out" 2>&1
  KILL1; sleep 2
  local deliv=$(med "$d/server.log")
  local offered=$(grep -aoE 'pktTx +[0-9,]+' "$d/h2client.out"|grep -oE '[0-9,]+$'|tr -d ,|sort -n|tail -1)
  log "RESULT $REG inter_rx_l7_1c_64: delivered=${deliv:-0} offered=${offered:-0} act=$(actsum "$d"/loader.log 2>/dev/null)"
}

run_inter_rx none
run_inter_rx esac
log "ALL DONE ROOT=$ROOT"

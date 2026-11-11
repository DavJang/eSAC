#!/bin/bash
# eSAC launcher admission gate: pre-screen a tenant's EAL resource request against its quota
# BEFORE exec. Over-limit -> refuse (never exec; attacker's repeated launches all blocked here,
# touching no kernel/NIC resource). Within-limit -> exec the real tenant. Pure control-plane.
#   usage: esac_admit.sh <quota.json> -- <tenant cmd...>
set -u
Q=$1; shift; [ "$1" = "--" ] && shift
CMD=("$@")
jget(){ grep -oE "\"$1\"[ ]*:[ ]*[0-9]+" "$Q" | grep -oE "[0-9]+$"; }
MAX_MB=$(jget max_socket_mem_mb); MAX_LC=$(jget max_lcore_count)
REQ_MB=0; REQ_LC=0
for ((i=0;i<${#CMD[@]};i++)); do
  case "${CMD[$i]}" in
    -m) REQ_MB=${CMD[$((i+1))]} ;;
    --socket-mem) IFS=',' read -ra S <<< "${CMD[$((i+1))]}"; for v in "${S[@]}"; do REQ_MB=$((REQ_MB + v)); done ;;
    -l|--lcores) IFS=',' read -ra L <<< "${CMD[$((i+1))]}"; REQ_LC=${#L[@]} ;;
  esac
done
DENY=0; R=""
[ -n "$MAX_MB" ] && [ "$REQ_MB" -gt "$MAX_MB" ] && { DENY=1; R="$R socket_mem ${REQ_MB}MB>${MAX_MB}MB"; }
[ -n "$MAX_LC" ] && [ "$REQ_LC" -gt "$MAX_LC" ] && { DENY=1; R="$R lcores ${REQ_LC}>${MAX_LC}"; }
if [ $DENY -eq 1 ]; then echo "[ADMIT] DENY (no exec):$R"; exit 2; fi
echo "[ADMIT] OK req_mb=$REQ_MB req_lc=$REQ_LC -> exec tenant"
exec "${CMD[@]}"

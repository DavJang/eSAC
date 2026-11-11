#!/bin/bash
# eSAC on a STOCK, UNMODIFIED real app: /usr/bin/memcached (apt 1.6.14, kernel sockets, NO DPDK).
# Demonstrates the only eSAC dimension that applies to an unmodified non-DPDK app:
# Tamper Sentinel (syscall tracepoint watchdog). NO app modification, NO recompile, NO f-stack.
#   1) stock memcached serves set/get (functional)
#   2) arm Tamper Sentinel on its PID
#   3) memcached STILL serves set/get (eSAC transparent)
#   4) simulate tamper (open /proc/self/mem via gdb) -> sentinel SIGKILLs memcached
set -u
D=/home/sungwoo/FINAL
MC=/usr/bin/memcached
SENTINEL=$D/tamper_sentinel/tamper_sentinel_event.sh
PORT=11212
OUT=$D/results/mc_tamper_$(date +%s); mkdir -p "$OUT"
say(){ echo "[$(date +%H:%M:%S)] $*"; }

# KV client via python3 (robust memcached ASCII protocol round-trip)
kv(){ python3 - "$1" "${2:-}" <<'PY' 2>/dev/null
import socket,sys
op=sys.argv[1]; val=sys.argv[2] if len(sys.argv)>2 else ""
s=socket.create_connection(("127.0.0.1",11212),timeout=3)
if op=="set":
    s.sendall(f"set k 0 0 {len(val)}\r\n{val}\r\n".encode())
    print(s.recv(100).decode().strip())
elif op=="get":
    s.sendall(b"get k\r\n")
    print(s.recv(200).decode().replace("\r\n","|").strip())
s.close()
PY
}

pkill -9 -f "memcached -p $PORT" 2>/dev/null; sleep 1

# (1) start STOCK unmodified memcached (non-root user instance on $PORT)
say "===== (1) STOCK unmodified memcached up ($MC, kernel sockets) ====="
setsid $MC -p $PORT -m 64 -l 127.0.0.1 > "$OUT/mc.log" 2>&1 < /dev/null & disown
sleep 2; PID=$(pgrep -f "memcached -p $PORT" | head -1); say "memcached pid=$PID ver=$($MC -h 2>&1 | head -1)"
say "  SET -> $(kv set HELLO)   GET -> $(kv get)"

# (2) arm Tamper Sentinel on the UNMODIFIED app's pid (syscall tracepoint, no app change)
say "===== (2) arm eSAC Tamper Sentinel on pid=$PID (syscall watchdog, app untouched) ====="
sudo -n bash "$SENTINEL" "$PID" 11 > "$OUT/sentinel.log" 2>&1 &
for j in $(seq 1 15); do grep -qi 'Attaching' "$OUT/sentinel.log" 2>/dev/null && break; sleep 1; done
say "  sentinel: $(grep -i Attaching "$OUT/sentinel.log" | head -1)"

# (3) still functional under eSAC (transparent)
say "===== (3) memcached STILL serves under eSAC (transparent) ====="
say "  SET -> $(kv set WORLD)   GET -> $(kv get)"
sleep 1
if kill -0 "$PID" 2>/dev/null; then say "  memcached alive & serving under sentinel -- OK"; else say "  memcached died unexpectedly -- FAIL"; fi

# (4) tamper -> SIGKILL
say "===== (4) TAMPER: open(/proc/self/mem) inside memcached via gdb -> expect eSAC KILL ====="
sudo -n timeout 25 gdb -p "$PID" -batch -ex 'call (int)open("/proc/self/mem", 2)' -ex detach -ex quit > "$OUT/gdb.log" 2>&1
sleep 3
if kill -0 "$PID" 2>/dev/null; then say "  memcached STILL ALIVE -- FAIL (sentinel missed tamper)"; else say "  memcached KILLED by eSAC Tamper Sentinel -- PASS"; fi
say "  sentinel hit: $(grep -aE 'EVWD' "$OUT/sentinel.log" | tail -1)"

# cleanup
pkill -9 -f "memcached -p $PORT" 2>/dev/null; sudo -n pkill -9 -f "bpftrace" 2>/dev/null
say "DONE OUT=$OUT"

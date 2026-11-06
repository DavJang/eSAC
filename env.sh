# source this before running eSAC binaries on any host: resolves bundled runtime libs
D="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export LD_LIBRARY_PATH="$D/lib/runtime:$D/suricata/lib:$D/lib/fstack-dpdk/lib:${LD_LIBRARY_PATH:-}"

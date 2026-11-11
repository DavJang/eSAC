/*
 * resource_loader.c
 * --------------------------------------------------------------
 * Phase 1 자원 접근 제어 로더.
 *
 * 책임:
 *   1) resource_monitor.bpf.o 열기.
 *   2) .rodata (runtime_config) 에 kill_signal/enabled/features 주입.
 *      → 모든 가변값은 eBPF 맵/.rodata 기반, 하드코딩 X.
 *   3) BPF load.
 *   4) libdpdk.so / librte_*.so 의 자원 API 들에 uprobe attach.
 *   5) resource_policy.json 을 파싱해 res_policy 맵 주입.
 *   6) res_events ringbuf 폴링 + SIGUSR1 → pid_res_stats 덤프.
 *
 * 빌드: gcc resource_loader.c -o resource_loader -lbpf -lelf -lz
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <getopt.h>
#include <dirent.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/common.h"

/* ---- 후킹 대상 심볼 ---- */
struct hook_target {
    const char *prog_uprobe;
    const char *prog_uretprobe;
    const char *symbol;
    const char *libname;   /* FIX(2026-09-20): 실제 심볼이 있는 .so 파일명.
                             * 이전에는 모든 훅이 --lib 인자 하나(보통
                             * librte_eal.so)에만 attach되어, rte_eal_init/
                             * rte_zmalloc/rte_memzone_reserve 등 진짜로
                             * librte_eal.so 안에 있는 함수들만 우연히
                             * 동작했다. rte_pktmbuf_pool_create(librte_
                             * mbuf.so)와 rte_eth_dev_configure 계열
                             * (librte_ethdev.so)은 다른 파일에 있는
                             * 심볼이라 offset 0(파일 시작, ELF 헤더)에
                             * uprobe가 붙어 "attached" 로그는 찍히지만
                             * 실제로는 절대 안 터지는 상태였다 (R3/R4
                             * 재설계 중 발견: VIOLATION=0, greedy가 정책
                             * 위반해도 안 죽음). --lib 인자의 디렉토리를
                             * 기준으로 이 필드의 파일명을 조합해서 진짜
                             * 심볼이 있는 라이브러리에 attach하도록 수정. */
};

static const struct hook_target HOOKS[] = {
    { "uprobe_eal_init",                  NULL,                                 "rte_eal_init",            "librte_eal.so" },
    { "uprobe_pktmbuf_pool_create",       "uretprobe_pktmbuf_pool_create",      "rte_pktmbuf_pool_create", "librte_mbuf.so" },
    { "uprobe_mempool_create",            NULL,                                 "rte_mempool_create",      "librte_mempool.so" },
    { "uprobe_eth_dev_configure",         NULL,                                 "rte_eth_dev_configure",   "librte_ethdev.so" },
    { "uprobe_eth_rx_queue_setup",        NULL,                                 "rte_eth_rx_queue_setup",  "librte_ethdev.so" },
    { "uprobe_eth_tx_queue_setup",        NULL,                                 "rte_eth_tx_queue_setup",  "librte_ethdev.so" },
    { "uprobe_eth_dev_start",             NULL,                                 "rte_eth_dev_start",       "librte_ethdev.so" },
    { "uprobe_rte_malloc",                NULL,                                 "rte_malloc",              "librte_eal.so" },
    { "uprobe_rte_zmalloc",               NULL,                                 "rte_zmalloc",             "librte_eal.so" },
    { "uprobe_memzone_reserve",           NULL,                                 "rte_memzone_reserve",     "librte_eal.so" },
    { "uprobe_eal_remote_launch",         NULL,                                 "rte_eal_remote_launch",   "librte_eal.so" },
    { "rl_flow_create",  NULL, "rte_flow_create",  "librte_ethdev.so" },
    { "rl_flow_destroy", NULL, "rte_flow_destroy", "librte_ethdev.so" },
    { "rl_flow_flush",   NULL, "rte_flow_flush",   "librte_ethdev.so" },
};

static volatile sig_atomic_t exiting  = 0;
static volatile sig_atomic_t dump_now = 0;
static void on_sigint(int s)  { (void)s; exiting = 1; }

static void on_sigusr1(int s) { (void)s; dump_now = 1; }

struct options {
    const char *bpf_obj;
    const char *lib_path;
    const char *policy_path;
    int verbose;
    int json;
    int kill_signal;     /* 가변, 기본 9(SIGKILL) */
    int attach_pid;      /* optional process-scoped uprobe target */
    int no_pin;          /* avoid altering shared bpffs pins during isolated runs */
};
static struct options G;

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s --bpf <obj.o> --lib <libdpdk.so> [--policy <file>]\n"
        "          [--kill-signal N] [--attach-pid PID] [--no-pin] [--json] [-v]\n", prog);
}

/* ---- JSON 파서 (간소) ---- */

static int json_extract_u64(const char *blob, const char *key, uint64_t *out)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(blob, pattern);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n') p++;
    if (*p == '"') return -1;
    char *end;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p) return -1;
    *out = v;
    return 0;
}
static int json_extract_str(const char *blob, const char *key,
                            char *out, size_t outsz)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(blob, pattern);
    if (!p) return -1;
    p = strchr(p, ':'); if (!p) return -1; p++;
    while (*p == ' ' || *p == '\t' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) out[i++] = *p++;
    out[i] = 0;
    return 0;
}
/* ---- 심볼 오프셋 조회 ---- */
/*
 * shared lib (.so)  : nm -D gives virtual addr == file offset (PIC, base=0)
 * PIE executable    : nm gives virtual addr ≈ file offset (LOAD base=0)
 * non-PIE static    : nm gives absolute vaddr; subtract text LOAD vaddr
 */
static unsigned long sym_offset(const char *lib, const char *sym)
{
    char cmd[512];
    unsigned long off = 0;

    /* 1) dynamic symbols first (shared library) */
    snprintf(cmd, sizeof(cmd),
        "nm -D '%s' 2>/dev/null | awk '$3==\"%s\"{print $1; exit}'", lib, sym);
    FILE *f = popen(cmd, "r");
    if (f) { if (fscanf(f, "%lx", &off) != 1) off = 0; pclose(f); }
    if (off) return off;

    /* 2) all symbols (static binary / PIE exe) */
    snprintf(cmd, sizeof(cmd),
        "nm '%s' 2>/dev/null | awk '$3==\"%s\"{print $1; exit}'", lib, sym);
    f = popen(cmd, "r");
    if (!f) return 0;
    if (fscanf(f, "%lx", &off) != 1) off = 0;
    pclose(f);
    if (!off) return 0;

    /* 3) non-PIE (ET_EXEC): subtract text segment virtual base */
    snprintf(cmd, sizeof(cmd),
        "readelf -h '%s' 2>/dev/null | awk '/Type:/{print $2}'", lib);
    f = popen(cmd, "r");
    char etype[16] = {};
    if (f) { if (fscanf(f, "%15s", etype) != 1) etype[0] = 0; pclose(f); }

    if (!strcmp(etype, "EXEC")) {
        snprintf(cmd, sizeof(cmd),
            "readelf -l '%s' 2>/dev/null"
            " | awk '/LOAD/{if($5~/E/){sub(/0x/,\"\",$3);"
            "printf \"0x%%s\\n\",$3; exit}}'", lib);
        f = popen(cmd, "r");
        unsigned long base = 0;
        if (f) { if (fscanf(f, "%lx", &base) != 1) base = 0; pclose(f); }
        if (base) off -= base;
    }
    return off;
}

static uint32_t parse_action(const char *s)
{
    if (!strcasecmp(s, "ALLOW")) return ACT_ALLOW;
    if (!strcasecmp(s, "KILL"))  return ACT_KILL;
    return UINT32_MAX;
}
static int parse_policy_block(const char *blob, struct resource_policy *out)
{
    memset(out, 0, sizeof(*out));
    uint64_t v;
    if (json_extract_u64(blob, "max_socket_mem_mb", &v) == 0)
        out->max_socket_mem_mb = v;
    if (json_extract_u64(blob, "max_mbuf_count", &v) == 0)
        out->max_mbuf_count = (uint32_t)v;
    if (json_extract_u64(blob, "max_mbuf_total_bytes", &v) == 0)
        out->max_mbuf_total_bytes = v;
    if (json_extract_u64(blob, "max_rx_queues", &v) == 0)
        out->max_rx_queues = (uint32_t)v;
    if (json_extract_u64(blob, "max_tx_queues", &v) == 0)
        out->max_tx_queues = (uint32_t)v;
    if (json_extract_u64(blob, "max_ports", &v) == 0)
        out->max_ports = (uint32_t)v;
    if (json_extract_u64(blob, "max_rte_malloc_bytes", &v) == 0)
        out->max_rte_malloc_bytes = v;
    if (json_extract_u64(blob, "max_lcore_count", &v) == 0)
        out->max_lcore_count = (uint32_t)v;

    char act[32] = "KILL";
    json_extract_str(blob, "action_on_violation", act, sizeof(act));
    out->action_on_violation = parse_action(act);
    if (out->action_on_violation == UINT32_MAX) {
        fprintf(stderr, "policy: invalid resource action '%s'\n", act);
        return -1;
    }
    return 0;
}

static int load_policy_file(const char *path, int policy_map_fd)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "policy: failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    char *blob = malloc(sz + 1); if (!blob) { fclose(f); return -1; }
    if (fread(blob, 1, sz, f) != (size_t)sz) {
        free(blob); fclose(f); return -1;
    }
    blob[sz] = 0; fclose(f);

    const char *def = strstr(blob, "\"default\"");
    if (def) {
        const char *open = strchr(def, '{');
        if (open) {
            struct resource_policy pol;
            if (parse_policy_block(open, &pol) < 0) { free(blob); return -1; }
            uint32_t key = 0;
            if (bpf_map_update_elem(policy_map_fd, &key, &pol, BPF_ANY) < 0)
                fprintf(stderr, "policy: default update failed: %s\n",
                        strerror(errno));
            else
                fprintf(stderr, "policy: default loaded (action=%u)\n",
                        pol.action_on_violation);
        }
    }
    const char *pids = strstr(blob, "\"pids\"");
    if (pids) {
        const char *p = pids;
        while ((p = strchr(p, '"')) != NULL) {
            p++;
            if (*p >= '0' && *p <= '9') {
                uint32_t pid = (uint32_t)strtoul(p, NULL, 10);
                const char *open = strchr(p, '{');
                if (!open) break;
                struct resource_policy pol;
                if (parse_policy_block(open, &pol) < 0) { free(blob); return -1; }
                if (bpf_map_update_elem(policy_map_fd, &pid, &pol, BPF_ANY) < 0)
                    fprintf(stderr, "policy: pid %u update failed: %s\n",
                            pid, strerror(errno));
                else
                    fprintf(stderr, "policy: pid %u loaded\n", pid);
                int depth = 1; const char *q = open + 1;
                while (*q && depth) {
                    if (*q == '{') depth++;
                    else if (*q == '}') depth--;
                    q++;
                }
                p = q;
            }
        }
    }
    free(blob);
    return 0;
}

/* ---- 이벤트 핸들러 ---- */

static const char *api_name(uint32_t id)
{
    switch (id) {
    case API_RTE_EAL_INIT:              return "rte_eal_init";
    case API_RTE_PKTMBUF_POOL_CREATE:   return "rte_pktmbuf_pool_create";
    case API_RTE_MEMPOOL_CREATE:        return "rte_mempool_create";
    case API_RTE_ETH_DEV_CONFIGURE:     return "rte_eth_dev_configure";
    case API_RTE_ETH_RX_QUEUE_SETUP:    return "rte_eth_rx_queue_setup";
    case API_RTE_ETH_TX_QUEUE_SETUP:    return "rte_eth_tx_queue_setup";
    case API_RTE_ETH_DEV_START:         return "rte_eth_dev_start";
    case API_RTE_MALLOC:                return "rte_malloc";
    case API_RTE_ZMALLOC:               return "rte_zmalloc";
    case API_RTE_MEMZONE_RESERVE:       return "rte_memzone_reserve";
    case API_RTE_EAL_REMOTE_LAUNCH:     return "rte_eal_remote_launch";
    default:                            return "unknown";
    }
}
static const char *action_name(uint32_t a)
{
    switch (a) {
    case ACT_ALLOW: return "ALLOW";
    case ACT_KILL:  return "KILL";
    default: return "?";
    }
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct resource_event *e = data;

    if (G.json) {
        printf("{\"ts_ns\":%llu,\"pid\":%u,\"tgid\":%u,"
               "\"api\":\"%s\",\"violation\":%u,\"action\":\"%s\"}\n",
               (unsigned long long)e->ts_ns,
               e->pid, e->tgid, api_name(e->api_id),
               e->violation, action_name(e->action_taken));
        /* bpf_send_signal workaround: enforce kill from userspace */
        if (e->violation && e->action_taken == ACT_KILL && e->pid > 1)
            kill((pid_t)e->pid, G.kill_signal > 0 ? G.kill_signal : 9);
    } else {
        char buf[160] = "";
        switch (e->api_id) {
        case API_RTE_PKTMBUF_POOL_CREATE:
            snprintf(buf, sizeof(buf),
                     " name=%s n=%u cache=%u priv=%u room=%u socket=%d",
                     e->arg.pool_create.name, e->arg.pool_create.n,
                     e->arg.pool_create.cache_size, e->arg.pool_create.priv_size,
                     e->arg.pool_create.data_room_size,
                     e->arg.pool_create.socket_id);
            break;
        case API_RTE_ETH_DEV_CONFIGURE:
            snprintf(buf, sizeof(buf), " port=%u rxq=%u txq=%u",
                     e->arg.dev_configure.port_id,
                     e->arg.dev_configure.nb_rx_queue,
                     e->arg.dev_configure.nb_tx_queue);
            break;
        case API_RTE_ETH_RX_QUEUE_SETUP:
        case API_RTE_ETH_TX_QUEUE_SETUP:
            snprintf(buf, sizeof(buf), " port=%u q=%u desc=%u socket=%d",
                     e->arg.queue_setup.port_id, e->arg.queue_setup.queue_id,
                     e->arg.queue_setup.nb_desc, e->arg.queue_setup.socket_id);
            break;
        case API_RTE_MALLOC:
        case API_RTE_ZMALLOC:
        case API_RTE_MEMZONE_RESERVE:
            snprintf(buf, sizeof(buf), " size=%llu align=%u",
                     (unsigned long long)e->arg.malloc.size,
                     e->arg.malloc.align);
            break;
        }
        printf("[%llu] pid=%u %s%s%s %s\n",
               (unsigned long long)e->ts_ns, e->pid,
               e->violation ? "[VIOLATION] " : "",
               api_name(e->api_id), buf, action_name(e->action_taken));
    }
    fflush(stdout);
    return 0;
}

/* ---- SIGUSR1: pid_res_stats 덤프 ---- */

static void dump_pid_stats(int fd)
{
    fprintf(stderr,
        "\n===== pid_res_stats =====\n"
        "%-8s %-8s %-12s %-12s %-12s %-10s %-10s %-10s %-12s %-10s\n",
        "pid", "tgid", "mbuf_pools", "mbuf_count", "mbuf_bytes",
        "rxq", "txq", "ports", "malloc_bytes", "violations");

    __u32 key = 0, next;
    int first = 1;
    while (1) {
        int r = first
            ? bpf_map_get_next_key(fd, NULL, &next)
            : bpf_map_get_next_key(fd, &key, &next);
        if (r != 0) break;
        first = 0;
        key = next;
        struct pid_resource_stats st;
        if (bpf_map_lookup_elem(fd, &key, &st) < 0) continue;
        fprintf(stderr,
            "%-8u %-8u %-12u %-12u %-12llu %-10u %-10u %-10u %-12llu %-10llu\n",
            st.pid, st.tgid,
            st.mbuf_pool_count, st.mbuf_total_count,
            (unsigned long long)st.mbuf_total_bytes,
            st.rx_queues_total, st.tx_queues_total, st.ports_configured,
            (unsigned long long)st.rte_malloc_bytes,
            (unsigned long long)st.violation_count);
    }
}

/* ---- main ---- */

static int bump_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &r) ? -1 : 0;
}

/* 이전 실행에서 남은 pinned BPF 맵을 자동으로 삭제.
 * LIBBPF_PIN_BY_NAME 은 /sys/fs/bpf/<map_name> 에 고정하고,
 * bpf_object__pin_maps 는 PIN_BASE/<map_name> 에 고정한다.
 * 구조체가 변경된 채로 재실행하면 "parameter mismatch" 오류가 발생하므로
 * 로더 시작 시 두 경로를 모두 제거한다. */
static void purge_pinned_maps(struct bpf_object *obj)
{
    (void)obj;
    char path[512];
    DIR *d = opendir(PIN_BASE);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "%s/%s", PIN_BASE, ent->d_name);
            if (remove(path) == 0)
                fprintf(stderr, "[init] purged stale pin: %s\n", path);
        }
        closedir(d);
    }
}

int main(int argc, char **argv)
{
    static struct option longopts[] = {
        { "bpf",          required_argument, 0, 'b' },
        { "lib",          required_argument, 0, 'l' },
        { "policy",       required_argument, 0, 'p' },
        { "kill-signal",  required_argument, 0, 'k' },
        { "json",         no_argument,       0, 'j' },
        { "verbose",      no_argument,       0, 'v' },
        { "attach-pid",   required_argument, 0, 'A' },
        { "no-pin",       no_argument,       0, 'N' },
        { 0, 0, 0, 0 }
    };
    G.kill_signal = 9;
    G.attach_pid = -1;
    int c;
    while ((c = getopt_long(argc, argv, "b:l:p:k:jvA:N", longopts, NULL)) != -1) {
        switch (c) {
        case 'b': G.bpf_obj     = optarg; break;
        case 'l': G.lib_path    = optarg; break;
        case 'p': G.policy_path = optarg; break;
        case 'k': G.kill_signal = atoi(optarg); break;
        case 'j': G.json = 1; break;
        case 'v': G.verbose = 1; break;
        case 'A': {
            char *end = NULL;
            long pid = strtol(optarg, &end, 10);
            if (!end || *end || pid <= 1 || pid > INT32_MAX) {
                fprintf(stderr, "invalid --attach-pid: %s\n", optarg);
                return 1;
            }
            G.attach_pid = (int)pid;
            break;
        }
        case 'N': G.no_pin = 1; break;
        default: usage(argv[0]); return 1;
        }
    }
    if (!G.bpf_obj || !G.lib_path) { usage(argv[0]); return 1; }

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGUSR1, on_sigusr1);
    if (bump_rlimit() < 0)
        fprintf(stderr, "warning: setrlimit MEMLOCK failed\n");

    if (!G.no_pin) mkdir(PIN_BASE, 0755);

    struct bpf_object *obj = bpf_object__open_file(G.bpf_obj, NULL);
    if (!obj) { perror("open"); return 1; }
    if (!G.no_pin) {
        purge_pinned_maps(obj);          /* legacy shared-pin mode */
        bpf_object__pin_maps(obj, PIN_BASE);
    }

    /* .rodata 주입 */
    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (rodata) {
        size_t value_size = 0;
        struct runtime_config *rcfg = bpf_map__initial_value(rodata, &value_size);
        if (rcfg && value_size >= sizeof(*rcfg)) {
            rcfg->kill_signal = G.kill_signal;
            rcfg->enabled     = 1;
            rcfg->generation  = (__u32)time(NULL);
            rcfg->features    = 0;
            rcfg->max_burst_inspect = 32;
            /* Phase 1 은 mbuf 오프셋 안 쓰지만 동일 struct 사용 */
            rcfg->mbuf_off_buf_addr = 0;
            rcfg->mbuf_off_data_off = 0;
            rcfg->mbuf_off_pkt_len  = 0;
            rcfg->mbuf_off_data_len = 0;
            fprintf(stderr,
                "[resource_loader] runtime_config: kill_signal=%u enabled=1\n",
                rcfg->kill_signal);
        }
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        return 1;
    }

    char libdir[512];
    strncpy(libdir, G.lib_path, sizeof(libdir)-1);
    libdir[sizeof(libdir)-1] = 0;
    {
        char *slash = strrchr(libdir, '/');
        if (slash) *slash = 0; else strcpy(libdir, ".");
    }

    int attached = 0;
    for (size_t i = 0; i < sizeof(HOOKS)/sizeof(HOOKS[0]); i++) {
        const struct hook_target *h = &HOOKS[i];
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, h->prog_uprobe);
        if (!prog) {
            fprintf(stderr, "skip %s: program %s not found\n",
                    h->symbol, h->prog_uprobe);
            continue;
        }
        char hook_lib[600];
        unsigned long off = sym_offset(G.lib_path, h->symbol);
        if (off) {
            snprintf(hook_lib, sizeof(hook_lib), "%s", G.lib_path);
        } else {
            snprintf(hook_lib, sizeof(hook_lib), "%s/%s", libdir, h->libname);
            off = sym_offset(hook_lib, h->symbol);
        }
        if (!off) {
            if (G.verbose) fprintf(stderr, "skip %s: symbol absent in %s and %s\n",
                                   h->symbol, G.lib_path, hook_lib);
            continue;
        }
        struct bpf_link *link = bpf_program__attach_uprobe(
            prog, false, G.attach_pid, hook_lib, off);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "attach uprobe %s failed (lib=%s): %s\n",
                    h->symbol, hook_lib, strerror(-libbpf_get_error(link)));
        } else {
            attached++;
            if (G.verbose) fprintf(stderr, "attached uprobe %s (lib=%s)\n", h->symbol, hook_lib);
        }
        if (h->prog_uretprobe) {
            struct bpf_program *rprog =
                bpf_object__find_program_by_name(obj, h->prog_uretprobe);
            if (rprog) {
                struct bpf_link *rlink = bpf_program__attach_uprobe(
                    rprog, true, G.attach_pid, hook_lib, off);
                if (libbpf_get_error(rlink))
                    fprintf(stderr, "attach uretprobe %s failed (lib=%s)\n", h->symbol, hook_lib);
                else if (G.verbose)
                    fprintf(stderr, "attached uretprobe %s (lib=%s)\n", h->symbol, hook_lib);
            }
        }
    }
    {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, "handle_process_exit");
        if (prog) {
            struct bpf_link *l = bpf_program__attach(prog);
            if (libbpf_get_error(l))
                fprintf(stderr, "attach sched_process_exit failed\n");
        }
    }

    fprintf(stderr, "[resource_loader] attached %d uprobes on %s\n",
            attached, G.lib_path);
    if (!attached) {
        fprintf(stderr, "[resource_loader] no resource hooks attached; refusing ready\n");
        return 1;
    }
    if (G.attach_pid > 0)
        fprintf(stderr, "[resource_loader] scoped uprobe target pid=%d\n", G.attach_pid);

    int pol_fd  = bpf_object__find_map_fd_by_name(obj, "res_policy");
    int stat_fd = bpf_object__find_map_fd_by_name(obj, "pid_res_stats");

    if (pol_fd < 0) { fprintf(stderr, "res_policy map not found\n"); return 1; }
    if (G.policy_path) {
        if (load_policy_file(G.policy_path, pol_fd) < 0) return 1;
    } else {
        struct resource_policy def = { 0 };
        def.action_on_violation = ACT_KILL;
        uint32_t k = 0;
        bpf_map_update_elem(pol_fd, &k, &def, BPF_ANY);
        fprintf(stderr, "[resource_loader] no policy file, default=KILL on violation\n");
    }

    int ev_fd = bpf_object__find_map_fd_by_name(obj, "res_events");
    if (ev_fd < 0) { fprintf(stderr, "res_events map missing\n"); return 1; }
    struct ring_buffer *rb = ring_buffer__new(ev_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf failed\n"); return 1; }

    fprintf(stderr, "[resource_loader] ready. SIGUSR1=dump, SIGINT=exit.\n");
    while (!exiting) {
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
        if (dump_now) {
            dump_now = 0;
            if (stat_fd >= 0) dump_pid_stats(stat_fd);
        }
    }
    if (stat_fd >= 0) dump_pid_stats(stat_fd);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}

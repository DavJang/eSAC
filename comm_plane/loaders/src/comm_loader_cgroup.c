/*
 * comm_loader.c
 * --------------------------------------------------------------
 * Phase 2 통신 접근 제어 로더.
 *
 * 책임:
 *   1) comm_filter.bpf.o 를 연다.
 *   2) tools/discover_offsets 가 출력한 mbuf 오프셋을
 *      libbpf .rodata (runtime_config) 에 주입한다.
 *   3) BPF load.
 *   4) RX 후킹:
 *      - API level: librte_ethdev.so 의 rte_eth_rx_burst 에 uprobe+uretprobe
 *      - 실패 시 Driver level: --pmd-lib 의 드라이버 함수에 uprobe+uretprobe
 *        (mlx5_rx_burst_*, i40e_recv_pkts, ixgbe_recv_pkts_*, ice_recv_pkts)
 *   5) TX 후킹 (Driver level 전용):
 *      - --pmd-lib 의 드라이버 TX 함수에 uprobe entry
 *        (mlx5_tx_burst_empw, i40e_xmit_pkts, ixgbe_xmit_pkts, ice_xmit_pkts)
 *      - TX는 API(rte_eth_tx_burst)가 inline 컴파일되어 심볼 없음 → 드라이버만 가능
 *   6) comm_policy.json 을 파싱해 comm_policy 맵에 주입.
 *   7) comm_events ringbuf 폴링.
 *   8) SIGUSR1 수신 시 queue_stats / lat_hist 합산해서 stderr 에 출력.
 *
 * 빌드: gcc comm_loader.c -o comm_loader -lbpf -lelf -lz
 *
 * 실행 예:
 *   # API level RX + Driver level TX (권장)
 *   sudo ./comm_loader \
 *     --bpf ./ebpf/comm_filter.bpf.o \
 *     --lib /usr/local/lib/x86_64-linux-gnu/librte_ethdev.so \
 *     --pmd-lib /usr/local/lib/x86_64-linux-gnu/librte_net_mlx5.so \
 *     --offsets ./tools/offsets.json \
 *     --policy comm_policy.json \
 *     --enforcement
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <poll.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ebpf/bpftime_variant/common_cgroup.h"

/* --------------------------------------------------------------------- */
/*  드라이버 레벨 심볼 목록                                               */
/* --------------------------------------------------------------------- */

/*
 * RX 드라이버 함수 심볼 목록.
 * API(rte_eth_rx_burst) 후킹 실패 시 순서대로 시도.
 * signature: uint16_t fn(void *rxq, rte_mbuf **rx_pkts, uint16_t nb_pkts)
 */
static const char *RX_DRIVER_SYMS[] = {
    "ixgbe_recv_scattered_pkts_vec", /* ixgbe scatter+vec (VPP) */
    "ixgbe_recv_scattered_burst_vec", /* ixgbe scatter burst+vec */
    "ixgbe_recv_pkts_vec",   /* ixgbe NIC vec (82599ES) */
    "ixgbe_recv_pkts",      /* ixgbe NIC (82599ES) */
    "eth_ring_rx",          /* net_ring vdev */
    "mlx5_rx_burst",
    "mlx5_rx_burst_mprq",
    "mlx5_rx_burst_vec",
    "mlx5_rx_burst_mprq_vec",
    "i40e_recv_pkts",
    "i40e_recv_pkts_vec",
    "i40e_recv_scattered_pkts",
    "ixgbe_recv_scattered_pkts",
    "ice_recv_pkts",
    "ice_recv_pkts_vec",
    NULL
};

/*
 * TX 드라이버 함수 심볼 목록.
 * rte_eth_tx_burst는 inline → 심볼 없음 → 항상 드라이버 레벨만 가능.
 * signature: uint16_t fn(void *txq, rte_mbuf **tx_pkts, uint16_t nb_pkts)
 */
static const char *TX_DRIVER_SYMS[] = {
    "ixgbe_xmit_pkts_vec",        /* ixgbe vec burst (82599ES) */
    "ixgbe_xmit_pkts",      /* ixgbe NIC (82599ES) */
    "eth_ring_tx",          /* net_ring vdev */
    "mlx5_tx_burst_empw",
    "mlx5_tx_burst",
    "mlx5_tx_burst_vec",
    "i40e_xmit_pkts",
    "i40e_xmit_pkts_vec",
    "i40e_xmit_pkts_simple",
    "ixgbe_xmit_pkts_vec",
    "ice_xmit_pkts",
    "ice_xmit_pkts_vec",
    NULL
};

static volatile sig_atomic_t exiting  = 0;
static volatile sig_atomic_t dump_now = 0;
static void on_sigint(int s)  { (void)s; exiting = 1; }
static void on_sigusr1(int s) { (void)s; dump_now = 1; }

static volatile int g_prologue_watchdog_run = 1;

/* ── Prologue Integrity Watchdog (RDNet-style process_vm_readv) ──────────
 * bpftime mode에서 악의적 테넌트가 PMD 함수 프롤로그를 복원해 후크를
 * 제거하는 공격을 탐지한다.
 * comm_loader 가 --pid <pid> 를 받으면:
 *   (1) 대상 프로세스 메모리에서 각 PMD 심볼의 런타임 주소를 계산
 *   (2) uprobe/bpftime 패치 직후의 기대 바이트를 스냅샷
 *   (3) PROLOGUE_POLL_US 마다 process_vm_readv 로 재확인
 *   (4) 불일치 → SIGKILL + 로그
 */
#define PROLOGUE_BYTES      8
#define PROLOGUE_POLL_US    1000   /* 1 ms */
#define PROLOGUE_WATCH_MAX  8

struct prologue_watch_entry {
    pid_t    pid;
    uint64_t vaddr;               /* 대상 프로세스 내 런타임 가상 주소 */
    unsigned long file_off;
    char     lib_path[PATH_MAX];
    uint8_t  expected[PROLOGUE_BYTES];
    char     sym_name[64];
    int      valid;               /* expected 스냅샷 완료 여부 */
};

static struct prologue_watch_entry g_pw[PROLOGUE_WATCH_MAX];
static int    g_pw_count    = 0;
static pid_t  g_target_pid  = -1;  /* --pid 로 지정된 대상 PID */

/* Resolve the ELF load bias from the matching /proc/<pid>/maps entry.
 * Never fall back to an unrelated executable while the target still runs
 * its stopped shell wrapper. */
static uint64_t get_aslr_base(pid_t pid, const char *lib_path)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "[watchdog] cannot open %s: %s\n",
                maps_path, strerror(errno));
        return 0;
    }

    const char *bname = strrchr(lib_path, '/');
    const char *name  = bname ? bname + 1 : lib_path;

    char line[512];
    uint64_t by_fullpath = 0, by_basename = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, file_off = 0;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &file_off) != 4 ||
            start < file_off) continue;
        /* The symbol offset is ELF virtual address, so subtract the
         * mapping's file offset to obtain the PIE/shared-object load bias. */
        if (!by_fullpath && strstr(line, lib_path))
            by_fullpath = start - file_off;
        if (!by_basename && strstr(line, name))
            by_basename = start - file_off;
    }
    fclose(f);

    uint64_t base = by_fullpath ? by_fullpath : by_basename;

    if (!base) {
        fprintf(stderr,
            "[watchdog] ASLR base not found for '%s' in pid=%d\n",
            lib_path, (int)pid);
    } else {
        fprintf(stderr,
            "[watchdog] ASLR base pid=%d: 0x%lx (%s)\n",
            (int)pid, base,
            by_fullpath ? "full-path" : "basename");
    }
    return base;
}

/* process_vm_readv 로 대상 프로세스의 vaddr 에서 n 바이트 읽기 */
static int read_prologue(pid_t pid, uint64_t vaddr, uint8_t *buf, size_t n)
{
    struct iovec local_iov  = { buf, n };
    struct iovec remote_iov = { (void *)(uintptr_t)vaddr, n };
    ssize_t r = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    return (r == (ssize_t)n) ? 0 : -1;
}

/* 감시 대상 PMD 심볼 등록
 *   lib_path: 심볼이 있는 바이너리/라이브러리 경로
 *   file_off: sym_offset() 이 반환한 파일 오프셋
 *   sym_name: 로그용 심볼 이름
 */
static void pw_register(const char *lib_path, unsigned long file_off,
                         const char *sym_name)
{
    if (g_target_pid <= 0 || g_pw_count >= PROLOGUE_WATCH_MAX) return;

    struct prologue_watch_entry *e = &g_pw[g_pw_count++];
    e->pid   = g_target_pid;
    e->file_off = file_off;
    snprintf(e->lib_path, sizeof(e->lib_path), "%s", lib_path);
    e->vaddr = 0; /* resolve after the paused tenant execs its real image */
    e->valid = 0;
    snprintf(e->sym_name, sizeof(e->sym_name), "%s", sym_name);
    fprintf(stderr, "[watchdog] registered: %s pending tenant exec (off=0x%lx)\n",
            sym_name, file_off);
}

static void *watchdog_prologue_thread(void *arg)
{
    (void)arg;

    /* The tenant resumes only after loader attachment. Resolve the binary
     * after exec, then wait for the agent's x86 jump patch before snapshot. */

    /* The loader attaches while the tenant is paused in a shell wrapper.
     * Resolve its mappings only after the agent has loaded in the tenant. */
    for (int attempt = 0; attempt < 100; attempt++) {
        int found = 0;
        for (int i = 0; i < g_pw_count; i++) {
            if (g_pw[i].vaddr) { found++; continue; }
            uint64_t base = get_aslr_base(g_pw[i].pid, g_pw[i].lib_path);
            if (base) {
                g_pw[i].vaddr = base + g_pw[i].file_off;
                fprintf(stderr, "[watchdog] resolved: %s vaddr=0x%lx\n",
                        g_pw[i].sym_name, (unsigned long)g_pw[i].vaddr);
                found++;
            }
        }
        if (found == g_pw_count) break;
        usleep(100000);
    }

    int patched = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        patched = 0;
        for (int i = 0; i < g_pw_count; i++) {
            uint8_t bytes[PROLOGUE_BYTES];
            if (g_pw[i].vaddr &&
                read_prologue(g_pw[i].pid, g_pw[i].vaddr, bytes, sizeof(bytes)) == 0 &&
                bytes[0] == 0xe9)
                patched++;
        }
        if (patched == g_pw_count) break;
        usleep(100000);
    }
    if (patched != g_pw_count) {
        fprintf(stderr, "[watchdog] ERROR: agent prologue patch incomplete (%d/%d)\n",
                patched, g_pw_count);
        return NULL;
    }
    usleep(100000); /* ensure the patch bytes remain stable before snapshot */

    /* 기대 바이트 스냅샷 */
    for (int i = 0; i < g_pw_count; i++) {
        if (!g_pw[i].vaddr) continue;
        if (read_prologue(g_pw[i].pid, g_pw[i].vaddr,
                          g_pw[i].expected, PROLOGUE_BYTES) == 0) {
            g_pw[i].valid = 1;
            fprintf(stderr,
                "[watchdog] snapshot %s: %02x %02x %02x %02x %02x ...\n",
                g_pw[i].sym_name,
                g_pw[i].expected[0], g_pw[i].expected[1],
                g_pw[i].expected[2], g_pw[i].expected[3],
                g_pw[i].expected[4]);
        } else {
            fprintf(stderr,
                "[watchdog] WARN: snapshot failed for %s (pid=%d) vaddr=0x%lx errno=%d (%s)\n",
                g_pw[i].sym_name, (int)g_pw[i].pid,
                (unsigned long)g_pw[i].vaddr,
                errno, strerror(errno));
        }
    }

    if (g_pw_count == 0) {
        fprintf(stderr, "[watchdog] prologue thread: no entries — exiting\n");
        return NULL;
    }

    fprintf(stderr,
        "[watchdog] prologue integrity active: %d hook(s), poll=%d μs\n",
        g_pw_count, PROLOGUE_POLL_US);

    while (g_prologue_watchdog_run) {
        usleep(PROLOGUE_POLL_US);

        for (int i = 0; i < g_pw_count; i++) {
            if (!g_pw[i].valid) continue;

            uint8_t cur[PROLOGUE_BYTES];
            if (read_prologue(g_pw[i].pid, g_pw[i].vaddr,
                              cur, PROLOGUE_BYTES) < 0)
                continue;  /* 프로세스 종료 등 */

            if (memcmp(cur, g_pw[i].expected, PROLOGUE_BYTES) != 0) {
                fprintf(stderr,
                    "\n[GOWN watchdog] *** INTEGRITY VIOLATION ***\n"
                    "  hook: %s  pid=%d  vaddr=0x%lx\n"
                    "  expected: %02x %02x %02x %02x %02x %02x %02x %02x\n"
                    "  found:    %02x %02x %02x %02x %02x %02x %02x %02x\n"
                    "  → PMD prologue tampered; sending SIGKILL\n",
                    g_pw[i].sym_name, (int)g_pw[i].pid,
                    (unsigned long)g_pw[i].vaddr,
                    g_pw[i].expected[0], g_pw[i].expected[1],
                    g_pw[i].expected[2], g_pw[i].expected[3],
                    g_pw[i].expected[4], g_pw[i].expected[5],
                    g_pw[i].expected[6], g_pw[i].expected[7],
                    cur[0], cur[1], cur[2], cur[3],
                    cur[4], cur[5], cur[6], cur[7]);

                {
                    struct timespec __ts;
                    clock_gettime(CLOCK_REALTIME, &__ts);
                    fprintf(stderr, "[GOWN watchdog] SIGKILL_SENT_EPOCH=%ld.%09ld\n",
                            (long)__ts.tv_sec, __ts.tv_nsec);
                }
                kill(g_pw[i].pid, SIGKILL);
                g_prologue_watchdog_run = 0;
                return NULL;
            }
        }
    }
    return NULL;
}

struct options {
    const char *bpf_obj;
    const char *lib_path;       /* librte_ethdev.so (API level RX) */
    const char *pmd_lib_path;       /* librte_net_mlx5.so 등 (Driver level RX/TX) */
    const char *pmd_debug_lib_path; /* stripped .so의 debug 심볼 파일 (nm 전용, ASLR base는 pmd_lib_path 사용) */
    const char *policy_path;
    const char *offsets_path;
    int json;
    int verbose;
    int enforcement;
    int frag_drop;
    int malformed_drop;
    int vlan_count;
    int latency_sample;
    int max_burst_inspect;
    int no_pin;   /* --no-pin: bpftime 모드용, map pinning 비활성화 */
    int pid;      /* --pid: 프롤로그 무결성 워치독 대상 PID (-1 = 비활성) */
    int attach_pids[8]; /* --attach-pid: 지정한 프로세스에만 uprobe 부착 */
    int attach_pid_count;
};
static struct options G;

/* Candidate pilot: resolve a scoped host PID to its cgroup-v2 inode. */
static int host_cgroup_id(int pid, __u64 *id)
{
    char proc_path[64], line[PATH_MAX], cg_path[PATH_MAX];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(proc_path, "r");
    if (!f) return -1;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3)) continue;
        char *p = line + 3;
        p[strcspn(p, "\r\n")] = 0;
        if (p[0] != '/' || !strcmp(p, "/") ||
            snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup%s", p) >= (int)sizeof(cg_path)) break;
        struct stat st;
        if (stat(cg_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            *id = (__u64)st.st_ino;
            found = 1;
        }
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

static int parse_attach_pid(const char *arg)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(arg, &end, 10);
    if (errno || !arg[0] || *end || value <= 0 || value > INT_MAX ||
        G.attach_pid_count >= 8) return -1;
    for (int i = 0; i < G.attach_pid_count; i++)
        if (G.attach_pids[i] == (int)value) return -1;
    G.attach_pids[G.attach_pid_count++] = (int)value;
    return 0;
}

/* Every program in a pair must attach to every requested PID. An agent in
 * another process must not inherit a kernel uprobe from this registration. */
static int attach_uprobe_pair_scoped(struct bpf_program *entry,
                                    struct bpf_program *ret,
                                    const char *path, unsigned long off)
{
    struct bpf_link *entries[8] = {0}, *returns[8] = {0};
    int n = G.attach_pid_count;
    for (int i = 0; i < n; i++) {
        int pid = G.attach_pids[i];
        entries[i] = bpf_program__attach_uprobe(entry, false, pid, path, off);
        returns[i] = bpf_program__attach_uprobe(ret, true, pid, path, off);
        if (libbpf_get_error(entries[i]) || libbpf_get_error(returns[i])) {
            for (int j = 0; j <= i; j++) {
                if (!libbpf_get_error(entries[j])) bpf_link__destroy(entries[j]);
                if (!libbpf_get_error(returns[j])) bpf_link__destroy(returns[j]);
            }
            return 0;
        }
    }
    return 1;
}

static int attach_uprobe_scoped(struct bpf_program *prog, bool ret,
                                const char *path, unsigned long off)
{
    struct bpf_link *links[8] = {0};
    int n = G.attach_pid_count;
    for (int i = 0; i < n; i++) {
        int pid = G.attach_pids[i];
        links[i] = bpf_program__attach_uprobe(prog, ret, pid, path, off);
        if (libbpf_get_error(links[i])) {
            for (int j = 0; j < i; j++) bpf_link__destroy(links[j]);
            return 0;
        }
    }
    return 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s --bpf <comm_filter.bpf.o> --lib <librte_ethdev.so>\n"
        "          --offsets <path>     mbuf 오프셋 파일 (필수)\n"
        "          [--pmd-lib <path>]   PMD 드라이버 라이브러리 (드라이버 레벨 후킹)\n"
        "                               예: /usr/local/lib/x86_64-linux-gnu/librte_net_mlx5.so\n"
        "                               RX fallback 및 TX 후킹에 필요\n"
        "          [--policy <file>] [--json] [-v]\n"
        "          [--enforcement] [--frag-drop] [--malformed-drop]\n"
        "          [--vlan-count] [--latency-sample]\n"
        "          [--max-burst-inspect N]\n"
        "          [--no-pin]   bpftime 모드: map pinning 비활성화 (EINVAL 회피)\n"
          "          [--pid <pid>]  프롤로그 무결성 워치독 대상 PID\n"
          "                         (bpftime 모드에서 후크 제거 공격 탐지)\n"
          "          [--attach-pid <pid>]  uprobe 대상 PID (반복 지정 가능)\n",
        prog);
}

/* ---- 오프셋 파일 ---- */
struct mbuf_offsets { int buf_addr, data_off, pkt_len, data_len, all_set; };
static int load_offsets(const char *path, struct mbuf_offsets *o)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    memset(o, 0, sizeof(*o));
    char line[256];
    int got = 0;
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        int v = atoi(eq + 1);
        if      (!strcmp(line, "buf_addr")) { o->buf_addr = v; got++; }
        else if (!strcmp(line, "data_off")) { o->data_off = v; got++; }
        else if (!strcmp(line, "pkt_len"))  { o->pkt_len  = v; got++; }
        else if (!strcmp(line, "data_len")) { o->data_len = v; got++; }
    }
    fclose(f);
    o->all_set = (got == 4);
    return o->all_set ? 0 : -1;
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


/* ---- tail-call stub 자동 우회 ---------------------------------------
 * 일부 PMD의 *_vec RX/TX 래퍼(예: ixgbe_recv_pkts_vec)는 실제 작업을
 * 하는 내부 함수(_recv_raw_pkts_vec 등)로 jmp 하나만 하는 수바이트짜리
 * tail-call 스텁이다. 커널 uprobe는 1바이트 INT3 패치만 하므로 문제가
 * 없지만, bpftime/Frida의 유저스페이스 트램폴린 주입은 함수 자체보다
 * 큰 코드를 써야 해서 이런 초소형 함수를 후킹하면 마지막 jmp(또는
 * 바로 다음 함수 영역)가 깨져 실제 트래픽이 흐르는 순간 세그폴트가
 * 난다 (2026-09-21 l3fwd bpftime 실험에서 최초 발견: gdb core backtrace
 * + objdump로 근본원인 확인, ixgbe_recv_pkts_vec 14바이트 스텁).
 *
 * sym_size()로 심볼 크기를 얻고, STUB_MAX_SIZE 이하이면서 마지막
 * 5바이트가 근접 jmp(0xE9 rel32)이면 실제 점프 타겟 주소를 계산해서
 * 그쪽에 후킹한다. 타겟 함수도 동일한 x86-64 SysV 레지스터
 * (rdi/rsi/edx = rxq/rx_pkts/nb_pkts)로 진입하므로 BPF_UPROBE 인자
 * 추출은 그대로 유효하다.
 */
#define STUB_MAX_SIZE 32

static unsigned long sym_size(const char *lib, const char *sym)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "nm -S '%s' 2>/dev/null | awk '$4==\"%s\"{print $2; exit}'", lib, sym);
    FILE *f = popen(cmd, "r");
    unsigned long sz = 0;
    if (f) { if (fscanf(f, "%lx", &sz) != 1) sz = 0; pclose(f); }
    return sz;
}

static unsigned long resolve_tailcall_stub(const char *lib, unsigned long off,
                                            const char *symname)
{
    unsigned long size = sym_size(lib, symname);
    if (size < 5 || size > STUB_MAX_SIZE) return off;

    FILE *f = fopen(lib, "rb");
    if (!f) return off;
    unsigned char buf[STUB_MAX_SIZE];
    int ok = (fseek(f, (long)off, SEEK_SET) == 0 &&
              fread(buf, 1, size, f) == size);
    fclose(f);
    if (!ok) return off;

    unsigned char *tail = buf + size - 5;
    if (tail[0] != 0xE9) return off;   /* 근접 jmp rel32 아님 */

    int32_t rel;
    memcpy(&rel, tail + 1, 4);
    unsigned long jmp_off = off + (size - 5);
    unsigned long target  = jmp_off + 5 + (long)rel;

    fprintf(stderr,
        "[comm] %s is a %lu-byte tail-call stub -> redirecting hook to "
        "true target @ 0x%lx (too small to safely trampoline under bpftime)\n",
        symname, size, target);
    return target;
}

/* ---- 정책 JSON (간소) ---- */
static int json_u64(const char *blob, const char *key, uint64_t *out)
{
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(blob, pat); if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\n' || *p == '\t') p++;
    if (*p == '"') return -1;
    char *end; unsigned long long v = strtoull(p, &end, 10);
    if (end == p) return -1;
    *out = v; return 0;
}
static int json_str(const char *blob, const char *key, char *out, size_t sz)
{
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(blob, pat); if (!p) return -1;
    p = strchr(p, ':'); if (!p) return -1; p++;
    while (*p == ' ' || *p == '\n' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0; while (*p && *p != '"' && i + 1 < sz) out[i++] = *p++;
    out[i] = 0; return 0;
}
static uint32_t act_of(const char *s)
{
    if (!strcasecmp(s, "ALLOW")) return ACT_ALLOW;
    if (!strcasecmp(s, "DROP"))  return ACT_DROP;
    if (!strcasecmp(s, "KILL"))  return ACT_KILL;
    return UINT32_MAX;
}
static uint32_t ip_of(const char *s)
{
    if (!s || !*s) return 0;
    struct in_addr a;
    if (inet_aton(s, &a) == 0) return 0;
    return a.s_addr;  /* FIX(2026-09-18): inet_aton() already returns network byte order; removed erroneous ntohl() that flipped it to host order and broke comm_policy IP matching */
}
/* opt3: build the per-(class,probe) presence mask from the policy.
 * bit = base + probe;  base = (cgroup!=0?0:10) + (src_port!=0?0:5);
 * probe P0 sip!=0&dip!=0&dp!=0 / P1 sip0,dipA,dpA / P2 sip0,dip0,dpA /
 *       P3 sip0,dipA,dp0 / P4 sip0,dip0,dp0.  Rules not fitting a probe
 * pattern are unmatchable by the lattice (same as original) -> no bit. */
static unsigned int compute_probe_mask(const char *path)
{
    FILE *f = fopen(path, "r"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return 0; }
    char *blob = malloc(sz + 1); if (!blob) { fclose(f); return 0; }
    if (fread(blob, 1, sz, f) != (size_t)sz) { free(blob); fclose(f); return 0; }
    blob[sz] = 0; fclose(f);
    const char *rules = strstr(blob, "\"rules\""); if (!rules) { free(blob); return 0; }
    const char *p = strchr(rules, '['); if (!p) { free(blob); return 0; } p++;
    unsigned int mask = 0;
    while (1) {
        const char *open = strchr(p, '{'); if (!open) break;
        int depth = 1; const char *q = open + 1;
        while (*q && depth) { if (*q=='{') depth++; else if (*q=='}') depth--; q++; }
        if (depth) break;
        char *block = strndup(open, q - open);
        char layer[8] = "L2", sip_s[32] = "0.0.0.0", dip_s[32] = "0.0.0.0";
        uint64_t sport = 0, dport = 0, cgroup_id = 0;
        json_str(block, "layer", layer, sizeof(layer));
        json_str(block, "src_ip", sip_s, sizeof(sip_s));
        json_str(block, "dst_ip", dip_s, sizeof(dip_s));
        json_u64(block, "src_port", &sport);
        json_u64(block, "dst_port", &dport);
        json_u64(block, "cgroup_id", &cgroup_id);
        if (strcasecmp(layer, "L1")) {
            unsigned int base = (cgroup_id != 0 ? 0u : 10u) + (sport != 0 ? 0u : 5u);
            uint32_t sip = ip_of(sip_s), dip = ip_of(dip_s);
            int probe = -1;
            if (sip != 0 && dip != 0 && dport != 0) probe = 0;
            else if (sip == 0 && dip != 0 && dport != 0) probe = 1;
            else if (sip == 0 && dip == 0 && dport != 0) probe = 2;
            else if (sip == 0 && dip != 0 && dport == 0) probe = 3;
            else if (sip == 0 && dip == 0 && dport == 0) probe = 4;
            if (probe >= 0) mask |= (1u << (base + (unsigned)probe));
        }
        free(block); p = q;
    }
    free(blob);
    return mask;
}

static int load_comm_policy(const char *path, int map_fd)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    char *blob = malloc(sz + 1);
    if (!blob) { fclose(f); return -1; }
    if (fread(blob, 1, sz, f) != (size_t)sz) {
        free(blob); fclose(f); return -1;
    }
    blob[sz] = 0; fclose(f);
    const char *rules = strstr(blob, "\"rules\"");
    if (!rules) { fprintf(stderr, "comm: no rules\n"); free(blob); return -1; }
    const char *p = strchr(rules, '[');
    if (!p) { free(blob); return -1; }
    p++;
    int l2 = 0, l1 = 0;
    while (1) {
        const char *open = strchr(p, '{');
        if (!open) break;
        int depth = 1; const char *q = open + 1;
        while (*q && depth) {
            if (*q == '{') depth++;
            else if (*q == '}') depth--;
            q++;
        }
        if (depth) break;
        size_t blen = q - open;
        char *block = strndup(open, blen);
        char layer[8] = "L2", action[16] = "";
        char sip_s[32] = "0.0.0.0", dip_s[32] = "0.0.0.0";
        uint64_t proto = 0, sport = 0, dport = 0, cgroup_id = 0;
        json_str(block, "layer", layer, sizeof(layer));
        json_str(block, "action", action, sizeof(action));
        uint32_t parsed_action = act_of(action);
        if (parsed_action == UINT32_MAX) {
            fprintf(stderr, "comm: invalid or missing action '%s'\n", action);
            free(block);
            free(blob);
            return -1;
        }
        json_str(block, "src_ip", sip_s, sizeof(sip_s));
        json_str(block, "dst_ip", dip_s, sizeof(dip_s));
        json_u64(block, "proto", &proto);
        json_u64(block, "src_port", &sport);
        json_u64(block, "dst_port", &dport);
        /* F-7: cgroup_id 파싱 — 없으면 0 (wildcard, 모든 cgroup에 적용) */
        json_u64(block, "cgroup_id", &cgroup_id);
        if (!strcasecmp(layer, "L1")) {
            fprintf(stderr,
                "[comm] L1 rule (HW flow) proto=%llu dst_port=%llu action=%s"
                " -- install via rte_flow externally\n",
                (unsigned long long)proto, (unsigned long long)dport, action);
            l1++;
        } else {
            struct comm_policy_key k = {};
            struct comm_policy_value v = {};
            k.cgroup_id = (uint64_t)cgroup_id;  /* 0 = wildcard */
            k.protocol  = (uint8_t)proto;
            k.dst_port  = (uint16_t)dport;
            k.src_port  = (uint16_t)sport;
            k.src_ip    = ip_of(sip_s);
            k.dst_ip    = ip_of(dip_s);
            k.layer     = 2;
            v.action    = parsed_action;
            if (bpf_map_update_elem(map_fd, &k, &v, BPF_ANY) < 0)
                fprintf(stderr, "comm: update failed proto=%u dport=%u cgroup=%llu: %s\n",
                        k.protocol, k.dst_port,
                        (unsigned long long)k.cgroup_id, strerror(errno));
            else l2++;
        }
        free(block);
        p = q;
    }
    fprintf(stderr, "[comm] L2 rules loaded=%d, L1 listed=%d\n", l2, l1);
    free(blob);
    return 0;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct comm_event)) {
        fprintf(stderr, "[comm] short event: %zu bytes\n", sz);
        return 0;
    }
    const struct comm_event *e = data;
    char sip[16], dip[16];
    struct in_addr a;
    /* BPF copies IPv4 bytes directly from the packet; they are already
     * in network byte order. Swapping again reverses addresses in logs. */
    a.s_addr = e->src_ip; inet_ntop(AF_INET, &a, sip, sizeof(sip));
    a.s_addr = e->dst_ip; inet_ntop(AF_INET, &a, dip, sizeof(dip));
    /* PATCHED (2026-09-21, bpftime overhead debug): disabled per-event
     * printf+fflush(stdout). Under sustained real traffic (10k cps ALLOW
     * policy), this synchronous I/O per packet event could not keep up
     * with the comm_events ringbuf producer rate, causing "Failed to
     * reserve" (ringbuf full) and possibly exacerbating a bpftime-runtime
     * crash under sustained backpressure. KILL logging below is untouched
     * (separate fprintf(stderr,...) block, not gated by this). */
    static unsigned drop_event_samples;
    if (G.verbose && e->action_taken == ACT_DROP && drop_event_samples++ < 20)
        fprintf(stderr,
                "[comm] ACT_DROP sample: pid=%u dir=%s tuple=%s:%u -> %s:%u proto=%u burst=%u dropped=%u\n",
                e->pid, e->hook_dir == 1 ? "RX" : e->hook_dir == 2 ? "TX" : "UNKNOWN",
                sip, e->src_port, dip, e->dst_port, e->protocol,
                e->nb_pkts_returned, e->nb_pkts_dropped);

    /*
     * bpftime에는 커널 전용 헬퍼인 bpf_send_signal()이 없어서 BPF
     * 프로그램 안에서 직접 시그널을 보낼 수 없다 (comm_filter_bpftime.bpf.c
     * 참고). 대신 여기 유저스페이스 loader가 comm_events로 ACT_KILL
     * 이벤트를 받으면 대상 PID만 정확히 SIGKILL한다 (watchdog의
     * kill(g_pw[i].pid, SIGKILL) 패턴과 동일 — cgroup 전체가 아니라
     * 단일 프로세스만 타겟팅하므로 loader 자기 자신은 안전하다).
     */
    if (e->action_taken == ACT_KILL) {
        if (G.attach_pid_count) {
            int allowed = 0;
            for (int i = 0; i < G.attach_pid_count; i++)
                if (e->pid == (__u32)G.attach_pids[i]) allowed = 1;
            if (!allowed) {
                fprintf(stderr, "[comm] REJECT KILL event for out-of-scope pid=%u\n",
                        e->pid);
                return 0;
            }
        }
        {
            struct timespec __kts;
            clock_gettime(CLOCK_MONOTONIC, &__kts);
            fprintf(stderr, "[comm] KILL_CALL_EPOCH=%ld.%09ld pid=%u\n",
                    (long)__kts.tv_sec, __kts.tv_nsec, e->pid);
        }
        fprintf(stderr,
            "[comm] ACT_KILL event: pid=%u dir=%s -- sending SIGKILL "
            "(loader enforcement)\n", e->pid,
            e->hook_dir == 1 ? "RX" : e->hook_dir == 2 ? "TX" : "UNKNOWN");
        if (kill((pid_t)e->pid, SIGKILL) < 0) {
            fprintf(stderr, "[comm] kill(%u, SIGKILL) failed: %s\n",
                    e->pid, strerror(errno));
        } else {
            fprintf(stderr, "[comm] SIGKILL_SENT pid=%u\n", e->pid);
        }
    }

    return 0;
}

/* ---- 통계 덤프 ---- */
static int ncpus(void) { int n = get_nprocs_conf(); return n > 0 ? n : 1; }
static void dump_queue_stats(int fd)
{
    int n = ncpus();
    struct queue_stats *per = calloc(n, sizeof(*per));
    if (!per) return;
    fprintf(stderr,
        "\n===== queue_stats =====\n"
        "%-6s %-6s %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
        "port", "queue", "rx", "tx", "drop",
        "allow", "frag", "malformed", "vlan", "rx_0burst", "tx_drop",
        "policy_hits", "parse_fail");
    __u32 key, next;
    int first = 1;
    while (1) {
        int r = first ? bpf_map_get_next_key(fd, NULL, &next)
                      : bpf_map_get_next_key(fd, &key, &next);
        if (r != 0) break;
        first = 0; key = next;
        memset(per, 0, n * sizeof(*per));
        if (bpf_map_lookup_elem(fd, &key, per) < 0) continue;
        struct queue_stats s = {};
        for (int i = 0; i < n; i++) {
            s.rx             += per[i].rx;
            s.tx             += per[i].tx;
            s.drop           += per[i].drop;
            s.allow          += per[i].allow;
            s.vlan_seen      += per[i].vlan_seen;
            s.frag_drop      += per[i].frag_drop;
            s.malformed_drop += per[i].malformed_drop;
            s.policy_hits    += per[i].policy_hits;
            s.parse_fail     += per[i].parse_fail;
            s.rx_zero_burst  += per[i].rx_zero_burst;
            s.tx_drop        += per[i].tx_drop;
        }
        fprintf(stderr,
            "%-6u %-6u %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu %-12llu\n",
            key >> 16, key & 0xffff,
            (unsigned long long)s.rx,   (unsigned long long)s.tx,
            (unsigned long long)s.drop,
            (unsigned long long)s.allow,
            (unsigned long long)s.frag_drop,
            (unsigned long long)s.malformed_drop,
            (unsigned long long)s.vlan_seen,
            (unsigned long long)s.rx_zero_burst,
            (unsigned long long)s.tx_drop,
            (unsigned long long)s.policy_hits,
            (unsigned long long)s.parse_fail);
    }
    free(per);
}
static void dump_latency_named(int fd, const char *label)
{
    int n = ncpus();
    struct latency_hist *per = calloc(n, sizeof(*per));
    if (!per) return;
    __u32 k = 0;
    if (bpf_map_lookup_elem(fd, &k, per) < 0) { free(per); return; }
    struct latency_hist agg = {};
    for (int i = 0; i < n; i++) {
        agg.sum   += per[i].sum;
        agg.count += per[i].count;
        if (per[i].max > agg.max) agg.max = per[i].max;
        for (int b = 0; b < LAT_BUCKETS; b++)
            agg.buckets[b] += per[i].buckets[b];
    }
    if (agg.count == 0) { free(per); return; }
    fprintf(stderr,
        "\n===== %s =====\n"
        "samples=%llu  avg(ns)=%.1f  max(ns)=%llu\n",
        label,
        (unsigned long long)agg.count,
        (double)agg.sum / agg.count,
        (unsigned long long)agg.max);
    __u64 cum = 0;
    __u64 t50 = agg.count*50/100, t95 = agg.count*95/100, t99 = agg.count*99/100;
    __u64 p50 = 0, p95 = 0, p99 = 0;
    for (int b = 0; b < LAT_BUCKETS; b++) {
        cum += agg.buckets[b];
        __u64 hi = 1ULL << (b + 1);
        if (!p50 && cum >= t50) p50 = hi;
        if (!p95 && cum >= t95) p95 = hi;
        if (!p99 && cum >= t99) p99 = hi;
    }
    fprintf(stderr,
        "p50<=%llu ns  p95<=%llu ns  p99<=%llu ns\n",
        (unsigned long long)p50, (unsigned long long)p95, (unsigned long long)p99);
    free(per);
}

static void dump_latency(int fd) { dump_latency_named(fd, "rx_latency"); }

/* 이전 실행에서 남은 pinned BPF 맵을 자동 삭제 */
static void purge_pinned_maps(struct bpf_object *obj)
{
    (void)obj;
    /* bpf_object__for_each_map / bpf_map__next API varies by libbpf version.
     * Stale pins are removed by the CLEAN() helper in experiment scripts
     * (rm -rf /sys/fs/bpf/guard), so this function is a safe no-op. */
}

/* ---- main ---- */
static int bump_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

int main(int argc, char **argv)
{
    static struct option lopts[] = {
        { "bpf",                required_argument, 0, 'b' },
        { "lib",                required_argument, 0, 'l' },
        { "pmd-lib",            required_argument, 0, 'P' },
        { "policy",             required_argument, 0, 'p' },
        { "offsets",            required_argument, 0, 'o' },
        { "json",               no_argument,       0, 'j' },
        { "verbose",            no_argument,       0, 'v' },
        { "enforcement",        no_argument,       0, 'E' },
        { "frag-drop",          no_argument,       0, 'F' },
        { "malformed-drop",     no_argument,       0, 'M' },
        { "vlan-count",         no_argument,       0, 'V' },
        { "latency-sample",     no_argument,       0, 'L' },
        { "max-burst-inspect",  required_argument, 0, 'B' },
        { "no-pin",             no_argument,       0, 'N' },
        { "pid",                required_argument, 0, 'D' },
        { "attach-pid",         required_argument, 0, 'A' },
        { "pmd-debug-lib",      required_argument, 0, 'G' },
        { 0, 0, 0, 0 }
    };
    G.max_burst_inspect = 32;
    /* Preserve the official object's active default when .rodata is applied. */
    G.latency_sample = 1;
    G.pid = -1;
    int c;
    while ((c = getopt_long(argc, argv, "b:l:P:p:o:jvEFMVLB:ND:G:A:", lopts, NULL)) != -1) {
        switch (c) {
        case 'b': G.bpf_obj             = optarg; break;
        case 'l': G.lib_path            = optarg; break;
        case 'P': G.pmd_lib_path        = optarg; break;
        case 'G': G.pmd_debug_lib_path  = optarg; break;
        case 'p': G.policy_path   = optarg; break;
        case 'o': G.offsets_path  = optarg; break;
        case 'j': G.json = 1; break;
        case 'v': G.verbose = 1; break;
        case 'E': G.enforcement = 1; break;
        case 'F': G.frag_drop = 1; break;
        case 'M': G.malformed_drop = 1; break;
        case 'V': G.vlan_count = 1; break;
        case 'L': G.latency_sample = 1; break;
        case 'B': G.max_burst_inspect = atoi(optarg); break;
        case 'N': G.no_pin = 1; break;
        case 'D': G.pid = atoi(optarg); break;
        case 'A':
            if (parse_attach_pid(optarg) < 0) {
                fprintf(stderr, "invalid or duplicate --attach-pid: %s\n", optarg);
                return 1;
            }
            break;
        default: usage(argv[0]); return 1;
        }
    }
    if (!G.bpf_obj || !G.offsets_path) { usage(argv[0]); return 1; }
    if (!G.attach_pid_count) {
        fprintf(stderr, "[comm] --attach-pid is required; refusing global uprobe attach\n");
        return 1;
    }
    for (int i = 0; i < G.attach_pid_count; i++)
        fprintf(stderr, "[comm] scoped uprobe target pid=%d\n", G.attach_pids[i]);

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGUSR1, on_sigusr1);
    bump_rlimit();
    if (G.pid > 0) {
        g_target_pid = (pid_t)G.pid;
        fprintf(stderr,
            "[comm] prologue watchdog target: pid=%d (poll=%d μs)\n",
            G.pid, PROLOGUE_POLL_US);
    }
    if (!G.no_pin) mkdir(PIN_BASE, 0755);

    /* 1) mbuf 오프셋 로드 */
    struct mbuf_offsets mo;
    if (load_offsets(G.offsets_path, &mo) < 0) {
        fprintf(stderr,
            "FATAL: failed to load mbuf offsets from %s\n"
            "       Run `tools/discover_offsets > %s` first.\n",
            G.offsets_path, G.offsets_path);
        return 1;
    }
    fprintf(stderr,
        "[comm] mbuf offsets: buf_addr=%d data_off=%d pkt_len=%d data_len=%d\n",
        mo.buf_addr, mo.data_off, mo.pkt_len, mo.data_len);

    /* Resolve once in the host control plane. Every PID in one loader must
     * be in the same cgroup; use separate loaders/SHM names for tenants. */
    __u64 tenant_cgroup_id = 0;
    int target_pidfds[8];
    for (int i = 0; i < 8; i++) target_pidfds[i] = -1;
    for (int i = 0; i < G.attach_pid_count; i++) {
        target_pidfds[i] = (int)syscall(SYS_pidfd_open, G.attach_pids[i], 0);
        if (target_pidfds[i] < 0) {
            fprintf(stderr, "FATAL: pidfd_open failed pid=%d: %s\n",
                    G.attach_pids[i], strerror(errno));
            return 1;
        }
        __u64 id = 0;
        if (host_cgroup_id(G.attach_pids[i], &id) < 0 || id == 0 ||
            (tenant_cgroup_id && tenant_cgroup_id != id)) {
            fprintf(stderr, "FATAL: missing or mixed host cgroup identities pid=%d\n",
                    G.attach_pids[i]);
            return 1;
        }
        tenant_cgroup_id = id;
        struct pollfd target = { .fd = target_pidfds[i], .events = POLLIN };
        if (poll(&target, 1, 0) != 0) {
            fprintf(stderr, "FATAL: target exited during cgroup capture pid=%d\n",
                    G.attach_pids[i]);
            return 1;
        }
        fprintf(stderr, "[comm] host cgroup identity pid=%d cgroup_id=%llu\n",
                G.attach_pids[i], (unsigned long long)id);
    }

    /* 2) BPF open */
    struct bpf_object *obj = bpf_object__open_file(G.bpf_obj, NULL);
    if (!obj) { perror("open"); return 1; }
    if (!G.no_pin) purge_pinned_maps(obj);  /* 이전 핀 자동 정리 */

    /* The host must inject a nonzero identity into .rodata before loading. */
    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, "comm_fil.rodata");
    if (!rodata) rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (!rodata) {
        fprintf(stderr, "FATAL: BPF .rodata map not found; refusing cgroup_id=0\n");
        return 1;
    } else {
        size_t vsize = 0;
        struct runtime_config *rcfg = bpf_map__initial_value(rodata, &vsize);
        if (!rcfg || vsize < sizeof(*rcfg)) {
            fprintf(stderr, "FATAL: .rodata size mismatch; refusing cgroup_id=0\n");
            return 1;
        } else {
            rcfg->mbuf_off_buf_addr = mo.buf_addr;
            rcfg->mbuf_off_data_off = mo.data_off;
            rcfg->mbuf_off_pkt_len  = mo.pkt_len;
            rcfg->mbuf_off_data_len = mo.data_len;
            rcfg->max_burst_inspect = G.max_burst_inspect > 32 ? 32 : G.max_burst_inspect;
            rcfg->kill_signal = 9;
            rcfg->enabled     = 1;
            rcfg->generation  = (__u32)time(NULL);
            rcfg->features =
                  (G.enforcement     ? FEAT_ENFORCEMENT     : 0)
                | (G.frag_drop       ? FEAT_FRAGMENT_DROP   : 0)
                | (G.malformed_drop  ? FEAT_MALFORMED_DROP  : 0)
                | (G.vlan_count      ? FEAT_VLAN_COUNT      : 0)
                | (G.latency_sample  ? FEAT_LATENCY_SAMPLE  : 0);
            rcfg->features |= (G.policy_path ? (compute_probe_mask(G.policy_path) << 8) : 0u); /* opt3 probe-mask */
            rcfg->tenant_cgroup_id = tenant_cgroup_id;
            fprintf(stderr, "[comm] runtime_config: features=0x%x burst=%u cgroup_id=%llu\n",
                    rcfg->features, rcfg->max_burst_inspect,
                    (unsigned long long)rcfg->tenant_cgroup_id);
        }
    }

    /* 4) load */
    /* bpftime --no-pin 모드: LIBBPF_PIN_BY_NAME이 설정된 맵의 pin 경로를
     * 해제해서 BPF_OBJ_GET syscall을 막는다. bpftime SYSCALL_SERVER가
     * BPF_OBJ_GET을 EINVAL로 처리하기 때문. */
    if (G.no_pin) {
        /* bpftime 모드: map pinning 비활성화.
         * bpf_map__next(NULL, obj) 는 일부 libbpf 버전에서 crash 발생.
         * 핀 경로 삭제 루프 대신, load 후 bpf_object__pin_maps 를 호출하지
         * 않는 것으로 충분하다 (아래 if (!G.no_pin) 가드로 이미 처리). */
        fprintf(stderr, "[comm] --no-pin: map pinning disabled (bpftime mode)\n");
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        return 1;
    }
    for (int i = 0; i < G.attach_pid_count; i++) {
        __u64 id = 0;
        if (host_cgroup_id(G.attach_pids[i], &id) < 0 || id != tenant_cgroup_id) {
            fprintf(stderr, "FATAL: cgroup identity changed before attach pid=%d\n",
                    G.attach_pids[i]);
            return 1;
        }
    }
    if (!G.no_pin) bpf_object__pin_maps(obj, PIN_BASE);  /* load 후 pin */

    /* ================================================================= */
    /*  5) RX 후킹                                                        */
    /*     전략: API level 시도 → 실패 시 드라이버 레벨 fallback          */
    /* ================================================================= */
    int rx_attached = 0;

    /* --- 5a) API level: rte_eth_rx_burst --- */
    {
        struct bpf_program *p_entry =
            bpf_object__find_program_by_name(obj, "uprobe_rx_burst");
        struct bpf_program *p_ret =
            bpf_object__find_program_by_name(obj, "uretprobe_rx_burst");

        if (p_entry && p_ret && G.lib_path) {
            unsigned long api_off = sym_offset(G.lib_path, "rte_eth_rx_burst");
            if (attach_uprobe_pair_scoped(p_entry, p_ret, G.lib_path, api_off)) {
                rx_attached = 1;
                fprintf(stderr,
                    "[comm] RX attached at API level: rte_eth_rx_burst @ %s\n"
                    "       NOTE: inline risk — use --pmd-lib for stable driver-level hooking\n",
                    G.lib_path);
            } else {
                if (G.verbose)
                    fprintf(stderr,
                        "[comm] API-level attach failed (rte_eth_rx_burst likely inlined),"
                        " trying driver level...\n");
            }
        }
    }

    /* --- 5b) Driver level fallback (--pmd-lib 필요) --- */
    if (!rx_attached || G.pmd_lib_path) {
        if (!G.pmd_lib_path) {
            fprintf(stderr,
                "[comm] WARNING: RX not attached at API level and --pmd-lib not provided.\n"
                "       Provide --pmd-lib to enable driver-level RX hooking.\n"
                "       Example: --pmd-lib /usr/local/lib/x86_64-linux-gnu/librte_net_mlx5.so\n");
        } else {
            struct bpf_program *p_drv_entry =
                bpf_object__find_program_by_name(obj, "uprobe_rx_burst_drv");
            struct bpf_program *p_drv_ret =
                bpf_object__find_program_by_name(obj, "uretprobe_rx_burst_drv");

            if (!p_drv_entry || !p_drv_ret) {
                fprintf(stderr,
                    "[comm] ERROR: driver-level RX BPF programs missing."
                    " Rebuild comm_filter.bpf.o\n");
            } else {
                for (int i = 0; RX_DRIVER_SYMS[i]; i++) {
                    const char *sym_lib = G.pmd_debug_lib_path ? G.pmd_debug_lib_path : G.pmd_lib_path;
                    unsigned long off = sym_offset(sym_lib, RX_DRIVER_SYMS[i]);
                    if (!off) {
                        if (G.verbose)
                            fprintf(stderr, "[comm] symbol %s not found in %s\n",
                                    RX_DRIVER_SYMS[i], sym_lib);
                        continue;
                    }
                    off = resolve_tailcall_stub(sym_lib, off, RX_DRIVER_SYMS[i]);
                    if (attach_uprobe_pair_scoped(p_drv_entry, p_drv_ret,
                                                  G.pmd_lib_path, off)) {
                        rx_attached = 1;
                        fprintf(stderr,
                            "[comm] RX attached at DRIVER level: %s @ %s (offset=0x%lx)\n",
                            RX_DRIVER_SYMS[i], G.pmd_lib_path, off);
                        /* 프롤로그 무결성 워치독 등록 */
                        pw_register(G.pmd_lib_path, off, RX_DRIVER_SYMS[i]);

                    } else if (G.verbose)
                        fprintf(stderr, "[comm] driver-level attach failed: %s\n",
                                RX_DRIVER_SYMS[i]);
                }

                if (!rx_attached)
                    fprintf(stderr,
                        "[comm] WARNING: no RX driver symbol found in %s.\n"
                        "       Check NIC driver and verify with: nm -D %s | grep burst\n",
                        G.pmd_lib_path, G.pmd_lib_path);
            }
        }
    }

    /* ================================================================= */
    /*  6) TX 후킹 (드라이버 레벨 전용)                                   */
    /*     rte_eth_tx_burst는 TX hot-path 최적화로 거의 항상 inline →      */
    /*     심볼 없음 → 드라이버 함수에만 후킹 가능                         */
    /* ================================================================= */
    int tx_attached = 0;

    if (!G.pmd_lib_path) {
        fprintf(stderr,
            "[comm] INFO: TX not attached (--pmd-lib not provided).\n"
            "       TX hooking requires driver-level access via --pmd-lib.\n");
    } else {
        struct bpf_program *p_tx =
            bpf_object__find_program_by_name(obj, "uprobe_tx_burst");

        if (!p_tx) {
            fprintf(stderr,
                "[comm] ERROR: uprobe_tx_burst BPF program missing."
                " Rebuild comm_filter.bpf.o\n");
        } else {
            for (int i = 0; TX_DRIVER_SYMS[i]; i++) {
                const char *sym_lib = G.pmd_debug_lib_path ? G.pmd_debug_lib_path : G.pmd_lib_path;
                unsigned long off = sym_offset(sym_lib, TX_DRIVER_SYMS[i]);
                if (!off) {
                    if (G.verbose)
                        fprintf(stderr, "[comm] TX symbol %s not found in %s\n",
                                TX_DRIVER_SYMS[i], sym_lib);
                    continue;
                }
                off = resolve_tailcall_stub(sym_lib, off, TX_DRIVER_SYMS[i]);
                if (attach_uprobe_scoped(p_tx, false, G.pmd_lib_path, off)) {
                    tx_attached = 1;
                    fprintf(stderr,
                        "[comm] TX attached at DRIVER level: %s @ %s (offset=0x%lx)\n",
                        TX_DRIVER_SYMS[i], G.pmd_lib_path, off);
                    /* 프롤로그 무결성 워치독 등록 */
                    pw_register(G.pmd_lib_path, off, TX_DRIVER_SYMS[i]);
                    /* latency sampling용 TX uretprobe 추가 */
                    struct bpf_program *p_tx_ret =
                        bpf_object__find_program_by_name(obj, "uretprobe_tx_burst");
                    if (p_tx_ret) {
                        if (attach_uprobe_scoped(p_tx_ret, true,
                                                 G.pmd_lib_path, off) && G.verbose)
                            fprintf(stderr, "[comm] TX uretprobe attached (latency)\n");
                    }

                } else if (G.verbose)
                    fprintf(stderr, "[comm] TX driver-level attach failed: %s\n",
                            TX_DRIVER_SYMS[i]);
            }

            if (!tx_attached)
                fprintf(stderr,
                    "[comm] WARNING: no TX driver symbol found in %s.\n"
                    "       Check NIC driver and verify with: nm -D %s | grep xmit\n",
                    G.pmd_lib_path, G.pmd_lib_path);
        }
    }

    fprintf(stderr,
        "[comm] attach summary: RX=%s TX=%s\n",
        rx_attached ? "OK" : "NONE",
        tx_attached ? "OK" : "NONE");

    /* ================================================================= */
    /*  7) 정책 주입                                                       */
    /* ================================================================= */
    int pol_fd = bpf_object__find_map_fd_by_name(obj, "comm_policy");
    if (pol_fd < 0) { fprintf(stderr, "comm_policy map missing\n"); return 1; }
    if (G.policy_path && load_comm_policy(G.policy_path, pol_fd) < 0) return 1;

    int qstats_fd  = bpf_object__find_map_fd_by_name(obj, "queue_stats");
    int lat_fd     = bpf_object__find_map_fd_by_name(obj, "lat_hist");
    int lat_tx_fd  = bpf_object__find_map_fd_by_name(obj, "lat_hist_tx");

    /* PMD 프롤로그 무결성 (process_vm_readv, RDNet-style) */
    if (g_target_pid > 0) {
        pthread_t pw_tid;
        if (pthread_create(&pw_tid, NULL, watchdog_prologue_thread, NULL) == 0)
            pthread_detach(pw_tid);
        else
            fprintf(stderr, "[comm] WARN: failed to start prologue watchdog thread\n");
    }

    /* ================================================================= */
    /*  8) ringbuf 폴링                                                    */
    /* ================================================================= */
    int ev_fd = bpf_object__find_map_fd_by_name(obj, "comm_events");
    struct ring_buffer *rb = ring_buffer__new(ev_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "perf_buffer failed\n"); return 1; }

    fprintf(stderr, "[comm_loader] ready. SIGUSR1=stats dump, SIGINT=exit.\n");

    unsigned cgroup_check_counter = 0;
    while (!exiting) {
        int n = ring_buffer__poll(rb, 20);
        if (n < 0 && n != -EINTR) break;
        if (++cgroup_check_counter >= 5) {
            cgroup_check_counter = 0;
            int alive_count = 0;
            for (int i = 0; i < G.attach_pid_count; i++) {
                if (target_pidfds[i] < 0) continue;
                struct pollfd pfd = { .fd = target_pidfds[i], .events = POLLIN };
                if (poll(&pfd, 1, 0) > 0) {
                    close(target_pidfds[i]);
                    target_pidfds[i] = -1;
                    continue;
                }
                ++alive_count;
                __u64 current_id = 0;
                if (host_cgroup_id(G.attach_pids[i], &current_id) < 0 ||
                    current_id != tenant_cgroup_id) {
                    fprintf(stderr, "[comm] CGROUP_IDENTITY_VIOLATION pid=%d expected=%llu actual=%llu\n",
                            G.attach_pids[i], (unsigned long long)tenant_cgroup_id,
                            (unsigned long long)current_id);
                    syscall(SYS_pidfd_send_signal, target_pidfds[i], SIGKILL, NULL, 0);
                    exiting = 1;
                    break;
                }
            }
            if (!alive_count) exiting = 1;
        }
        if (dump_now) {
            dump_now = 0;
            if (qstats_fd >= 0) dump_queue_stats(qstats_fd);
            if (lat_tx_fd >= 0) dump_latency_named(lat_tx_fd, "tx_latency");
            if (lat_fd    >= 0) dump_latency(lat_fd);
        }
    }

    g_prologue_watchdog_run = 0;
    if (qstats_fd >= 0) dump_queue_stats(qstats_fd);
    if (lat_tx_fd >= 0) dump_latency_named(lat_tx_fd, "tx_latency");
    if (lat_fd    >= 0) dump_latency(lat_fd);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    for (int i = 0; i < G.attach_pid_count; i++)
        if (target_pidfds[i] >= 0) close(target_pidfds[i]);
    return 0;
}

/* eSAC flow-rate THROTTLE loader: attaches the rate-limit BPF to rte_flow_create
 * as ATTACH_UPROBE_OVERRIDE (perf_event type 1008) so bpf_override_return() can
 * deny over-rate calls. Run under LD_PRELOAD=libbpftime-syscall-server.so.
 * argv: <bpf.o> <librte_ethdev.so> <offset_hex> <pid>
 * Stays alive (keeps the bpftime shm) so the in-process agent attaches + runs it. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_TYPE_UPROBE_OVERRIDE 1008
#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

static volatile int exiting = 0;
static void on_sig(int s){ (void)s; exiting = 1; }
static __u64 p2u(const void *p){ return (__u64)(unsigned long)p; }

static int peo_override(const char *name, uint64_t off, int pid, int type)
{
    struct perf_event_attr a; memset(&a, 0, sizeof(a));
    a.size = sizeof(a); a.type = type;
    a.config1 = p2u(name);   /* uprobe path */
    a.config2 = off;         /* probe offset */
    int pfd = syscall(__NR_perf_event_open, &a, pid < 0 ? -1 : pid,
                      pid == -1 ? 0 : -1, -1, PERF_FLAG_FD_CLOEXEC);
    return pfd >= 0 ? pfd : -errno;
}

static int attach_override(struct bpf_object *o, const char *prog, const char *lib,
                           uint64_t off, int pid)
{
    struct bpf_program *p = bpf_object__find_program_by_name(o, prog);
    if (!p) { fprintf(stderr, "prog %s not found\n", prog); return -1; }
    int pfd = peo_override(lib, off, pid, BPF_TYPE_UPROBE_OVERRIDE);
    if (pfd < 0) { fprintf(stderr, "perf_event_open override fail %s: %d\n", prog, pfd); return pfd; }
    int r = bpf_prog_attach(bpf_program__fd(p), pfd, BPF_MODIFY_RETURN, 0);
    fprintf(stderr, "[throttle] attach %s OVERRIDE -> rc=%d (pfd=%d off=0x%lx pid=%d)\n",
            prog, r, pfd, (unsigned long)off, pid);
    return r;
}

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: %s <bpf.o> <lib.so> <offset_hex> <pid>\n", argv[0]); return 2; }
    const char *objp = argv[1], *lib = argv[2];
    uint64_t off = strtoull(argv[3], NULL, 0);
    int pid = atoi(argv[4]);
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    struct bpf_object *o = bpf_object__open(objp);
    if (!o) { fprintf(stderr, "open %s fail\n", objp); return 1; }
    if (bpf_object__load(o)) { fprintf(stderr, "load fail: %s\n", strerror(errno)); return 1; }

    if (attach_override(o, "rl_flow_create", lib, off, pid) < 0) { fprintf(stderr, "ATTACH_FAIL\n"); return 1; }
    fprintf(stderr, "[throttle] ready (override on rte_flow_create). holding shm...\n");
    fflush(stderr);
    while (!exiting) sleep(1);
    bpf_object__close(o);
    return 0;
}

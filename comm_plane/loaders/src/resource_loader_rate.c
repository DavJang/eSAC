/* eSAC control-plane/resource loader (rate-limit path). Attaches a resource-loader BPF's
 * programs to MANY exported DPDK symbols as ATTACH_UPROBE_OVERRIDE so
 * bpf_override_return() can rate-limit or cap each call.
 * Run under LD_PRELOAD=libbpftime-syscall-server.so. Stays alive (holds shm).
 * argv: <bpf.o> <pid> <config>
 *   config: one hook per line:  <lib_path> <offset_hex> <prog_name>
 */
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

static volatile int exiting = 0;
static void on_sig(int s){ (void)s; exiting = 1; }
static __u64 p2u(const void *p){ return (__u64)(unsigned long)p; }

static int peo_override(const char *name, uint64_t off, int pid)
{
    struct perf_event_attr a; memset(&a, 0, sizeof(a));
    a.size = sizeof(a); a.type = BPF_TYPE_UPROBE_OVERRIDE;
    a.config1 = p2u(name); a.config2 = off;
    int pfd = syscall(__NR_perf_event_open, &a, pid < 0 ? -1 : pid,
                      pid == -1 ? 0 : -1, -1, PERF_FLAG_FD_CLOEXEC);
    return pfd >= 0 ? pfd : -errno;
}

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: %s <bpf.o> <pid> <config>\n", argv[0]); return 2; }
    const char *objp = argv[1]; int pid = atoi(argv[2]); const char *cfg = argv[3];
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    struct bpf_object *o = bpf_object__open(objp);
    if (!o || bpf_object__load(o)) { fprintf(stderr, "open/load %s fail\n", objp); return 1; }

    FILE *f = fopen(cfg, "r");
    if (!f) { fprintf(stderr, "open cfg %s fail\n", cfg); return 1; }
    char lib[512], prog[128]; unsigned long off; int n = 0, ok = 0;
    char line[800];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%511s %lx %127s", lib, &off, prog) != 3) continue;
        n++;
        struct bpf_program *p = bpf_object__find_program_by_name(o, prog);
        if (!p) { fprintf(stderr, "[gov] prog %s not found\n", prog); continue; }
        /* perf_event_open override needs a persistent copy of the lib path string */
        char *libdup = strdup(lib);
        int pfd = peo_override(libdup, off, pid);
        if (pfd < 0) { fprintf(stderr, "[gov] peo fail %s@%s: %d\n", prog, lib, pfd); continue; }
        int r = bpf_prog_attach(bpf_program__fd(p), pfd, BPF_MODIFY_RETURN, 0);
        fprintf(stderr, "[gov] %-14s -> %s@0x%lx rc=%d\n", prog, lib, off, r);
        if (r == 0) ok++;
    }
    fclose(f);
    fprintf(stderr, "[gov] ready: %d/%d hooks attached (pid=%d). holding shm...\n", ok, n, pid);
    fflush(stderr);
    while (!exiting) sleep(1);
    bpf_object__close(o);
    return 0;
}

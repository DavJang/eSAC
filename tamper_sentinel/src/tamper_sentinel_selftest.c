/* tamper_sentinel_selftest — exercises each tamper syscall vector so the FINAL tamper_sentinel can be validated.
 * Usage: tamper_sentinel_selftest <mprotect|procmem|ptrace|vmwritev|none> [delay_sec]
 * After [delay] sec it performs the chosen syscall on itself, then sleeps 20s and prints
 * SURVIVED if still alive. Run the tamper_sentinel against this pid; a working tamper_sentinel SIGKILLs it
 * (so it never prints SURVIVED and exits via signal 9).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

int main(int argc, char **argv) {
    const char *what = argc > 1 ? argv[1] : "none";
    int delay = argc > 2 ? atoi(argv[2]) : 5;
    fprintf(stderr, "[selftest] pid=%d vector=%s delay=%d\n", getpid(), what, delay);
    fflush(stderr);
    sleep(delay);

    if (!strcmp(what, "mprotect")) {
        /* map a page R-X then re-grant WRITE (the attacker "un-RO" move) */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int r = mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
        fprintf(stderr, "[selftest] mprotect rc=%d\n", r);
    } else if (!strcmp(what, "procmem")) {
        int fd = open("/proc/self/mem", O_RDWR);
        fprintf(stderr, "[selftest] open(/proc/self/mem) fd=%d\n", fd);
    } else if (!strcmp(what, "ptrace")) {
        long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
        fprintf(stderr, "[selftest] ptrace(TRACEME) rc=%ld\n", r);
    } else if (!strcmp(what, "vmwritev")) {
        long src = 0, dst = 0;
        struct iovec l = { &src, sizeof src }, r = { &dst, sizeof dst };
        ssize_t n = process_vm_writev(getpid(), &l, 1, &r, 1, 0);
        fprintf(stderr, "[selftest] process_vm_writev n=%zd\n", n);
    }
    fflush(stderr);
    sleep(20);
    printf("SURVIVED\n");
    fflush(stdout);
    return 0;
}

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Experimental privileged sidecar for a single scoped tenant.
 * Input is a manifest of the PMD symbols that the loader actually attached:
 * one hexadecimal ELF offset and symbol name per line. No host configuration
 * is changed. Keep the tenant paused until this process prints READY. */
#define MAX_HOOKS 256
#define PROLOGUE_BYTES 8
#define POLL_US 2000

struct hook { unsigned long offset; char name[96]; uint8_t expected[8]; };
static struct hook hooks[MAX_HOOKS];
static int count;
static uint8_t current[MAX_HOOKS][PROLOGUE_BYTES];
static struct iovec local[MAX_HOOKS], remote[MAX_HOOKS];

static uint64_t monotonic_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void sleep_us(long us) {
    struct timespec t = { .tv_sec = us / 1000000, .tv_nsec = (us % 1000000) * 1000 };
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}

static unsigned long load_bias(pid_t pid, const char *path) {
    char proc[64], line[1024];
    snprintf(proc, sizeof(proc), "/proc/%ld/maps", (long)pid);
    FILE *f = fopen(proc, "r");
    if (!f) return 0;
    unsigned long base = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end, offset;
        char perm[8];
        if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perm, &offset) != 4) continue;
        if (start >= offset && strstr(line, path)) { base = start - offset; break; }
    }
    fclose(f);
    return base;
}

static int read_all(pid_t pid) {
    ssize_t n = process_vm_readv(pid, local, count, remote, count, 0);
    return n == (ssize_t)count * PROLOGUE_BYTES ? 0 : -1;
}

static int target_is_zombie(pid_t pid) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT;
    int dead = 0;
    if (fgets(line, sizeof(line), f)) {
        char *end = strrchr(line, ')');
        if (end && end[1] == ' ' && (end[2] == 'Z' || end[2] == 'X')) dead = 1;
    }
    fclose(f);
    return dead;
}

static void kill_target(int pidfd, pid_t pid, const char *reason, const char *symbol) {
    fprintf(stderr, "VIOLATION pid=%ld reason=%s hook=%s at_ns=%llu\n",
            (long)pid, reason, symbol ? symbol : "NA",
            (unsigned long long)monotonic_ns());
    fflush(stderr);
    if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) < 0) {
        fprintf(stderr, "pidfd_send_signal failed: %s\n", strerror(errno));
        exit(2);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s PID EXECUTABLE MANIFEST\n", argv[0]);
        return 2;
    }
    char *end;
    long parsed = strtol(argv[1], &end, 10);
    if (*end || parsed <= 1 || parsed > INT32_MAX) return 2;
    pid_t pid = (pid_t)parsed;
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) { perror("pidfd_open"); return 2; }
    FILE *f = fopen(argv[3], "r");
    if (!f) { perror("manifest"); return 2; }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        struct hook h;
        if (sscanf(line, "%lx %95s", &h.offset, h.name) != 2) {
            fprintf(stderr, "invalid manifest line\n"); return 2;
        }
        int duplicate = 0;
        for (int i = 0; i < count; i++) if (hooks[i].offset == h.offset) duplicate = 1;
        if (duplicate) continue;
        if (count == MAX_HOOKS) { fprintf(stderr, "too many hooks\n"); return 2; }
        hooks[count++] = h;
    }
    fclose(f);
    if (!count) { fprintf(stderr, "empty manifest\n"); return 2; }

    unsigned long base = 0;
    for (int tries = 0; tries < 100 && !base; tries++) {
        base = load_bias(pid, argv[2]);
        if (!base) sleep_us(100000);
    }
    if (!base) { fprintf(stderr, "executable mapping absent\n"); return 2; }
    for (int i = 0; i < count; i++) {
        local[i].iov_base = current[i];
        local[i].iov_len = PROLOGUE_BYTES;
        remote[i].iov_base = (void *)(base + hooks[i].offset);
        remote[i].iov_len = PROLOGUE_BYTES;
    }

    int patched = 0;
    for (int tries = 0; tries < 100; tries++) {
        patched = 0;
        if (read_all(pid) == 0) {
            for (int i = 0; i < count; i++) patched += current[i][0] == 0xe9;
        }
        if (patched == count) break;
        sleep_us(100000);
    }
    if (patched != count) {
        fprintf(stderr, "patch incomplete %d/%d\n", patched, count);
        return 2;
    }
    sleep_us(100000);
    if (read_all(pid) < 0) { fprintf(stderr, "snapshot read failed\n"); return 2; }
    for (int i = 0; i < count; i++) memcpy(hooks[i].expected, current[i], PROLOGUE_BYTES);
    fprintf(stderr, "READY self_pid=%ld pid=%ld hooks=%d poll_us=%d readv_calls_per_scan=1\n",
            (long)getpid(), (long)pid, count, POLL_US);
    fflush(stderr);

    unsigned long scans = 0;
    while (1) {
        sleep_us(POLL_US);
        /* A missing mapping or lost read permission is an integrity failure
         * while this pidfd still names the original living process. */
        if (read_all(pid) < 0) {
            struct pollfd exit_poll = { .fd = pidfd, .events = POLLIN };
            /* ELF mappings may disappear just before a normal process exit.
             * Prologue changes are still checked without this grace period. */
            int poll_rc = poll(&exit_poll, 1, 1000);
            if (target_is_zombie(pid) ||
                (poll_rc > 0 && (exit_poll.revents & (POLLIN | POLLHUP))) ||
                (syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) < 0 && errno == ESRCH))
                break;
            kill_target(pidfd, pid, "read_failure", NULL);
            return 1;
        }
        for (int i = 0; i < count; i++) {
            if (memcmp(current[i], hooks[i].expected, PROLOGUE_BYTES)) {
                kill_target(pidfd, pid, "prologue_mismatch", hooks[i].name);
                return 1;
            }
        }
        if (++scans % 100 == 0 && load_bias(pid, argv[2]) != base) {
            kill_target(pidfd, pid, "mapping_changed", NULL);
            return 1;
        }
    }
    fprintf(stderr, "TARGET_EXIT pid=%ld scans=%lu\n", (long)pid, scans);
    return 0;
}

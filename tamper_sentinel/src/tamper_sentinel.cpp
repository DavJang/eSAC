#include "bpftime_shm.hpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <map>
#include <poll.h>
#include <cstdlib>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct policy_key {
    uint64_t cgroup_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol, layer;
    uint16_t pad;
};
struct policy_value { uint32_t action, hit_count; };
static_assert(sizeof(policy_key) == 24);
static_assert(sizeof(policy_value) == 8);

static uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

static int policy_fd() {
    for (int fd = 0; fd < 256; ++fd) {
        bpftime::bpf_map_attr attr{};
        const char *name = nullptr;
        bpftime::bpf_map_type type{};
        if (bpftime_map_get_info(fd, &attr, &name, &type) == 0 && name &&
            !strcmp(name, "comm_policy")) {
            if (attr.key_size != sizeof(policy_key) ||
                attr.value_size != sizeof(policy_value)) return -1;
            return fd;
        }
    }
    return -1;
}

using key_bytes = std::array<unsigned char, sizeof(policy_key)>;
using snapshot = std::map<key_bytes, uint32_t>;

static int baseline_actions(int fd, const snapshot &baseline) {
    for (const auto &[key, expected] : baseline) {
        auto *value = static_cast<const policy_value *>(
            bpftime_map_lookup_elem(fd, key.data()));
        if (!value) return 2;
        if (value->action != expected) return 1;
    }
    return 0;
}

static bool read_policy(int fd, snapshot &out) {
    out.clear();
    key_bytes previous{}, next{};
    const void *key = nullptr;
    for (size_t i = 0; i < 4097; ++i) {
        if (bpftime_map_get_next_key(fd, key, next.data()) != 0)
            return true;
        auto *value = static_cast<const policy_value *>(
            bpftime_map_lookup_elem(fd, next.data()));
        if (!value) return false;
        if (!out.emplace(next, value->action).second) return false;
        if (out.size() > 4096) return false;
        previous = next;
        key = previous.data();
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s PID\n", argv[0]);
        return 2;
    }
    char *end = nullptr;
    long parsed = strtol(argv[1], &end, 10);
    if (!end || *end || parsed <= 1 || parsed > INT32_MAX) return 2;
    pid_t pid = pid_t(parsed);
    int pidfd = int(syscall(SYS_pidfd_open, pid, 0));
    if (pidfd < 0) { perror("pidfd_open"); return 2; }
    try {
        bpftime_initialize_global_shm(bpftime::shm_open_type::SHM_OPEN_ONLY);
        int fd = policy_fd();
        if (fd < 0) { fprintf(stderr, "comm_policy missing or wrong schema\n"); return 2; }
        snapshot baseline, current;
        if (!read_policy(fd, baseline)) {
            fprintf(stderr, "policy baseline read failed\n"); return 2;
        }
        fprintf(stderr, "POLICY_READY self_pid=%ld pid=%ld entries=%zu poll_us=1000\n",
                long(getpid()), long(pid), baseline.size());
        fflush(stderr);
        pollfd target{pidfd, POLLIN, 0};
        timespec delay{0, 1000000};
        uint64_t scans = 0;
        while (true) {
            if (poll(&target, 1, 0) > 0) break;
            /* The agent may briefly rebuild the hash table while attaching.
             * Verify a structural discrepancy twice. Action changes on a
             * present baseline key are checked every scan without delay. */
            int state = baseline_actions(fd, baseline);
            bool same = state == 0;
            if (state == 2 || (same && (!read_policy(fd, current) || current != baseline))) {
                /* Map removal also occurs during agent teardown. A changed
                 * action still takes the immediate path above. */
                if (poll(&target, 1, 1000) > 0) break;
                same = baseline_actions(fd, baseline) == 0 &&
                       read_policy(fd, current) && current == baseline;
            }
            if (!same) {
                fprintf(stderr, "VIOLATION pid=%ld reason=policy_mismatch at_ns=%llu entries=%zu expected=%zu\n",
                        long(pid), (unsigned long long)now_ns(),
                        current.size(), baseline.size());
                fflush(stderr);
                if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0) < 0 &&
                    errno != ESRCH) perror("pidfd_send_signal");
                return 1;
            }
            ++scans;
            nanosleep(&delay, nullptr);
        }
        fprintf(stderr, "POLICY_TARGET_EXIT pid=%ld scans=%llu\n",
                long(pid), (unsigned long long)scans);
        return 0;
    } catch (const std::exception &e) {
        fprintf(stderr, "policy monitor error: %s\n", e.what());
        return 2;
    }
}

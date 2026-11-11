/* SPDX-License-Identifier: GPL-2.0
 * common.h — GUARD 통신 접근 제어 공통 자료형 & 상수
 *
 * BPF 쪽과 사용자 공간 로더가 함께 include한다.
 * __bpf__ 가드로 양쪽 컴파일 환경을 모두 지원한다.
 *
 * F-6 수정: volatile const struct runtime_config RCFG 선언 지원
 * F-7 수정: cgroup_id 기반 멀티프로세스/컨테이너 추적 지원
 */
#ifndef _GUARD_COMMON_H
#define _GUARD_COMMON_H

#ifndef __bpf__
/* ── 사용자 공간: 커널 헤더에서 정수 타입 가져오기 ─────────────────── */
#include <linux/types.h>
#else
/* ── BPF 타깃: 외부 헤더 없이 타입 직접 정의 ─────────────────────── */

/* 부호 없는 정수 (커널 정의와 동일해야 함; __u64는 반드시 ull) */
typedef unsigned char        __u8;
typedef unsigned short       __u16;
typedef unsigned int         __u32;
typedef unsigned long long   __u64;

/* 부호 있는 정수 (bpf_helper_defs.h의 __s32, __s64 등에 필요) */
typedef signed char          __s8;
typedef signed short         __s16;
typedef signed int           __s32;
typedef signed long long     __s64;

/* 빅엔디언/리틀엔디언 힌트 타입 (bpf_helper_defs.h 요구) */
typedef __u16                __be16;
typedef __u32                __be32;
typedef __u64                __be64;
typedef __u16                __le16;
typedef __u32                __le32;
typedef __u64                __le64;
typedef __u32                __wsum;   /* checksum 타입 */

/* BPF map 타입 (linux/bpf.h의 enum bpf_map_type 대체) */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC                = 0,
    BPF_MAP_TYPE_HASH                  = 1,
    BPF_MAP_TYPE_ARRAY                 = 2,
    BPF_MAP_TYPE_PROG_ARRAY            = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
    BPF_MAP_TYPE_PERCPU_HASH           = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
    BPF_MAP_TYPE_STACK_TRACE           = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
    BPF_MAP_TYPE_LRU_HASH              = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
    BPF_MAP_TYPE_LPM_TRIE              = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
    BPF_MAP_TYPE_DEVMAP                = 14,
    BPF_MAP_TYPE_SOCKMAP               = 15,
    BPF_MAP_TYPE_CPUMAP                = 16,
    BPF_MAP_TYPE_XSKMAP                = 17,
    BPF_MAP_TYPE_SOCKHASH              = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE                 = 22,
    BPF_MAP_TYPE_STACK                 = 23,
    BPF_MAP_TYPE_SK_STORAGE            = 24,
    BPF_MAP_TYPE_DEVMAP_HASH           = 25,
    BPF_MAP_TYPE_STRUCT_OPS            = 26,
    BPF_MAP_TYPE_RINGBUF               = 27,
    BPF_MAP_TYPE_INODE_STORAGE         = 28,
    BPF_MAP_TYPE_TASK_STORAGE          = 29,
    BPF_MAP_TYPE_BLOOM_FILTER          = 30,
};

/* BPF map 업데이트 플래그 */
#define BPF_ANY     0               /* create or update */
#define BPF_NOEXIST 1               /* create only */
#define BPF_EXIST   2               /* update only */

/* perf_event_output: 현재 CPU 자동 선택 */
#define BPF_F_CURRENT_CPU  0xffffffffULL

/* x86_64 uprobe/kprobe 아키텍처 지정.
 * bpf_tracing.h가 이 매크로를 보고 PT_REGS_PARM* / PT_REGS_RC 를 정의.
 * common.h가 bpf_tracing.h 보다 먼저 include 되므로 여기서 정의. */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

/* x86_64 struct pt_regs 완전 정의.
 * libbpf v1.8.0의 bpf_tracing.h는 이 구조체를 직접 정의하지 않고
 * bpf_helper_defs.h는 forward declaration만 한다.
 * BPF_UPROBE/BPF_URETPROBE 매크로가 멤버에 직접 접근하므로
 * 여기서 완전한 정의를 제공한다. */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};

#endif /* __bpf__ */

/* ── BPF 맵 핀 경로 ────────────────────────────────────────────────── */
#define PIN_BASE  "/sys/fs/bpf/guard/comm"

/* ── Action 코드 ──────────────────────────────────────────────────── */
#define ACT_ALLOW  0
#define ACT_DROP   2   /* mbuf 무효화 (bpf_probe_write_user) */
#define ACT_KILL   3   /* SIGKILL 직접 송신 (bpf_send_signal) */

/* ── Feature 플래그 (runtime_config.features 비트마스크) ─────────── */
#define FEAT_ENFORCEMENT     (1u << 0)
#define FEAT_FRAGMENT_DROP   (1u << 1)
#define FEAT_MALFORMED_DROP  (1u << 2)
#define FEAT_VLAN_COUNT      (1u << 3)
#define FEAT_LATENCY_SAMPLE  (1u << 4)

/* ── 레이턴시 히스토그램 버킷 수 ──────────────────────────────────── */
#define LAT_BUCKETS 64

/* ── F-6: 런타임 설정 (BPF .rodata 섹션에 주입) ──────────────────── */
/*
 * BPF 쪽: const volatile struct runtime_config RCFG = { defaults };
 * 로더 쪽: bpf_map__initial_value(rodata, &sz) 로 포인터를 얻어
 *          mbuf 오프셋 등을 프로그램 로드 전에 덮어쓴다.
 */
struct runtime_config {
    __u32 mbuf_off_buf_addr;   /* rte_mbuf.buf_addr 의 바이트 오프셋  */
    __u32 mbuf_off_data_off;   /* rte_mbuf.data_off 의 바이트 오프셋  */
    __u32 mbuf_off_pkt_len;    /* rte_mbuf.pkt_len  의 바이트 오프셋  */
    __u32 mbuf_off_data_len;   /* rte_mbuf.data_len 의 바이트 오프셋  */
    __u32 max_burst_inspect;   /* burst 중 검사할 패킷 최대 개수 (≤32) */
    __u32 kill_signal;         /* ACT_KILL 시 전송 시그널 (9=SIGKILL)   */
    __u32 enabled;             /* 0이면 모든 probe가 즉시 반환          */
    __u32 generation;          /* 설정 갱신 카운터 (로더가 time() 주입) */
    __u32 features;            /* FEAT_* 비트마스크                     */
    __u64 tenant_cgroup_id;    /* trusted host snapshot; one cgroup per loader */
};

/* ── 정책 맵 키 ───────────────────────────────────────────────────── */
/*
 * F-7 수정: cgroup_id 필드 추가.
 *   cgroup_id = 0  → wildcard (모든 cgroup에 적용)
 *   cgroup_id != 0 → 해당 cgroup 전용 규칙
 *
 * 조회 우선순위 (lookup_action 참조):
 *   1. (cgroup, proto, dst_port, src_ip, dst_ip)  — 완전 일치
 *   2. (cgroup, proto, dst_port, 0, 0)            — IP 와일드카드
 *   3. (cgroup, proto, 0, 0, 0)                   — 포트+IP 와일드카드
 *   4. (0, proto, dst_port, src_ip, dst_ip)       — cgroup 와일드카드
 *   5. (0, proto, dst_port, 0, 0)
 *   6. (0, proto, 0, 0, 0)
 */
struct comm_policy_key {
    __u64 cgroup_id;  /* host-injected cgroup-v2 inode, 0 = wildcard */
    __u32 src_ip;     /* network byte order, 0 = any */
    __u32 dst_ip;     /* network byte order, 0 = any */
    __u16 src_port;   /* host byte order, 0 = any */
    __u16 dst_port;
    __u8  protocol;   /* 6=TCP 17=UDP 1=ICMP 0=any */
    __u8  layer;      /* 1 = HW flow, 2 = eBPF */
    __u16 _pad;
};

/* ── 정책 맵 값 ───────────────────────────────────────────────────── */
struct comm_policy_value {
    __u32 action;     /* ACT_* */
    __u32 hit_count;  /* 원자적으로 증가 */
};

/* ── 이벤트 (perf ring → 사용자 공간) ────────────────────────────── */
/*
 * F-7 수정: cgroup_id 필드 추가.
 * 로더가 이 값으로 어느 컨테이너/프로세스 그룹의 패킷인지 식별.
 */
struct comm_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;           /* bpf_get_current_cgroup_id() */
    __u16 port_id;
    __u16 queue_id;
    __u16 nb_pkts_returned;
    __u16 nb_pkts_dropped;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  action_taken;
    __u16 hook_dir;          /* 1=RX, 2=TX; preserves event layout */
};

/* ── 큐별 통계 (PERCPU 맵 값) ─────────────────────────────────────── */
struct queue_stats {
    __u64 rx;
    __u64 tx;
    __u64 drop;            /* ACT_DROP: mbuf 무효화 횟수               */
    __u64 allow;
    __u64 vlan_seen;
    __u64 frag_drop;
    __u64 malformed_drop;
    __u64 policy_hits;
    __u64 parse_fail;
    __u64 rx_zero_burst;   /* RX starvation: zero-return burst 횟수    */
    __u64 tx_drop;         /* TX drop: nb_sent < nb_requested 횟수     */
};

/* ── 취약성 이벤트 (vuln_events → 사용자 공간) ───────────────────── */
#define VULN_RX_STARVATION  1u  /* zero-return burst 연속 발생          */
#define VULN_TX_DROP        2u  /* nb_sent < nb_requested               */
#define VULN_MBUF_MALFORM   3u  /* null buf_addr / oversized pkt_len    */

struct vuln_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    __u16 port_id;
    __u16 queue_id;
    __u8  vuln_type;     /* VULN_* */
    __u8  _pad[3];
    __u32 detail;        /* starvation: 연속 zero 횟수, tx_drop: 손실 수 */
};

/* ── 레이턴시 히스토그램 ──────────────────────────────────────────── */
struct latency_hist {
    __u64 buckets[LAT_BUCKETS];
    __u64 sum;
    __u64 count;
    __u64 max;
};


/* ── 자원 감시 모듈 공용 자료형 ─────────────────────────────────── */

#define API_RTE_EAL_INIT              0u
#define API_RTE_PKTMBUF_POOL_CREATE   1u
#define API_RTE_MEMPOOL_CREATE        2u
#define API_RTE_ETH_DEV_CONFIGURE     3u
#define API_RTE_ETH_RX_QUEUE_SETUP    4u
#define API_RTE_ETH_TX_QUEUE_SETUP    5u
#define API_RTE_ETH_DEV_START         6u
#define API_RTE_MALLOC                7u
#define API_RTE_ZMALLOC               8u
#define API_RTE_MEMZONE_RESERVE       9u
#define API_RTE_EAL_REMOTE_LAUNCH    10u  /* lcore 과점유 감지 */

struct resource_policy {
    __u64 max_socket_mem_mb;       /* rte_eal_init --socket-mem 합계 (MB, 0=무제한) */
    __u32 max_mbuf_count;
    __u64 max_mbuf_total_bytes;
    __u32 max_rx_queues;
    __u32 max_tx_queues;
    __u32 max_ports;
    __u64 max_rte_malloc_bytes;
    __u32 max_lcore_count;         /* 허용 lcore 최대 수 (0=무제한) */
    __u32 action_on_violation;
    __u64 binary_hash;
};

struct pid_resource_stats {
    __u32 pid;
    __u32 tgid;
    __u64 socket_mem_mb;           /* rte_eal_init --socket-mem 합계 (MB) */
    __u32 mbuf_pool_count;
    __u32 mbuf_total_count;
    __u64 mbuf_total_bytes;
    __u32 mempool_count;
    __u32 rx_queues_total;
    __u32 tx_queues_total;
    __u32 ports_configured;
    __u32 lcore_count;             /* rte_eal_remote_launch 호출 횟수  */
    __u64 rte_malloc_bytes;
    __u64 first_seen_ns;
    __u64 last_event_ns;
    __u64 violation_count;
};

union resource_arg {
    struct {
        __u32  n;
        __u32  cache_size;
        __u32  priv_size;
        __u32  data_room_size;
        __s32  socket_id;
        __u32  _rsvd;
        char   name[32];
    } pool_create;
    struct {
        __u16  port_id;
        __u16  nb_rx_queue;
        __u16  nb_tx_queue;
        __u16  _pad;
    } dev_configure;
    struct {
        __u16  port_id;
        __u16  queue_id;
        __u32  nb_desc;
        __s32  socket_id;
        __u32  _pad;
    } queue_setup;
    struct {
        __u64  size;
        __u32  align;
        __u32  _pad;
    } malloc;
};

struct resource_event {
    __u64              ts_ns;
    __u32              pid;
    __u32              tgid;
    __u32              api_id;
    __u32              action_taken;
    __u32              violation;
    __u32              _pad;
    union resource_arg arg;
};
#endif /* _GUARD_COMMON_H */

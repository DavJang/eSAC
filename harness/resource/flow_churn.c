/* eSAC demo: flow-rule churn tenant. Repeatedly calls rte_flow_create().
 * Without eSAC: all calls proceed. With eSAC flow-ratelimit uprobe: over-rate
 * calls are overridden to return NULL (denied) -> tenant throttled.
 * Build: cc flow_churn.c -o flow_churn $(pkg-config --cflags --libs libdpdk) */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>

static long now_ms(void){ struct timeval t; gettimeofday(&t,NULL); return t.tv_sec*1000L + t.tv_usec/1000L; }

int main(int argc, char **argv)
{
    int n = rte_eal_init(argc, argv);
    if (n < 0) { fprintf(stderr, "EAL init failed\n"); return 1; }
    argc -= n; argv += n;
    int iters = (argc > 1) ? atoi(argv[1]) : 30;

    uint16_t port = 0;
    if (rte_eth_dev_count_avail() == 0) { fprintf(stderr, "no eth ports\n"); return 2; }

    struct rte_mempool *mp = rte_pktmbuf_pool_create("MBUF", 8192, 256, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mp) { fprintf(stderr, "mbuf pool fail: %s\n", rte_strerror(rte_errno)); return 3; }

    struct rte_eth_conf pc; memset(&pc, 0, sizeof(pc));
    int r = rte_eth_dev_configure(port, 1, 1, &pc);
    if (r < 0) fprintf(stderr, "configure warn: %d\n", r);
    rte_eth_rx_queue_setup(port, 0, 512, rte_eth_dev_socket_id(port), NULL, mp);
    rte_eth_tx_queue_setup(port, 0, 512, rte_eth_dev_socket_id(port), NULL);
    r = rte_eth_dev_start(port);
    if (r < 0) fprintf(stderr, "start warn: %d (continuing; rte_flow_create still callable)\n", r);

    /* simple match-all -> QUEUE(0) flow, created repeatedly (churn) */
    struct rte_flow_attr attr; memset(&attr, 0, sizeof(attr)); attr.ingress = 1;
    struct rte_flow_item pattern[2]; memset(pattern, 0, sizeof(pattern));
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    struct rte_flow_action_queue q = { .index = 0 };
    struct rte_flow_action action[2]; memset(action, 0, sizeof(action));
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE; action[0].conf = &q;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    long t0 = now_ms();
    int ok = 0, nul = 0;
    printf("CHURN start iters=%d pid=%d\n", iters, (int)getpid()); fflush(stdout);
    for (int i = 0; i < iters; i++) {
        struct rte_flow_error err; memset(&err, 0, sizeof(err));
        struct rte_flow *f = rte_flow_create(port, &attr, pattern, action, &err);
        long dt = now_ms() - t0;
        if (f) { ok++; printf("[%2d] t=%4ldms rte_flow_create=OK(%p)\n", i, dt, (void*)f); rte_flow_destroy(port, f, &err); }
        else   { nul++; printf("[%2d] t=%4ldms rte_flow_create=NULL err=%s\n", i, dt, err.message?err.message:"(none)"); }
        fflush(stdout);
        usleep(50000); /* 20 calls/sec attempted */
    }
    printf("CHURN done: OK=%d NULL=%d in %ldms\n", ok, nul, now_ms()-t0);
    return 0;
}

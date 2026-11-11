/* eSAC demo tenant: exercises several shared NIC control-plane APIs + host-mem
 * allocation in a loop. Without eSAC all succeed; with the governor, control
 * ops are rate-throttled (flow_create->NULL, int APIs->-EAGAIN) and rte_malloc
 * is quota-capped (->NULL). Build: cc control_churn.c $(pkg-config --cflags --libs libdpdk) */
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
#include <rte_malloc.h>
#include <rte_ether.h>

static long now_ms(void){ struct timeval t; gettimeofday(&t,NULL); return t.tv_sec*1000L+t.tv_usec/1000L; }

int main(int argc, char **argv)
{
    int n = rte_eal_init(argc, argv);
    if (n < 0) return 1;
    argc -= n; argv += n;
    int iters = (argc > 1) ? atoi(argv[1]) : 12;
    uint16_t port = 0;
    if (rte_eth_dev_count_avail() == 0) { fprintf(stderr,"no ports\n"); return 2; }
    struct rte_mempool *mp = rte_pktmbuf_pool_create("MB", 8192, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    struct rte_eth_conf pc; memset(&pc,0,sizeof(pc));
    rte_eth_dev_configure(port, 1, 1, &pc);
    rte_eth_rx_queue_setup(port, 0, 512, rte_eth_dev_socket_id(port), NULL, mp);
    rte_eth_tx_queue_setup(port, 0, 512, rte_eth_dev_socket_id(port), NULL);
    rte_eth_dev_start(port);

    struct rte_flow_attr attr; memset(&attr,0,sizeof(attr)); attr.ingress=1;
    struct rte_flow_item pat[2]; memset(pat,0,sizeof(pat));
    pat[0].type=RTE_FLOW_ITEM_TYPE_ETH; pat[1].type=RTE_FLOW_ITEM_TYPE_END;
    struct rte_flow_action_queue q={.index=0};
    struct rte_flow_action act[2]; memset(act,0,sizeof(act));
    act[0].type=RTE_FLOW_ACTION_TYPE_QUEUE; act[0].conf=&q; act[1].type=RTE_FLOW_ACTION_TYPE_END;

    long t0=now_ms();
    printf("CTLCHURN start iters=%d pid=%d\n", iters, (int)getpid()); fflush(stdout);
    for (int i=0;i<iters;i++){
        long t=now_ms()-t0;
        struct rte_flow_error e; memset(&e,0,sizeof(e));
        struct rte_flow *fl=rte_flow_create(port,&attr,pat,act,&e);
        int pr=rte_eth_promiscuous_enable(port);
        int mt=rte_eth_dev_set_mtu(port, (i&1)?1500:1600);
        struct rte_ether_addr mac={{0x02,0,0,0,0,(uint8_t)(i+1)}};
        int ma=rte_eth_dev_mac_addr_add(port,&mac,0);
        void *mem=rte_malloc("t",65536,0);
        printf("[%2d t=%4ldms] flow=%s promisc=%d mtu=%d mac_add=%d malloc=%s\n",
               i, t, fl?"OK":"NULL", pr, mt, ma, mem?"OK":"NULL");
        fflush(stdout);
        if (fl) rte_flow_destroy(port,fl,&e);
        if (mem) rte_free(mem);
        usleep(60000);
    }
    printf("CTLCHURN done in %ldms\n", now_ms()-t0);
    return 0;
}

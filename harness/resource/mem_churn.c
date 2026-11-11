/* mem_churn (ATTACKER): DPDK app that churns rte_malloc(mb)+touch+rte_free in a tight loop for
 * DUR s. Holds NET-ZERO memory (frees every iteration) -> a HOLD/quota gate sees nothing to kill.
 * Large blocks force the DPDK heap to grow/shrink, driving kernel hugepage mmap/munmap (zeroing +
 * hugetlb_lock) on the SHARED node0 pool. rte_malloc is the governable entry point: a rate governor
 * returning NULL (bpf_override_return 0) throttles the churn. Counts ok vs null (denied). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rte_eal.h>
#include <rte_malloc.h>
int main(int argc,char**argv){
  int r=rte_eal_init(argc,argv);
  if(r<0){ printf("MEMCHURN EAL_FAIL\n"); return 1; }
  argc-=r; argv+=r; argv[0]=(char*)"mem_churn";
  long mb=64; double dur=12.0;
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--mb")&&i+1<argc) mb=atoll(argv[++i]);
    else if(!strcmp(argv[i],"--dur")&&i+1<argc) dur=atof(argv[++i]);
  }
  size_t sz=(size_t)mb*1024UL*1024UL;
  struct timespec t0,b; clock_gettime(CLOCK_MONOTONIC,&t0);
  long ok=0,nul=0;
  printf("MEMCHURN start mb=%ld dur=%.1f\n",mb,dur); fflush(stdout);
  for(;;){
    clock_gettime(CLOCK_MONOTONIC,&b);
    double el=(b.tv_sec-t0.tv_sec)+(b.tv_nsec-t0.tv_nsec)/1e9;
    if(el>=dur) break;
    void*p=rte_malloc(NULL,sz,64);
    if(!p){ nul++; continue; }
    for(size_t o=0;o<sz;o+=2UL*1024*1024) ((volatile char*)p)[o]=1;
    rte_free(p);
    ok++;
  }
  printf("MEMCHURN done ok=%ld null=%ld rate=%.1f/s\n",ok,nul,ok/dur); fflush(stdout);
  return 0;
}

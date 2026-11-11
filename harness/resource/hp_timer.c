/* hp_timer: allocate N 2MB hugepages ONE AT A TIME (mmap+touch), timing EACH; then free ONE AT A
 * TIME (munmap), timing EACH. Prints "A <i> <ns>" per alloc and "F <i> <ns>" per free, so we can see
 * whether an individual hugepage alloc/free latency SPIKES (e.g. kernel zeroing / pool boundary). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#define HP (2UL*1024*1024)
static long ns(struct timespec a, struct timespec b){ return (b.tv_sec-a.tv_sec)*1000000000L+(b.tv_nsec-a.tv_nsec); }
int main(int argc, char**argv){
  int N = argc>1 ? atoi(argv[1]) : 2000;
  void **p = calloc(N, sizeof(void*));
  struct timespec a,b;
  for(int i=0;i<N;i++){
    clock_gettime(CLOCK_MONOTONIC,&a);
    void *m = mmap(NULL, HP, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
    if(m==MAP_FAILED){ printf("A %d FAIL\n", i); continue; }
    *((volatile char*)m) = 1;            /* fault in -> kernel actually assigns+zeros the hugepage */
    clock_gettime(CLOCK_MONOTONIC,&b);
    p[i]=m; printf("A %d %ld\n", i, ns(a,b));
  }
  fflush(stdout);
  for(int i=0;i<N;i++){
    if(!p[i]) continue;
    clock_gettime(CLOCK_MONOTONIC,&a);
    munmap(p[i], HP);                     /* free one hugepage back to the pool */
    clock_gettime(CLOCK_MONOTONIC,&b);
    printf("F %d %ld\n", i, ns(a,b));
  }
  return 0;
}

/* hp_probe (VICTIM): for DURATION s, repeatedly mmap one 2MB hugepage, fault it in, munmap,
 * timing each full cycle (ns). This probes the SHARED kernel hugepage path (hugetlb_lock +
 * per-page zeroing) that SR-IOV does not isolate. Reports percentiles after a warmup window. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#define HP (2UL*1024*1024)
static long nsdiff(struct timespec a, struct timespec b){ return (b.tv_sec-a.tv_sec)*1000000000L+(b.tv_nsec-a.tv_nsec); }
static int cmpl(const void*x,const void*y){ long a=*(const long*)x,b=*(const long*)y; return a<b?-1:a>b?1:0; }
int main(int argc,char**argv){
  double dur = argc>1?atof(argv[1]):10.0;
  double warm= argc>2?atof(argv[2]):1.0;
  size_t cap=8000000; long*s=malloc(cap*sizeof(long)); size_t n=0; long fails=0;
  struct timespec t0,a,b; clock_gettime(CLOCK_MONOTONIC,&t0);
  for(;;){
    clock_gettime(CLOCK_MONOTONIC,&b);
    double el=(b.tv_sec-t0.tv_sec)+(b.tv_nsec-t0.tv_nsec)/1e9;
    if(el>=dur) break;
    clock_gettime(CLOCK_MONOTONIC,&a);
    void*m=mmap(NULL,HP,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB,-1,0);
    if(m==MAP_FAILED){ fails++; continue; }
    *((volatile char*)m)=1;
    munmap(m,HP);
    clock_gettime(CLOCK_MONOTONIC,&b);
    if(el>=warm && n<cap) s[n++]=nsdiff(a,b);
  }
  if(n==0){ printf("# hp_probe NO_SAMPLES fails=%ld\n",fails); return 1; }
  qsort(s,n,sizeof(long),cmpl);
  double sum=0; for(size_t i=0;i<n;i++) sum+=s[i];
  printf("# hp_probe samples=%zu fails=%ld mean_us=%.2f p50_us=%.2f p90_us=%.2f p99_us=%.2f p999_us=%.2f max_us=%.2f\n",
     n,fails, sum/n/1000.0,
     s[(size_t)(0.50*(n-1))]/1000.0, s[(size_t)(0.90*(n-1))]/1000.0,
     s[(size_t)(0.99*(n-1))]/1000.0, s[(size_t)(0.999*(n-1))]/1000.0, s[n-1]/1000.0);
  return 0;
}

/* esac_dom_ufunc.so — TENANT provider: extract hostname (DNS QNAME / HTTP Host / TLS SNI) from the
 * payload, then O(1) hash lookup (subdomain suffix-iterated) against the host-RW/tenant-RO domain
 * table. Returns an ACTION (ALLOW/DROP/KILL, or NONE=defer-to-L4). No per-packet full scan.
 * build: gcc -shared -fPIC -O2 esac_dom_ufunc.c -o esac_dom_ufunc.so -lrt -Wl,-z,relro,-z,now
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "esac_dom_shm.h"
#include <hs/hs.h>
#include "esac_hs_shm.h"
#include <stdint.h>

#define PAGE 4096UL
struct dstate { struct esac_dom_shm *shm; };
static union { struct dstate s; char pad[PAGE]; } g_sp __attribute__((aligned(4096)));
#define g_shm (g_sp.s.shm)
static char g_name[64];
const char *esac_dom_shm_name_resolved(void){ return g_name; }
void       *esac_dom_shm_base(void){ return (void*)g_shm; }
uint32_t    esac_dom_shm_version(void){ return g_shm?g_shm->version:0; }
static int  g_dbg=0;

static unsigned long long self_cgid(void){
    FILE *f=fopen("/proc/self/cgroup","r"); if(!f) return 0;
    char line[512]; unsigned long long cg=0;
    while(fgets(line,sizeof line,f)){ if(!strncmp(line,"0::",3)){ char*p=line+3,*nl=strchr(p,'\n'); if(nl)*nl=0;
        char path[600]; snprintf(path,sizeof path,"/sys/fs/cgroup%s",p); struct stat st; if(stat(path,&st)==0) cg=st.st_ino; break; } }
    fclose(f); return cg;
}

__attribute__((constructor))
static void dom_init(void){
    g_dbg=(getenv("ESAC_DOM_DEBUG")!=NULL);
    const char *env=getenv("ESAC_DOM_SHM");
    if(env&&*env) snprintf(g_name,sizeof g_name,"%s",env);
    else { unsigned long long cg=self_cgid(); if(cg) esac_dom_shm_name(g_name,sizeof g_name,cg); else snprintf(g_name,sizeof g_name,"%s",ESAC_DOM_SHM_DEFAULT); }
    int fd=shm_open(g_name,O_RDONLY,0);
    if(fd<0 && !(env&&*env) && strcmp(g_name,ESAC_DOM_SHM_DEFAULT)){ snprintf(g_name,sizeof g_name,"%s",ESAC_DOM_SHM_DEFAULT); fd=shm_open(g_name,O_RDONLY,0); }
    if(fd<0){ fprintf(stderr,"[esac_dom] shm_open(%s) RO failed (run esac_dom_ctl first)\n",g_name); return; }
    void *p=mmap(NULL,sizeof(struct esac_dom_shm),PROT_READ,MAP_SHARED,fd,0); close(fd);
    if(p==MAP_FAILED){ fprintf(stderr,"[esac_dom] mmap RO failed\n"); return; }
    g_shm=(struct esac_dom_shm*)p;
    int ro=(mprotect(&g_sp,PAGE,PROT_READ)==0);
    fprintf(stderr,"[esac_dom] attached RO shm=%s magic=%x version=%u ptr-RO=%d\n",g_name,g_shm->magic,g_shm->version,ro);
}

/* ---- parsers (all bounds-checked) ---- */
static int dns_sane(const unsigned char*p,uint32_t len){ if(len<12)return 0; uint32_t qd=(p[4]<<8)|p[5]; if(qd<1||qd>8)return 0; if(((p[2]>>3)&0xf)>2)return 0; return 1; }
static uint32_t dns_qname(const unsigned char*p,uint32_t len,char*out,uint32_t cap){
    uint32_t off=12,o=0;
    for(int i=0;i<64;i++){ if(off>=len)return 0; uint8_t ll=p[off]; if(ll==0)break; if(ll&0xC0)break; off++;
        if(off+ll>len)return 0; if(o+ll+1>=cap)break; for(uint32_t j=0;j<ll;j++)out[o++]=(char)p[off+j]; off+=ll; out[o++]='.'; }
    if(o>0&&out[o-1]=='.')o--; return o;
}
static int ci4(const unsigned char*a,const char*b){ for(int i=0;i<4;i++){ unsigned char c=a[i]; if(c>='A'&&c<='Z')c+=32; if(c!=(unsigned char)b[i])return 0;} return 1; }
static uint32_t http_host(const unsigned char*p,uint32_t len,char*out,uint32_t cap){
    uint32_t scan=len>2048?2048:len;
    for(uint32_t i=0;i+7<scan;i++){
        if(p[i]=='\r'&&p[i+1]=='\n'&&(p[i+2]=='H'||p[i+2]=='h')&&ci4(p+i+2,"host")&&p[i+6]==':'){
            uint32_t v=i+7; while(v<scan&&(p[v]==' '||p[v]=='\t'))v++;
            uint32_t s=v; while(v<scan&&p[v]!='\r'&&p[v]!='\n'&&p[v]!=':')v++;
            uint32_t n=v-s; if(n>0&&n<cap){ for(uint32_t k=0;k<n;k++)out[k]=(char)p[s+k]; return n; } return 0;
        }
    }
    return 0;
}
static uint32_t tls_sni(const unsigned char*p,uint32_t len,char*out,uint32_t cap){
    if(len<44||p[0]!=0x16||p[5]!=0x01) return 0;        /* handshake + ClientHello */
    uint32_t o=43;                                       /* after 32B random: session_id len byte */
    if(o>=len)return 0; o+=1+p[o];                       /* session_id */
    if(o+2>len)return 0; o+=2+((p[o]<<8)|p[o+1]);        /* cipher_suites */
    if(o+1>len)return 0; o+=1+p[o];                      /* compression */
    if(o+2>len)return 0; uint32_t extlen=(p[o]<<8)|p[o+1]; o+=2;
    uint32_t end=o+extlen; if(end>len)end=len;
    while(o+4<=end){
        uint32_t et=(p[o]<<8)|p[o+1], el=(p[o+2]<<8)|p[o+3]; o+=4;
        if(et==0){ /* server_name */
            if(o+5>end)return 0;
            uint32_t ntype=p[o+2], nlen=(p[o+3]<<8)|p[o+4], no=o+5;
            if(ntype==0&&no+nlen<=end&&nlen<cap){ for(uint32_t i=0;i<nlen;i++)out[i]=(char)p[no+i]; return nlen; }
            return 0;
        }
        o+=el;
    }
    return 0;
}

static int dom_lookup(uint32_t slot,const char*name,uint32_t n){
    if(n==0||n>ESAC_DOM_MAXLEN) return -1;
    uint64_t h=esac_dom_hash(name,n);
    uint32_t i=(uint32_t)(h&(ESAC_DOM_BUCKETS-1));
    for(int probe=0;probe<ESAC_DOM_BUCKETS;probe++){
        const volatile struct dom_entry*e=&g_shm->tbl[slot][i];
        if(!e->used) return -1;
        if(e->h==h&&e->len==n){ int same=1; for(uint32_t k=0;k<n;k++) if(e->name[k]!=name[k]){same=0;break;} if(same) return e->action; }
        i=(i+1)&(ESAC_DOM_BUCKETS-1);
    }
    return -1;
}


/* ================= HYBRID additions ================= */
static struct esac_hs_shm *g_hs = NULL;
static int g_hs_tried = 0;
static __thread hs_scratch_t *t_hscr = NULL;
static __thread uint32_t t_hver = 0xffffffffu;
static __thread const hs_database_t *t_hdb = NULL;

static void hs_attach_once(void){
    if (g_hs || g_hs_tried) return; g_hs_tried = 1;
    char nm[64]; const char *env = getenv("ESAC_HS_SHM");
    if (env && *env) snprintf(nm, sizeof nm, "%s", env);
    else snprintf(nm, sizeof nm, "%s", ESAC_HS_SHM_DEFAULT);
    int fd = shm_open(nm, O_RDONLY, 0); if (fd < 0) return;
    void *p = mmap(NULL, sizeof(struct esac_hs_shm), PROT_READ, MAP_SHARED, fd, 0); close(fd);
    if (p != MAP_FAILED) g_hs = (struct esac_hs_shm*)p;
    fprintf(stderr, "[esac_hybrid] hs attach %s -> %p\n", nm, (void*)g_hs);
}
static const hs_database_t* hs_cur(uint32_t *slot){
    if (!g_hs || g_hs->magic != ESAC_HS_SHM_MAGIC) return NULL;
    uint32_t ver = g_hs->version, s = g_hs->active_slot & 1u;
    const hs_database_t *db = (const hs_database_t*)g_hs->db[s];
    if (t_hver != ver || t_hdb != db || !t_hscr) {
        if (t_hscr) { hs_free_scratch(t_hscr); t_hscr = NULL; }
        if (hs_alloc_scratch(db, &t_hscr) != HS_SUCCESS) { t_hscr = NULL; return NULL; }
        t_hver = ver; t_hdb = db;
    }
    *slot = s; return db;
}
struct hmctx { const volatile uint8_t *pa; int matched; int best; };
static int hs_on_match(unsigned id, unsigned long long f, unsigned long long to, unsigned fl, void *c){
    (void)f; (void)to; (void)fl; struct hmctx *m = c;
    if (id < ESAC_HS_MAXPAT) { int a = m->pa[id]; if (a != ESAC_ACT_NONE && a > m->best) m->best = a; }
    m->matched = 1; return 0;
}
/* full-payload Hyperscan scan (slow/safe path): action or NONE */
static uint32_t hs_fullscan(const void *payload, uint32_t len){
    hs_attach_once();
    uint32_t slot; const hs_database_t *db = hs_cur(&slot);
    if (!db || !t_hscr) return ESAC_ACT_NONE;
    struct hmctx c = { g_hs->pat_action[slot], 0, ESAC_ACT_ALLOW };
    hs_scan(db, (const char*)payload, len, 0, t_hscr, hs_on_match, &c);
    return c.matched ? (uint32_t)c.best : g_hs->default_action[slot];
}

/* DNS "clean": exactly one question, no answer/authority/additional records, qname ends with 0x00
   (no compression), and nothing after QTYPE+QCLASS. Reads only the header + qname wire bytes. */
static int dns_clean(const unsigned char *p, uint32_t len){
    if (len < 12) return 0;
    uint32_t qd = (p[4]<<8)|p[5], an = (p[6]<<8)|p[7], ns = (p[8]<<8)|p[9], ar = (p[10]<<8)|p[11];
    if (qd != 1 || an != 0 || ns != 0 || ar != 0) return 0;
    uint32_t off = 12;
    for (int i = 0; i < 128; i++) {
        if (off >= len) return 0;
        uint8_t ll = p[off];
        if (ll == 0) { off++; break; }
        if (ll & 0xC0) return 0;          /* compression pointer -> not clean */
        off += 1 + ll;
    }
    return (off + 4 == len) ? 1 : 0;      /* exactly QTYPE(2)+QCLASS(2) after qname */
}

/* ---- decision tree (per packet) ---- */
static uint32_t esac_hybrid_scan(const void *payload, uint32_t len){
    if (!payload || len == 0) return ESAC_ACT_NONE;
    const unsigned char *p = payload;
    char host[256]; uint32_t hl = 0;

    if (len >= 44 && p[0] == 0x16 && p[5] == 0x01) {            /* TLS ClientHello */
        hl = tls_sni(p, len, host, sizeof host);
        if (hl == 0) return ESAC_ACT_NONE;                     /* encrypted/not CH -> nothing to see */
    } else if (len >= 16 && p[0] >= 'A' && p[0] <= 'Z') {       /* HTTP */
        hl = http_host(p, len, host, sizeof host);
        if (hl == 0) return hs_fullscan(payload, len);         /* no Host / deep content -> full-scan */
    } else if (len >= 12 && dns_sane(p, len)) {                /* DNS (UDP, offset 0) */
        if (dns_clean(p, len)) hl = dns_qname(p, len, host, sizeof host);
        if (hl == 0) return hs_fullscan(payload, len);         /* not clean -> full-scan */
    } else {
        return hs_fullscan(payload, len);                      /* unknown / non-standard -> full-scan */
    }
    if (hl == 0) return ESAC_ACT_NONE;

    for (uint32_t i = 0; i < hl; i++) { char c = host[i]; if (c >= 'A' && c <= 'Z') host[i] = c + 32; }
    if (hl && host[hl-1] == '.') hl--;
    if (!g_shm || g_shm->magic != ESAC_DOM_MAGIC) return ESAC_ACT_NONE;
    uint32_t slot = g_shm->active_slot & 1u, start = 0;
    for (int depth = 0; depth < 8; depth++) {                   /* exact + subdomain suffix hash */
        int a = dom_lookup(slot, host + start, hl - start);
        if (a >= 0) return (uint32_t)(unsigned)a;
        uint32_t dot = start; while (dot < hl && host[dot] != '.') dot++;
        if (dot >= hl) break; start = dot + 1; if (start >= hl) break;
    }
    return (uint32_t)g_shm->default_action[slot];              /* no hit -> default (none -> L4) */
}

struct hs_batch_item { uint64_t pl_ptr; uint32_t pl_len; uint32_t act; };
/* batched ufunc entry (same name/signature as the Hyperscan/dom batch providers -> drop-in) */
uint64_t esac_hs_scan(const void *arg, uint32_t count){
    struct hs_batch_item *it = (struct hs_batch_item*)(void*)(uintptr_t)arg;
    if (!it) return 0;
    if (count > 128) count = 128;
    for (uint32_t i = 0; i < count; i++) {
        if (it[i].pl_ptr && it[i].pl_len)
            it[i].act = esac_hybrid_scan((const void*)(uintptr_t)it[i].pl_ptr, it[i].pl_len);
        else it[i].act = ESAC_ACT_NONE;
    }
    return 0;
}

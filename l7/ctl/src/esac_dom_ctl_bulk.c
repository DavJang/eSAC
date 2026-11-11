/* esac_dom_ctl — HOST loader for the unified domain->action hash (DNS/HTTP/TLS hostnames).
 * Builds an open-addressing hash table in the inactive shm slot, then atomically flips.
 * usage: esac_dom_ctl <cgid|/name> "dom1:act1,dom2:act2,..." [default_action]
 *   act/default: allow|drop|kill|none  (domain default act = drop; no-match default = none)
 * build: gcc -O2 esac_dom_ctl.c -o esac_dom_ctl -lrt
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include "esac_dom_shm.h"

static int parse_act(const char *s){
    if (!s||!*s) return -1;
    if (!strcasecmp(s,"allow")||!strcasecmp(s,"a")) return ESAC_ACT_ALLOW;
    if (!strcasecmp(s,"drop") ||!strcasecmp(s,"d")) return ESAC_ACT_DROP;
    if (!strcasecmp(s,"kill") ||!strcasecmp(s,"k")) return ESAC_ACT_KILL;
    if (!strcasecmp(s,"none") ||!strcasecmp(s,"n")) return ESAC_ACT_NONE;
    return -1;
}

static void insert(struct dom_entry *tbl, const char *name, uint32_t n, uint8_t act){
    uint64_t h = esac_dom_hash(name, n);
    uint32_t i = (uint32_t)(h & (ESAC_DOM_BUCKETS-1));
    for (int p=0;p<ESAC_DOM_BUCKETS;p++){
        struct dom_entry *e = &tbl[i];
        if (!e->used || (e->h==h && e->len==n && memcmp(e->name,name,n)==0)){
            e->used=1; e->action=act; e->len=(uint16_t)n; e->h=h;
            memcpy(e->name,name,n); e->name[n]=0; return;
        }
        i = (i+1) & (ESAC_DOM_BUCKETS-1);
    }
    fprintf(stderr,"table full, dropped %.*s\n",(int)n,name);
}

int main(int argc, char **argv){
    const char *arg  = (argc>1)?argv[1]:"0";
    const char *spec = (argc>2)?argv[2]:"evil.com:drop";
    int def = (argc>3)?parse_act(argv[3]):ESAC_ACT_NONE; if (def<0) def=ESAC_ACT_NONE;

    char namebuf[64]; const char *name;
    if (arg[0]=='/') name=arg;
    else { esac_dom_shm_name(namebuf,sizeof namebuf,strtoull(arg,NULL,10)); name=namebuf; }

    int fd = shm_open(name,O_CREAT|O_RDWR,0644);
    if (fd<0){ perror("shm_open"); return 1; }
    if (ftruncate(fd,sizeof(struct esac_dom_shm))!=0){ perror("ftruncate"); return 1; }
    struct esac_dom_shm *s = mmap(NULL,sizeof(*s),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if (s==MAP_FAILED){ perror("mmap"); return 1; }
    close(fd);

    uint32_t fresh = (s->magic!=ESAC_DOM_MAGIC);
    uint32_t inact = fresh?0u:(s->active_slot^1u);
    memset(s->tbl[inact],0,sizeof(s->tbl[inact]));

    unsigned n=0;
    #define DOM_INS(TOKEXPR) do{ char *tok=(TOKEXPR); uint8_t act=ESAC_ACT_DROP; \
        char *cc=strrchr(tok,':'); if(cc){ int a=parse_act(cc+1); if(a>=0){ act=(uint8_t)a; *cc=0; } } \
        uint32_t L=strlen(tok); while(L>0&&tok[L-1]=='.')L--; \
        for(uint32_t i=0;i<L;i++){ char ch=tok[i]; if(ch>='A'&&ch<='Z') tok[i]=ch+32; } \
        if(L!=0&&L<=ESAC_DOM_MAXLEN){ insert(s->tbl[inact],tok,L,act); if(n<5)printf("   dom[%u]='%.*s' -> act=%u\n",n,(int)L,tok,act); n++; } }while(0)
    FILE *pf=fopen(spec,"r");
    if(pf){
        char line[1024];
        while(fgets(line,sizeof line,pf)){
            char *s0=line; while(*s0==' '||*s0=='\t')s0++;
            char *e=s0+strlen(s0); while(e>s0&&(e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t'))*--e=0;
            if(!*s0||*s0=='#')continue;
            DOM_INS(s0);
        }
        fclose(pf);
    } else {
        char *dup=strdup(spec);
        for(char *tok=strtok(dup,",");tok;tok=strtok(NULL,",")) DOM_INS(tok);
    }
    if(n>5) printf("   ... (%u domains total)\n", n);

    s->default_action[inact]=(uint8_t)def;
    __sync_synchronize();
    s->active_slot=inact;
    s->version = fresh?1u:(s->version+1u);
    s->magic=ESAC_DOM_MAGIC;
    __sync_synchronize();
    printf("[esac_dom_ctl] shm=%s version=%u active=%u ndom=%u default=%d\n",name,s->version,s->active_slot,n,def);
    return 0;
}

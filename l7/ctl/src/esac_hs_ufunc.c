/* esac_hs_ufunc.so -- Hyperscan payload-scan provider for eSAC + RO hardening.
 *
 * Hardening (so the tenant cannot tamper the L7 patterns):
 *   (1) the compiled Hyperscan DB is placed on page-aligned memory and
 *       mprotect()'d READ-ONLY after compile.
 *   (2) the state pointers (db, scratch_proto) live in a dedicated page-aligned
 *       struct that is also mprotect()'d READ-ONLY after init -> the db pointer
 *       itself cannot be NULLed/forged. (Isolated to its own page so RO'ing it
 *       does NOT touch .data the C runtime needs at exit.)
 * Scratch stays RW (per-scan). TamperSentinel catches mprotect/proc-self-mem bypass.
 *
 * build: gcc -shared -fPIC -O2 esac_hs_ufunc.c -o esac_hs_ufunc.so -lhs
 */
#define _GNU_SOURCE
#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096UL
static unsigned long pdown(unsigned long a){ return a & ~(PAGE-1); }
static unsigned long pup(unsigned long a){ return (a + PAGE - 1) & ~(PAGE-1); }

/* ---- protected state: its own page, RO'd after init ---- */
struct hs_state {
    hs_database_t *db;
    hs_scratch_t  *scratch_proto;
    unsigned long  db_ro_base;
    unsigned long  db_ro_len;
};
static union { struct hs_state s; char pad[PAGE]; }
    g_sp __attribute__((aligned(4096)));
#define g_db            (g_sp.s.db)
#define g_scratch_proto (g_sp.s.scratch_proto)
#define g_db_ro_base    (g_sp.s.db_ro_base)
#define g_db_ro_len     (g_sp.s.db_ro_len)

static __thread hs_scratch_t *t_scratch = NULL;   /* per-thread, stays RW (TLS) */

/* page-aligned allocator used ONLY for the HS database (so it can be RO'd). */
#define MAXDB 64
static struct { void *base; size_t len; } g_dba[MAXDB];
static int g_ndba = 0;
static void *db_alloc(size_t n){
    size_t len = pup(n ? n : 1);
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (g_ndba < MAXDB) { g_dba[g_ndba].base = p; g_dba[g_ndba].len = len; g_ndba++; }
    return p;
}
static void db_free(void *p){
    if (!p) return;
    for (int i = 0; i < g_ndba; i++) if (g_dba[i].base == p) { munmap(p, g_dba[i].len); g_dba[i].base = NULL; return; }
}

static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *ctx)
{ (void)id;(void)from;(void)to;(void)flags; *(int*)ctx = 1; return 1; }

__attribute__((constructor))
static void esac_hs_init(void)
{
    char **pats = NULL; unsigned n = 0, cap = 0;
    const char *env = getenv("ESAC_HS_PATTERNS");
    if (env && *env) {
        char *dup = strdup(env);
        for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
            if (n >= cap) { cap = cap ? cap*2 : 8; pats = realloc(pats, cap*sizeof(char*)); }
            pats[n++] = strdup(tok);
        }
        free(dup);
    } else {
        static const char *def[] = { "evil", "malware", "phishing", "baddomain" };
        n = 4; pats = malloc(n*sizeof(char*));
        for (unsigned i=0;i<n;i++) pats[i] = strdup(def[i]);
    }
    if (n == 0) { fprintf(stderr, "[esac_hs] no patterns\n"); return; }

    unsigned *ids = malloc(n*sizeof(unsigned)), *flags = malloc(n*sizeof(unsigned));
    for (unsigned i=0;i<n;i++){ ids[i]=i; flags[i]=HS_FLAG_DOTALL|HS_FLAG_SINGLEMATCH; }

    hs_set_database_allocator(db_alloc, db_free);   /* DB on page-aligned mem */

    hs_compile_error_t *err = NULL;
    if (hs_compile_multi((const char*const*)pats, flags, ids, n, HS_MODE_BLOCK, NULL, &g_db, &err) != HS_SUCCESS) {
        fprintf(stderr, "[esac_hs] compile failed: %s\n", err?err->message:"?");
        hs_free_compile_error(err); return;
    }
    if (hs_alloc_scratch(g_db, &g_scratch_proto) != HS_SUCCESS) {
        fprintf(stderr, "[esac_hs] scratch alloc failed\n"); return;
    }

    /* (1) RO the compiled DB */
    size_t dbsz = 0;
    if (hs_database_size(g_db, &dbsz) == HS_SUCCESS) {
        unsigned long base = pdown((unsigned long)g_db);
        unsigned long len  = pup(((unsigned long)g_db - base) + dbsz);
        if (mprotect((void*)base, len, PROT_READ) == 0) { g_db_ro_base = base; g_db_ro_len = len; }
    }
    /* (2) RO the state page (db / scratch_proto pointers) -- own page, safe */
    int sp_ro = (mprotect(&g_sp, PAGE, PROT_READ) == 0);
    fprintf(stderr, "[esac_hs] compiled %u patterns, DB RO @ %lx(%zuB), state-page RO=%d\n",
            n, g_db_ro_base, dbsz, sp_ro);
}

/* RO'd DB range + state-page address (for verification / tamper_sentinel) */
void esac_hs_db_region(void **addr, unsigned long *len){ if(addr)*addr=(void*)g_db_ro_base; if(len)*len=g_db_ro_len; }
void *esac_hs_dbptr_addr(void){ return (void*)&g_db; }

uint64_t esac_hs_scan(const void *payload, uint32_t len)
{
    if (!g_db || !payload || len == 0) return 0;
    if (!t_scratch) { if (hs_clone_scratch(g_scratch_proto, &t_scratch) != HS_SUCCESS) return 0; }
    int matched = 0;
    hs_scan(g_db, (const char*)payload, len, 0, t_scratch, on_match, &matched);
    return (uint64_t)matched;
}

/* eSAC batch scanner (ADDED) with debug. layout matches hs_batch_item {u64 pl_ptr;u32 pl_len;u32 act}. */
#include <stdio.h>
struct esac_hs_batch_item { uint64_t pl_ptr; uint32_t pl_len; uint32_t act; };
uint64_t gown_hs_scan(void *items, uint64_t n)
{
    struct esac_hs_batch_item *it = (struct esac_hs_batch_item *)items;
    if (!g_db || !it) { fprintf(stderr,"[GOWN_DBG] no db/items\n"); return 0; }
    if (!t_scratch) { if (hs_clone_scratch(g_scratch_proto, &t_scratch) != HS_SUCCESS) return 0; }
    if (n > 128) n = 128;
    fprintf(stderr,"[GOWN_DBG] called n=%llu\n",(unsigned long long)n);
    uint64_t hits = 0;
    for (uint64_t i = 0; i < n; i++) {
        if (!it[i].pl_ptr || it[i].pl_len == 0) continue;
        int matched = 0;
        hs_scan(g_db, (const char*)(uintptr_t)it[i].pl_ptr, it[i].pl_len, 0, t_scratch, on_match, &matched);
        fprintf(stderr,"[GOWN_DBG] i=%llu len=%u matched=%d\n",(unsigned long long)i,it[i].pl_len,matched);
        if (matched) { it[i].act = 2u; hits++; }
    }
    fprintf(stderr,"[GOWN_DBG] hits=%llu\n",(unsigned long long)hits);
    return hits;
}

/* unique single-payload scanner (external-only) with debug, for the hsreal BPF. */
uint64_t esac_hs1(const void *p, uint32_t len)
{
    if (!g_db || !p || len == 0) { fprintf(stderr,"[HS1] nodb/empty len=%u\n",len); return 0; }
    if (!t_scratch) { if (hs_clone_scratch(g_scratch_proto, &t_scratch) != HS_SUCCESS) return 0; }
    int matched = 0;
    hs_scan(g_db, (const char*)p, len > 1460 ? 1460 : len, 0, t_scratch, on_match, &matched);
    fprintf(stderr,"[HS1] len=%u matched=%d first=%c%c%c\n", len, matched,
            len>0?((const char*)p)[0]:0, len>1?((const char*)p)[1]:0, len>2?((const char*)p)[2]:0);
    return (uint64_t)matched;
}

/* esac_hs_ctl — HOST-side Hyperscan L7 policy loader/updater (trusted), data-driven actions.
 * Each pattern carries an action (like an L4 rule's action). Compiles patterns -> HS DB in the
 * inactive shm slot, fills the per-pattern action table + default, then atomically flips.
 * Run again to UPDATE patterns AND/OR actions at runtime (tenant picks it up, no restart).
 *
 * usage: esac_hs_ctl <cgid | /shm_name> "pat1:act1,pat2:act2,..." [default_action]
 *   act/default: allow|a | drop|d | kill|k | none|n   (pattern default = drop; no-match default = none)
 *   numeric 1st arg -> /esac_hs_db_<cgid> ; /name -> explicit
 * build: gcc -O2 esac_hs_ctl.c -o esac_hs_ctl -lhs -lrt
 */
#define _GNU_SOURCE
#include <hs/hs.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "esac_hs_shm.h"

static int parse_act(const char *s)   /* -> ACT_* or -1 if not an action word */
{
    if (!s || !*s) return -1;
    if (!strcasecmp(s,"allow")||!strcasecmp(s,"a")) return ESAC_ACT_ALLOW;
    if (!strcasecmp(s,"drop") ||!strcasecmp(s,"d")) return ESAC_ACT_DROP;
    if (!strcasecmp(s,"kill") ||!strcasecmp(s,"k")) return ESAC_ACT_KILL;
    if (!strcasecmp(s,"none") ||!strcasecmp(s,"n")) return ESAC_ACT_NONE;
    return -1;
}

int main(int argc, char **argv)
{
    const char *arg    = (argc > 1) ? argv[1] : "0";
    const char *spec   = (argc > 2) ? argv[2] : "evil:drop,malware:drop";
    int def_act = (argc > 3) ? parse_act(argv[3]) : ESAC_ACT_NONE;
    if (def_act < 0) def_act = ESAC_ACT_NONE;

    char namebuf[64]; const char *name;
    if (arg[0] == '/') name = arg;
    else { esac_hs_shm_name(namebuf, sizeof namebuf, strtoull(arg, NULL, 10)); name = namebuf; }

    /* parse patterns: from FILE (one "pat[:act]" per line) if spec is a readable file, else CSV "pat:act,..." */
    char **pats = NULL; uint8_t *acts = NULL; unsigned n = 0, cap = 0;
    FILE *pf = fopen(spec, "r");
    if (pf) {
        char line[1024];
        while (fgets(line, sizeof line, pf)) {
            char *s0 = line; while (*s0 == ' ' || *s0 == '\t') s0++;
            char *e = s0 + strlen(s0);
            while (e > s0 && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
            if (!*s0 || *s0 == '#') continue;
            int a = ESAC_ACT_DROP;
            char *colon = strrchr(s0, ':');
            if (colon) { int pa = parse_act(colon + 1); if (pa >= 0) { a = pa; *colon = 0; } }
            if (!*s0) continue;
            if (n >= cap) { cap = cap ? cap*2 : 1024; pats = realloc(pats, cap*sizeof(char*)); acts = realloc(acts, cap); }
            pats[n] = strdup(s0); acts[n] = (uint8_t)a; n++;
            if (n >= ESAC_HS_MAXPAT) break;
        }
        fclose(pf);
    } else {
        char *dup = strdup(spec);
        for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
            int a = ESAC_ACT_DROP;
            char *colon = strrchr(tok, ':');
            if (colon) { int pa = parse_act(colon + 1); if (pa >= 0) { a = pa; *colon = 0; } }
            if (n >= cap) { cap = cap ? cap*2 : 8; pats = realloc(pats, cap*sizeof(char*)); acts = realloc(acts, cap); }
            pats[n] = strdup(tok); acts[n] = (uint8_t)a; n++;
            if (n >= ESAC_HS_MAXPAT) break;
        }
    }
    if (n == 0) { fprintf(stderr, "no patterns\n"); return 1; }

    unsigned *ids = malloc(n*sizeof(unsigned)), *fl = malloc(n*sizeof(unsigned));
    unsigned __base = getenv("ESAC_HS_EXACT") ? HS_FLAG_SINGLEMATCH : (HS_FLAG_SINGLEMATCH|HS_FLAG_CASELESS);
    for (unsigned i = 0; i < n; i++) { ids[i] = i; fl[i] = __base; }
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    size_t *lens = (size_t*)malloc(n*sizeof(size_t)); for (unsigned i=0;i<n;i++) lens[i]=strlen(pats[i]);
    if (hs_compile_multi((const char*const*)pats, fl, ids, n, HS_MODE_BLOCK, NULL, &db, &err) != HS_SUCCESS) {
        fprintf(stderr, "compile fail: %s\n", err ? err->message : "?"); return 1;
    }
    char *ser = NULL; size_t serlen = 0;
    if (hs_serialize_database(db, &ser, &serlen) != HS_SUCCESS) { fprintf(stderr, "serialize fail\n"); return 1; }
    size_t need = 0; hs_serialized_database_size(ser, serlen, &need);
    if (need > ESAC_HS_SLOT_MAX) { fprintf(stderr, "db too big: %zu\n", need); return 1; }

    int fd = shm_open(name, O_CREAT|O_RDWR, 0644);
    if (fd < 0) { perror("shm_open"); return 1; }
    if (ftruncate(fd, sizeof(struct esac_hs_shm)) != 0) { perror("ftruncate"); return 1; }
    struct esac_hs_shm *s = mmap(NULL, sizeof(*s), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (s == MAP_FAILED) { perror("mmap"); return 1; }
    close(fd);

    uint32_t fresh    = (s->magic != ESAC_HS_SHM_MAGIC);
    uint32_t inactive = fresh ? 0u : (s->active_slot ^ 1u);

    if (hs_deserialize_database_at(ser, serlen, (hs_database_t*)s->db[inactive]) != HS_SUCCESS) {
        fprintf(stderr, "deserialize_at fail\n"); return 1;
    }
    s->slot_len[inactive] = (uint32_t)need;
    s->npat[inactive]     = n;
    s->default_action[inactive] = (uint8_t)def_act;
    for (unsigned i = 0; i < n && i < ESAC_HS_MAXPAT; i++) s->pat_action[inactive][i] = acts[i];

    __sync_synchronize();
    s->active_slot = inactive;
    s->version     = fresh ? 1u : (s->version + 1u);
    s->magic       = ESAC_HS_SHM_MAGIC;
    __sync_synchronize();

    printf("[esac_hs_ctl] shm=%s version=%u active=%u npat=%u default_act=%d db=%zuB\n",
           name, s->version, s->active_slot, n, def_act, need);
    for (unsigned i = 0; i < n && i < 5; i++) printf("   pat[%u]='%s' -> act=%u\n", i, pats[i], acts[i]);
    if (n > 5) printf("   ... (%u patterns total)\n", n);
    return 0;
}

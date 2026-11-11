/* Unified hostname->action domain hash for L7 (DNS QNAME + HTTP Host + TLS SNI), host-RW/tenant-RO.
 * Replaces Hyperscan per-packet full-scan with: extract the exact hostname (first packet of a flow)
 * -> hash lookup (O(1), suffix-iterated for subdomains). ~L4 cost. cgroup-keyed per-tenant shm.
 * Only for EXACT host/domain blocking; true regex/substring DPI still needs Hyperscan. */
#ifndef ESAC_DOM_SHM_H
#define ESAC_DOM_SHM_H
#include <stdint.h>
#include <stdio.h>

#define ESAC_DOM_MAGIC   0x474F444Du      /* 'GODM' */
#define ESAC_DOM_MAXLEN  255
#define ESAC_DOM_BUCKETS 4096             /* power of two (open addressing) */
#define ESAC_DOM_SHM_DEFAULT "/esac_dom_db"

#define ESAC_ACT_ALLOW 0
#define ESAC_ACT_DROP  2
#define ESAC_ACT_KILL  3
#define ESAC_ACT_NONE  255

struct dom_entry {
    uint8_t  used;
    uint8_t  action;
    uint16_t len;
    uint64_t h;
    char     name[ESAC_DOM_MAXLEN + 1];
};

struct esac_dom_shm {
    volatile uint32_t magic;
    volatile uint32_t version;
    volatile uint32_t active_slot;
    volatile uint8_t  default_action[2];
    volatile uint8_t  _pad[2];
    struct dom_entry  tbl[2][ESAC_DOM_BUCKETS];   /* double-buffered hash table */
};

static inline uint64_t esac_dom_hash(const char *s, uint32_t n) {
    uint64_t h = 1469598103934665603ULL;          /* FNV-1a 64 */
    for (uint32_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}
static inline void esac_dom_shm_name(char *b, size_t n, unsigned long long cgid) {
    snprintf(b, n, "/esac_dom_db_%llu", cgid);
}
#endif

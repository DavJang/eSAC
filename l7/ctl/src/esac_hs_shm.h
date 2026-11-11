/* Shared layout for host-controlled, tenant-RO Hyperscan L7 policy (runtime-updatable, per-tenant).
 * Mirrors L4 (comm_policy) as closely as the engine allows: the ACTION is DATA (a per-pattern
 * table, like L4's value), not hardcoded block/allow in the filter. Host (esac_hs_ctl) maps RW
 * and updates; tenant (esac_hs_ufunc_shm.so) maps RO and scans. Per-tenant via cgroup: shm name
 * = /esac_hs_db_<cgid> (cgroup-v2 inode, same identity L4 uses as its key).
 *
 * Engine difference that CANNOT be unified: L4 match = exact 5-tuple hash lookup; L7 match =
 * regex/substring over payload (Hyperscan), which is not a hashable key -> needs the scan engine
 * via ufunc. Everything else (action=data table, RO, host-load, runtime update, cgroup id) is same.
 */
#ifndef ESAC_HS_SHM_H
#define ESAC_HS_SHM_H
#include <stdint.h>
#include <stdio.h>

#define ESAC_HS_SHM_MAGIC   0x47484E32u      /* 'GHN2' (action-table layout) */
#define ESAC_HS_SLOT_MAX    (1u << 20)        /* 1 MiB per DB slot */
#define ESAC_HS_MAXPAT      256
#define ESAC_HS_SHM_DEFAULT "/esac_hs_db"

/* actions mirror L4 comm_policy values; NONE = L7 has no opinion -> defer to L4 */
#define ESAC_ACT_ALLOW 0
#define ESAC_ACT_DROP  2
#define ESAC_ACT_KILL  3
#define ESAC_ACT_NONE  255

/* double-buffered: host writes inactive slot (db + action table), then flips active_slot + version */
struct esac_hs_shm {
    volatile uint32_t magic;
    volatile uint32_t version;
    volatile uint32_t active_slot;            /* 0 or 1 */
    volatile uint32_t slot_len[2];            /* deserialized db length per slot */
    volatile uint32_t npat[2];                /* pattern count per slot */
    volatile uint8_t  default_action[2];      /* no-match action per slot (ACT_*) */
    volatile uint8_t  _pad[6];
    volatile uint8_t  pat_action[2][ESAC_HS_MAXPAT];  /* pattern id -> ACT_* (the "value" table) */
    uint8_t  db[2][ESAC_HS_SLOT_MAX] __attribute__((aligned(64)));
};

/* per-tenant shm name from the tenant's cgroup-v2 inode */
static inline void esac_hs_shm_name(char *buf, size_t n, unsigned long long cgid) {
    snprintf(buf, n, "/esac_hs_db_%llu", cgid);
}

#endif

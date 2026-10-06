#ifndef _SEPOL_SID_TABLE_H_
#define _SEPOL_SID_TABLE_H_

#include <sepol/policydb.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque SID table for use with the security server helpers (sepol_sid_to_context,
 * sepol_context_to_sid, etc.) without exposing sidtab_t.
 */

typedef struct sepol_sid_table sepol_sid_table_t;

extern sepol_sid_table_t *sepol_sid_table_new(void);

/*
 * Frees a SID table created by sepol_sid_table_new(). If this table is
 * currently installed as the process-global active table (via
 * sepol_sid_table_set_opaque()), it is automatically uninstalled first,
 * so subsequent calls into the security server helpers (sepol_sid_to_context,
 * sepol_context_to_sid, etc.) will not dereference the freed table.
 */
extern void sepol_sid_table_free(sepol_sid_table_t *tab);

extern int sepol_sid_table_load_isids(sepol_sid_table_t *tab,
				      sepol_policydb_t *policydb);

/*
 * Installs tab as the process-global active SID table used internally by
 * the security server helpers (sepol_sid_to_context, sepol_context_to_sid,
 * etc.). Only one table can be active at a time; calling this again with
 * a different table replaces the previous one as the active table.
 */
extern int sepol_sid_table_set_opaque(sepol_sid_table_t *tab);

#ifdef __cplusplus
}
#endif

#endif

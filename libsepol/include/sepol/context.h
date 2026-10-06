#ifndef _SEPOL_CONTEXT_H_
#define _SEPOL_CONTEXT_H_

#include <sepol/context_record.h>
#include <sepol/policydb.h>
#include <sepol/handle.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -- Deprecated -- */

extern int sepol_check_context(const char *context);

/* -- End deprecated -- */

extern int sepol_context_check(sepol_handle_t *handle,
			       const sepol_policydb_t *policydb,
			       const sepol_context_t *context);

extern int sepol_mls_contains(sepol_handle_t *handle,
			      const sepol_policydb_t *policydb,
			      const char *mls1, const char *mls2,
			      int *response);

extern int sepol_mls_check(sepol_handle_t *handle,
			   const sepol_policydb_t *policydb, const char *mls);

/*
 * Build a security context string from policy-internal symbol values (1-based)
 * and optional MLS range string (same MLS syntax as in full context strings).
 * When MLS is disabled for the policy, mls_range must be NULL or empty.
 */
extern int sepol_values_to_context_string(sepol_handle_t *handle,
					  const sepol_policydb_t *policydb,
					  uint32_t user_val, uint32_t role_val,
					  uint32_t type_val,
					  const char *mls_range, char **out,
					  size_t *out_len);

extern int sepol_values_to_context_record(sepol_handle_t *handle,
					  const sepol_policydb_t *policydb,
					  uint32_t user_val, uint32_t role_val,
					  uint32_t type_val,
					  const char *mls_range,
					  sepol_context_t **record);

/*
 * Resolve a SID to a context using only the given policydb (no process-global
 * sepol_set_policydb / sepol_set_sidtab). Builds a temporary SID table from
 * the policy's initial SID contexts on each call; for many lookups prefer
 * sepol_sid_table_t with sepol_sid_table_load_isids().
 */
extern int
sepol_policydb_sid_to_context_string(sepol_handle_t *handle,
				     const sepol_policydb_t *policydb,
				     uint32_t sid, char **out, size_t *out_len);

extern int
sepol_policydb_sid_to_context_record(sepol_handle_t *handle,
				     const sepol_policydb_t *policydb,
				     uint32_t sid, sepol_context_t **record);

/*
 * Legacy security-server helpers (sepol_sid_to_context,
 * sepol_sid_to_context_record) remain in <sepol/policydb/services.h> and
 * require an active process-global policydb and sidtab.
 */

#ifdef __cplusplus
}
#endif

#endif

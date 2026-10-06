#ifndef _SEPOL_ROLES_H_
#define _SEPOL_ROLES_H_

#include <sepol/policydb.h>
#include <sepol/role_record.h>
#include <sepol/handle.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_role_iter;
typedef struct sepol_role_iter sepol_role_iter_t;

/* Return the number of roles */
extern int sepol_role_count(sepol_handle_t *handle, const sepol_policydb_t *p,
			    unsigned int *response);

/* Check if the specified role exists */
extern int sepol_role_exists(sepol_handle_t *handle, const sepol_policydb_t *p,
			     const sepol_role_key_t *key, int *response);

/* Query a role - returns the role or NULL if not found */
extern int sepol_role_query(sepol_handle_t *handle, const sepol_policydb_t *p,
			    const sepol_role_key_t *key,
			    sepol_role_t **response);

/* Resolve a role value to its name.  Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_role_value_to_name(sepol_handle_t *handle,
				    const sepol_policydb_t *p, uint32_t value,
				    const char **name);

/* Query a role by value - returns the role or NULL if not found */
extern int sepol_role_query_by_value(sepol_handle_t *handle,
				     const sepol_policydb_t *p, uint32_t value,
				     sepol_role_t **response);

/*
 * Iterating roles. Iteration order follows ascending internal value
 * assignment, which typically -- but is not guaranteed to -- match
 * declaration order; callers should not treat it as a stable guarantee
 * across policydb versions.
 */
extern int sepol_role_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_role_iter_t **iter);
extern void sepol_role_iter_destroy(sepol_role_iter_t *iter);
extern int sepol_role_iter_next(sepol_handle_t *handle, sepol_role_iter_t *iter,
				sepol_role_t **item);

#ifdef __cplusplus
}
#endif

#endif

#ifndef _SEPOL_BOOLEANS_H_
#define _SEPOL_BOOLEANS_H_

#include <stddef.h>
#include <stdint.h>
#include <sepol/policydb.h>
#include <sepol/boolean_record.h>
#include <sepol/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set the specified boolean */
extern int sepol_bool_set(sepol_handle_t *handle, sepol_policydb_t *policydb,
			  const sepol_bool_key_t *key,
			  const sepol_bool_t *data);

/* Return the number of booleans */
extern int sepol_bool_count(sepol_handle_t *handle, const sepol_policydb_t *p,
			    unsigned int *response);

/* Check if the specified boolean exists */
extern int sepol_bool_exists(sepol_handle_t *handle,
			     const sepol_policydb_t *policydb,
			     const sepol_bool_key_t *key, int *response);

/* Query a boolean - returns the boolean, or NULL if not found */
extern int sepol_bool_query(sepol_handle_t *handle, const sepol_policydb_t *p,
			    const sepol_bool_key_t *key,
			    sepol_bool_t **response);

/* Iterate the booleans
 * The handler may return:
 * -1 to signal an error condition,
 * 1 to signal successful exit
 * 0 to signal continue */

extern int
sepol_bool_iterate(sepol_handle_t *handle, const sepol_policydb_t *policydb,
		   int (*fn)(const sepol_bool_t *boolean, void *fn_arg),
		   void *arg);

/* Look up the name of a boolean by its 1-based value.
 * Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_bool_value_to_name(sepol_handle_t *handle,
				    const sepol_policydb_t *p, uint32_t value,
				    const char **name);

extern int sepol_bool_query_by_value(sepol_handle_t *handle,
				     const sepol_policydb_t *p, uint32_t value,
				     sepol_bool_t **response);

typedef struct sepol_bool_iter sepol_bool_iter_t;

/*
 * Iteration order follows ascending internal value assignment, which
 * typically -- but is not guaranteed to -- match declaration order;
 * callers should not treat it as a stable guarantee across policydb
 * versions.
 */
extern int sepol_bool_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_bool_iter_t **iter);

extern void sepol_bool_iter_destroy(sepol_bool_iter_t *iter);

extern int sepol_bool_iter_next(sepol_handle_t *handle, sepol_bool_iter_t *iter,
				sepol_bool_t **item);

#ifdef __cplusplus
}
#endif

#endif

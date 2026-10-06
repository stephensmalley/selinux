#ifndef _SEPOL_MLS_ITER_H_
#define _SEPOL_MLS_ITER_H_

#include <sepol/cat_set.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTE on sepol_cat_set_iter_t **cat_iter parameters below: see the
 * ownership contract documented in cat_set.h. The callee always allocates
 * a new, caller-owned iterator that must be freed with
 * sepol_cat_set_iter_destroy().
 */

/* Category iterator */

typedef struct sepol_cat_iter sepol_cat_iter_t;

/*
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal symbol table) and may change between library versions or
 * policydb loads; callers must not rely on it matching declaration order
 * or being stable across calls.
 */
extern int sepol_cat_iter_create(sepol_handle_t *handle,
				 const sepol_policydb_t *p,
				 sepol_cat_iter_t **iter);

extern void sepol_cat_iter_destroy(sepol_cat_iter_t *iter);

extern int sepol_cat_iter_next(sepol_handle_t *handle, sepol_cat_iter_t *iter,
			       const char **name, uint32_t *value,
			       int *isalias);

/* Sensitivity iterator */

typedef struct sepol_sens_iter sepol_sens_iter_t;

/*
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal symbol table) and may change between library versions or
 * policydb loads; callers must not rely on it matching declaration order
 * or being stable across calls.
 */
extern int sepol_sens_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_sens_iter_t **iter);

extern void sepol_sens_iter_destroy(sepol_sens_iter_t *iter);

extern int sepol_sens_iter_next(sepol_handle_t *handle, sepol_sens_iter_t *iter,
				const char **name, uint32_t *sens_value,
				int *isalias);

extern int sepol_sens_iter_get_level_cat(sepol_handle_t *handle,
					 const sepol_sens_iter_t *iter,
					 sepol_cat_set_iter_t **cat_iter);

/* Resolve a category value to its name.  Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_cat_value_to_name(sepol_handle_t *handle,
				   const sepol_policydb_t *p, uint32_t value,
				   const char **name);

/* Resolve a sensitivity value to its name.  Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_sens_value_to_name(sepol_handle_t *handle,
				    const sepol_policydb_t *p, uint32_t value,
				    const char **name);

#ifdef __cplusplus
}
#endif

#endif

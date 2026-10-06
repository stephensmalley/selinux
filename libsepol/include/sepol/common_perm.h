#ifndef _SEPOL_COMMON_PERM_H_
#define _SEPOL_COMMON_PERM_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sepol_common_iter sepol_common_iter_t;

/*
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal symbol table) and may change between library versions or
 * policydb loads; callers must not rely on it matching declaration order
 * or being stable across calls.
 */
extern int sepol_common_iter_create(sepol_handle_t *handle,
				    const sepol_policydb_t *p,
				    sepol_common_iter_t **iter);

extern void sepol_common_iter_destroy(sepol_common_iter_t *iter);

extern int sepol_common_iter_next(sepol_handle_t *handle,
				  sepol_common_iter_t *iter, const char **name,
				  uint32_t *value);

typedef struct sepol_common_perm_iter sepol_common_perm_iter_t;

extern int sepol_common_perm_iter_create(sepol_handle_t *handle,
					 const sepol_policydb_t *p,
					 uint32_t common_value,
					 sepol_common_perm_iter_t **iter);

extern void sepol_common_perm_iter_destroy(sepol_common_perm_iter_t *iter);

extern int sepol_common_perm_iter_next(sepol_handle_t *handle,
				       sepol_common_perm_iter_t *iter,
				       const char **perm_name);

/* Resolve a common permission set value to its name.
 * Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_common_value_to_name(sepol_handle_t *handle,
				      const sepol_policydb_t *p, uint32_t value,
				      const char **name);

#ifdef __cplusplus
}
#endif

#endif

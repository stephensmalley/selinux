#ifndef _SEPOL_PERMISSIVE_H_
#define _SEPOL_PERMISSIVE_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sepol_permissive_iter sepol_permissive_iter_t;

extern int sepol_permissive_iter_create(sepol_handle_t *handle,
					const sepol_policydb_t *p,
					sepol_permissive_iter_t **iter);

extern void sepol_permissive_iter_destroy(sepol_permissive_iter_t *iter);

/* On each successful call with iteration remaining, *type_value is set
 * to the value of a type marked permissive -- i.e. the same 1-based
 * value returned by sepol_type_query()/used as a type_datum_t's
 * s.value, not a 0-based bit position. Iteration is exhausted once
 * *type_value is set to 0 (0 is never a valid type value). */
extern int sepol_permissive_iter_next(sepol_handle_t *handle,
				      sepol_permissive_iter_t *iter,
				      uint32_t *type_value);

#ifdef __cplusplus
}
#endif

#endif

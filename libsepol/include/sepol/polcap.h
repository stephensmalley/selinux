#ifndef _SEPOL_POLCAP_H_
#define _SEPOL_POLCAP_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/polcaps.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sepol_polcap_iter sepol_polcap_iter_t;

extern int sepol_polcap_iter_create(sepol_handle_t *handle,
				    const sepol_policydb_t *p,
				    sepol_polcap_iter_t **iter);

extern void sepol_polcap_iter_destroy(sepol_polcap_iter_t *iter);

/* On each successful call with iteration remaining, *cap_num is set to
 * a 0-based policy capability number, as defined by the
 * POLICYDB_CAP_* enum in <sepol/policydb/polcaps.h> and accepted by
 * sepol_polcap_getname()/sepol_polcap_getnum() -- unlike
 * sepol_permissive_iter_next()'s 1-based type_value, 0 is a valid
 * capability number here. Iteration is exhausted once *cap_name is
 * set to NULL. */
extern int sepol_polcap_iter_next(sepol_handle_t *handle,
				  sepol_polcap_iter_t *iter, uint32_t *cap_num,
				  const char **cap_name);

/*
 * sepol_polcap_getnum()/sepol_polcap_getname() are declared by
 * <sepol/policydb/polcaps.h>, included above.
 */

#ifdef __cplusplus
}
#endif

#endif

#ifndef _SEPOL_RANGE_TRANS_H_
#define _SEPOL_RANGE_TRANS_H_

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

typedef struct sepol_range_trans_iter sepol_range_trans_iter_t;

/*
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal symbol table) and may change between library versions or
 * policydb loads; callers must not rely on it matching declaration order
 * or being stable across calls.
 */
extern int sepol_range_trans_iter_create(sepol_handle_t *handle,
					 const sepol_policydb_t *p,
					 sepol_range_trans_iter_t **iter);

extern void sepol_range_trans_iter_destroy(sepol_range_trans_iter_t *iter);

extern int sepol_range_trans_iter_next(sepol_handle_t *handle,
				       sepol_range_trans_iter_t *iter,
				       uint32_t *source_type,
				       uint32_t *target_type,
				       uint32_t *target_class);

extern uint32_t
sepol_range_trans_iter_get_low_sens(const sepol_range_trans_iter_t *iter);
extern uint32_t
sepol_range_trans_iter_get_high_sens(const sepol_range_trans_iter_t *iter);
extern int
sepol_range_trans_iter_get_low_cat(const sepol_range_trans_iter_t *iter,
				   sepol_cat_set_iter_t **cat_iter);
extern int
sepol_range_trans_iter_get_high_cat(const sepol_range_trans_iter_t *iter,
				    sepol_cat_set_iter_t **cat_iter);

#ifdef __cplusplus
}
#endif

#endif

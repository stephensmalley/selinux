#ifndef _SEPOL_FILENAME_TRANS_H_
#define _SEPOL_FILENAME_TRANS_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_filename_trans_iter;
typedef struct sepol_filename_trans_iter sepol_filename_trans_iter_t;

/*
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal symbol table) and may change between library versions or
 * policydb loads; callers must not rely on it matching declaration order
 * or being stable across calls.
 */
extern int sepol_filename_trans_iter_create(sepol_handle_t *handle,
					    const sepol_policydb_t *p,
					    sepol_filename_trans_iter_t **iter);

extern void
sepol_filename_trans_iter_destroy(sepol_filename_trans_iter_t *iter);

/*
 * Advance to the next flattened filename transition rule.
 * Sets *source_type to 0 when done.
 * All type/class values are 1-based.
 */
extern int sepol_filename_trans_iter_next(
	sepol_handle_t *handle, sepol_filename_trans_iter_t *iter,
	uint32_t *source_type, uint32_t *target_type, uint32_t *target_class,
	const char **filename, uint32_t *default_type);

#ifdef __cplusplus
}
#endif

#endif

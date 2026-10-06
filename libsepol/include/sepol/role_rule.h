#ifndef _SEPOL_ROLE_RULE_H_
#define _SEPOL_ROLE_RULE_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sepol_role_allow_iter sepol_role_allow_iter_t;

extern int sepol_role_allow_iter_create(sepol_handle_t *handle,
					const sepol_policydb_t *p,
					sepol_role_allow_iter_t **iter);

extern void sepol_role_allow_iter_destroy(sepol_role_allow_iter_t *iter);

extern int sepol_role_allow_iter_next(sepol_handle_t *handle,
				      sepol_role_allow_iter_t *iter,
				      uint32_t *role, uint32_t *new_role);

typedef struct sepol_role_trans_iter sepol_role_trans_iter_t;

extern int sepol_role_trans_iter_create(sepol_handle_t *handle,
					const sepol_policydb_t *p,
					sepol_role_trans_iter_t **iter);

extern void sepol_role_trans_iter_destroy(sepol_role_trans_iter_t *iter);

extern int sepol_role_trans_iter_next(sepol_handle_t *handle,
				      sepol_role_trans_iter_t *iter,
				      uint32_t *role, uint32_t *type,
				      uint32_t *tclass, uint32_t *new_role);

#ifdef __cplusplus
}
#endif

#endif

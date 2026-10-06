#include <sepol/role_rule.h>

#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"

struct sepol_role_allow_iter {
	const role_allow_t *cur;
};

int sepol_role_allow_iter_create(sepol_handle_t *handle,
				 const sepol_policydb_t *p,
				 sepol_role_allow_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_role_allow_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.role_allow;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_role_allow_iter_destroy(sepol_role_allow_iter_t *iter)
{
	free(iter);
}

int sepol_role_allow_iter_next(sepol_handle_t *handle __attribute__((unused)),
			       sepol_role_allow_iter_t *iter, uint32_t *role,
			       uint32_t *new_role)
{
	if (!iter || !role || !new_role)
		return STATUS_ERR;

	if (!iter->cur) {
		*role = 0;
		*new_role = 0;
		return STATUS_SUCCESS;
	}

	*role = iter->cur->role;
	*new_role = iter->cur->new_role;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

struct sepol_role_trans_iter {
	const role_trans_t *cur;
};

int sepol_role_trans_iter_create(sepol_handle_t *handle,
				 const sepol_policydb_t *p,
				 sepol_role_trans_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_role_trans_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.role_tr;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_role_trans_iter_destroy(sepol_role_trans_iter_t *iter)
{
	free(iter);
}

int sepol_role_trans_iter_next(sepol_handle_t *handle __attribute__((unused)),
			       sepol_role_trans_iter_t *iter, uint32_t *role,
			       uint32_t *type, uint32_t *tclass,
			       uint32_t *new_role)
{
	if (!iter || !role || !type || !tclass || !new_role)
		return STATUS_ERR;

	if (!iter->cur) {
		*role = 0;
		*type = 0;
		*tclass = 0;
		*new_role = 0;
		return STATUS_SUCCESS;
	}

	*role = iter->cur->role;
	*type = iter->cur->type;
	*tclass = iter->cur->tclass;
	*new_role = iter->cur->new_role;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

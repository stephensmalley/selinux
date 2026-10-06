#include <sepol/common_perm.h>

#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"
#include "private.h"

struct sepol_common_iter {
	hashtab_iter_t ht_iter;
};

int sepol_common_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			     sepol_common_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_common_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(p->p.p_commons.table, &tmp->ht_iter);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_common_iter_destroy(sepol_common_iter_t *iter)
{
	free(iter);
}

int sepol_common_iter_next(sepol_handle_t *handle __attribute__((unused)),
			   sepol_common_iter_t *iter, const char **name,
			   uint32_t *value)
{
	if (!iter || !name || !value)
		return STATUS_ERR;

	hashtab_key_t hkey;
	hashtab_datum_t hdatum;

	hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
	if (!hkey) {
		*name = NULL;
		*value = 0;
		return STATUS_SUCCESS;
	}

	common_datum_t *d = (common_datum_t *)hdatum;

	*name = hkey;
	*value = d->s.value;

	return STATUS_SUCCESS;
}

struct sepol_common_perm_iter {
	hashtab_iter_t ht_iter;
};

int sepol_common_perm_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  uint32_t common_value,
				  sepol_common_perm_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (common_value == 0 || common_value > p->p.p_commons.nprim) {
		ERR(handle, "invalid common value %u", common_value);
		*iter = NULL;
		return STATUS_ERR;
	}

	const char *name = p->p.p_common_val_to_name[common_value - 1];
	if (!name) {
		ERR(handle, "no name for common value %u", common_value);
		*iter = NULL;
		return STATUS_ERR;
	}

	common_datum_t *d = hashtab_search(p->p.p_commons.table, name);
	if (!d) {
		ERR(handle, "common %s not found", name);
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_common_perm_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(d->permissions.table, &tmp->ht_iter);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_common_perm_iter_destroy(sepol_common_perm_iter_t *iter)
{
	free(iter);
}

int sepol_common_perm_iter_next(sepol_handle_t *handle __attribute__((unused)),
				sepol_common_perm_iter_t *iter,
				const char **perm_name)
{
	if (!iter || !perm_name)
		return STATUS_ERR;

	hashtab_key_t hkey;
	hashtab_datum_t hdatum;

	hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
	if (!hkey) {
		*perm_name = NULL;
		return STATUS_SUCCESS;
	}

	*perm_name = hkey;

	return STATUS_SUCCESS;
}

DEFINE_VALUE_TO_NAME(sepol_common_value_to_name, "common", p_commons,
		     p_common_val_to_name)

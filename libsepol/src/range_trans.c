#include <sepol/range_trans.h>

#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/mls_types.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "cat_set_internal.h"
#include "debug.h"

struct sepol_range_trans_iter {
	hashtab_iter_t ht_iter;
	const range_trans_t *last_key;
	const mls_range_t *last_range;
};

int sepol_range_trans_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_range_trans_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_range_trans_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(p->p.range_tr, &tmp->ht_iter);
	tmp->last_key = NULL;
	tmp->last_range = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_range_trans_iter_destroy(sepol_range_trans_iter_t *iter)
{
	free(iter);
}

int sepol_range_trans_iter_next(sepol_handle_t *handle __attribute__((unused)),
				sepol_range_trans_iter_t *iter,
				uint32_t *source_type, uint32_t *target_type,
				uint32_t *target_class)
{
	if (!iter || !source_type || !target_type || !target_class)
		return STATUS_ERR;

	hashtab_key_t hkey;
	hashtab_datum_t hdatum;

	hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
	if (!hkey) {
		*source_type = 0;
		*target_type = 0;
		*target_class = 0;
		iter->last_key = NULL;
		iter->last_range = NULL;
		return STATUS_SUCCESS;
	}

	iter->last_key = (const range_trans_t *)hkey;
	iter->last_range = (const mls_range_t *)hdatum;

	*source_type = iter->last_key->source_type;
	*target_type = iter->last_key->target_type;
	*target_class = iter->last_key->target_class;

	return STATUS_SUCCESS;
}

uint32_t
sepol_range_trans_iter_get_low_sens(const sepol_range_trans_iter_t *iter)
{
	if (!iter || !iter->last_range)
		return 0;
	return iter->last_range->level[0].sens;
}

uint32_t
sepol_range_trans_iter_get_high_sens(const sepol_range_trans_iter_t *iter)
{
	if (!iter || !iter->last_range)
		return 0;
	return iter->last_range->level[1].sens;
}

int sepol_range_trans_iter_get_low_cat(const sepol_range_trans_iter_t *iter,
				       sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;
	if (!iter || !iter->last_range) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&iter->last_range->level[0].cat,
						cat_iter);
}

int sepol_range_trans_iter_get_high_cat(const sepol_range_trans_iter_t *iter,
					sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;
	if (!iter || !iter->last_range) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&iter->last_range->level[1].cat,
						cat_iter);
}

#include <sepol/mls_iter.h>

#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "cat_set_internal.h"
#include "debug.h"
#include "private.h"

/* ---- Category iterator ---- */

struct sepol_cat_iter {
	hashtab_iter_t ht_iter;
};

int sepol_cat_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			  sepol_cat_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_cat_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(p->p.p_cats.table, &tmp->ht_iter);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_cat_iter_destroy(sepol_cat_iter_t *iter)
{
	free(iter);
}

int sepol_cat_iter_next(sepol_handle_t *handle __attribute__((unused)),
			sepol_cat_iter_t *iter, const char **name,
			uint32_t *value, int *isalias)
{
	if (!iter || !name || !value || !isalias)
		return STATUS_ERR;

	hashtab_key_t hkey;
	hashtab_datum_t hdatum;

	hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
	if (!hkey) {
		*name = NULL;
		*value = 0;
		*isalias = 0;
		return STATUS_SUCCESS;
	}

	cat_datum_t *d = (cat_datum_t *)hdatum;
	*name = hkey;
	*value = d->s.value;
	*isalias = d->isalias;

	return STATUS_SUCCESS;
}

/* ---- Sensitivity iterator ---- */

struct sepol_sens_iter {
	hashtab_iter_t ht_iter;
	const level_datum_t *last;
};

int sepol_sens_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_sens_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_sens_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(p->p.p_levels.table, &tmp->ht_iter);
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_sens_iter_destroy(sepol_sens_iter_t *iter)
{
	free(iter);
}

int sepol_sens_iter_next(sepol_handle_t *handle __attribute__((unused)),
			 sepol_sens_iter_t *iter, const char **name,
			 uint32_t *sens_value, int *isalias)
{
	if (!iter || !name || !sens_value || !isalias)
		return STATUS_ERR;

	hashtab_key_t hkey;
	hashtab_datum_t hdatum;

	hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
	if (!hkey) {
		*name = NULL;
		*sens_value = 0;
		*isalias = 0;
		iter->last = NULL;
		return STATUS_SUCCESS;
	}

	level_datum_t *d = (level_datum_t *)hdatum;
	iter->last = d;
	*name = hkey;
	*sens_value = d->level->sens;
	*isalias = d->isalias;

	return STATUS_SUCCESS;
}

int sepol_sens_iter_get_level_cat(sepol_handle_t *handle
				  __attribute__((unused)),
				  const sepol_sens_iter_t *iter,
				  sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;
	if (!iter || !iter->last) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&iter->last->level->cat,
						cat_iter);
}

DEFINE_VALUE_TO_NAME(sepol_cat_value_to_name, "category", p_cats,
		     p_cat_val_to_name)

DEFINE_VALUE_TO_NAME(sepol_sens_value_to_name, "sensitivity", p_levels,
		     p_sens_val_to_name)

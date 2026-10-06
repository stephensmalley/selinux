#include <sepol/filename_trans.h>

#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"

struct sepol_filename_trans_iter {
	hashtab_iter_t ht_iter;
	const filename_trans_key_t *cur_key;
	const filename_trans_datum_t *cur_datum;
	ebitmap_node_t *stype_node;
	uint32_t stype_bit;
	uint32_t stype_highbit;
};

static void init_ebitmap_walk(sepol_filename_trans_iter_t *iter,
			      const ebitmap_t *e)
{
	iter->stype_bit = ebitmap_start(e, &iter->stype_node);
	iter->stype_highbit = ebitmap_length(e);
}

static void advance(sepol_filename_trans_iter_t *iter)
{
	for (;;) {
		if (iter->cur_datum &&
		    ebitmap_find_next_set_bit(&iter->stype_node,
					      &iter->stype_bit,
					      iter->stype_highbit))
			return;

		if (iter->cur_datum && iter->cur_datum->next) {
			iter->cur_datum = iter->cur_datum->next;
			init_ebitmap_walk(iter, &iter->cur_datum->stypes);
			continue;
		}

		hashtab_key_t hkey;
		hashtab_datum_t hdatum;
		hashtab_iter_next(&iter->ht_iter, &hkey, &hdatum);
		if (!hkey) {
			iter->cur_key = NULL;
			iter->cur_datum = NULL;
			return;
		}

		iter->cur_key = (const filename_trans_key_t *)hkey;
		iter->cur_datum = (const filename_trans_datum_t *)hdatum;
		init_ebitmap_walk(iter, &iter->cur_datum->stypes);
	}
}

int sepol_filename_trans_iter_create(sepol_handle_t *handle,
				     const sepol_policydb_t *p,
				     sepol_filename_trans_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_filename_trans_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_init(p->p.filename_trans, &tmp->ht_iter);
	tmp->cur_key = NULL;
	tmp->cur_datum = NULL;
	tmp->stype_node = NULL;
	tmp->stype_bit = 0;
	tmp->stype_highbit = 0;

	advance(tmp);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_filename_trans_iter_destroy(sepol_filename_trans_iter_t *iter)
{
	free(iter);
}

int sepol_filename_trans_iter_next(sepol_handle_t *handle
				   __attribute__((unused)),
				   sepol_filename_trans_iter_t *iter,
				   uint32_t *source_type, uint32_t *target_type,
				   uint32_t *target_class,
				   const char **filename,
				   uint32_t *default_type)
{
	if (!iter || !source_type || !target_type || !target_class ||
	    !filename || !default_type)
		return STATUS_ERR;

	if (!iter->cur_key) {
		*source_type = 0;
		*target_type = 0;
		*target_class = 0;
		*filename = NULL;
		*default_type = 0;
		return STATUS_SUCCESS;
	}

	*source_type = iter->stype_bit + 1;
	*target_type = iter->cur_key->ttype;
	*target_class = iter->cur_key->tclass;
	*filename = iter->cur_key->name;
	*default_type = iter->cur_datum->otype;

	iter->stype_bit = ebitmap_next(&iter->stype_node, iter->stype_bit);
	advance(iter);

	return STATUS_SUCCESS;
}

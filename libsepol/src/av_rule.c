#include <sepol/av_rule.h>
#include <sepol/constants.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include <string.h>

#include "av_rule_internal.h"
#include "debug.h"

/* --- Avtab iterator --- */

struct sepol_avtab_iter {
	const sepol_policydb_t *p;
	const avtab_t *avtab;
	uint32_t bucket;
	avtab_ptr_t node;
	uint32_t specified_filter;
	const avtab_datum_t *last_datum;
	uint16_t last_specified;
};

static void avtab_iter_advance(sepol_avtab_iter_t *iter)
{
	while (iter->bucket < iter->avtab->nslot) {
		while (iter->node) {
			uint16_t spec = iter->node->key.specified;
			if (!iter->specified_filter ||
			    (spec & iter->specified_filter))
				return;
			iter->node = iter->node->next;
		}
		iter->bucket++;
		if (iter->bucket < iter->avtab->nslot)
			iter->node = iter->avtab->htable[iter->bucket];
	}
}

int sepol_avtab_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			    uint32_t specified, sepol_avtab_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_avtab_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->p = p;
	tmp->avtab = &p->p.te_avtab;
	tmp->specified_filter = specified;
	tmp->bucket = 0;
	tmp->node = tmp->avtab->nslot > 0 ? tmp->avtab->htable[0] : NULL;
	tmp->last_datum = NULL;
	tmp->last_specified = 0;

	avtab_iter_advance(tmp);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_avtab_iter_destroy(sepol_avtab_iter_t *iter)
{
	free(iter);
}

int sepol_avtab_iter_next(sepol_handle_t *handle __attribute__((unused)),
			  sepol_avtab_iter_t *iter, uint32_t *ruletype,
			  uint32_t *source_type, uint32_t *target_type,
			  uint32_t *target_class)
{
	if (!iter || !ruletype || !source_type || !target_type || !target_class)
		return STATUS_ERR;

	if (iter->bucket >= iter->avtab->nslot || !iter->node) {
		iter->last_datum = NULL;
		iter->last_specified = 0;
		*ruletype = 0;
		*source_type = 0;
		*target_type = 0;
		*target_class = 0;
		return STATUS_SUCCESS;
	}

	avtab_key_t *key = &iter->node->key;
	iter->last_datum = &iter->node->datum;
	iter->last_specified = key->specified;

	*ruletype = key->specified & ~AVTAB_ENABLED;
	*source_type = key->source_type;
	*target_type = key->target_type;
	*target_class = key->target_class;

	iter->node = iter->node->next;
	avtab_iter_advance(iter);

	return STATUS_SUCCESS;
}

uint32_t sepol_avtab_iter_get_av_data(const sepol_avtab_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_av_data(iter->last_datum, iter->last_specified);
}

uint32_t sepol_avtab_iter_get_type_data(const sepol_avtab_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_type_data(iter->last_datum);
}

uint8_t sepol_avtab_iter_get_xperm_type(const sepol_avtab_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_xperm_type(iter->last_datum);
}

uint8_t sepol_avtab_iter_get_xperm_driver(const sepol_avtab_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_xperm_driver(iter->last_datum);
}

/* --- Permission name sub-iterator --- */

struct sepol_perm_iter {
	const policydb_t *p;
	uint32_t target_class;
	uint32_t perm_data;
	uint32_t current_bit;
};

int sepol_perm_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   uint32_t target_class, uint32_t perm_data,
			   sepol_perm_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (target_class < 1 || target_class > p->p.p_classes.nprim) {
		ERR(handle, "invalid class value %u", target_class);
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_perm_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->p = &p->p;
	tmp->target_class = target_class;
	tmp->perm_data = perm_data;
	tmp->current_bit = 0;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_perm_iter_destroy(sepol_perm_iter_t *iter)
{
	free(iter);
}

struct perm_search_data {
	uint32_t val;
	const char *name;
};

static int find_perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	struct perm_search_data *d = data;
	perm_datum_t *perm = datum;
	if (perm->s.value == d->val) {
		d->name = key;
		return 1;
	}
	return 0;
}

int sepol_perm_iter_next(sepol_handle_t *handle __attribute__((unused)),
			 sepol_perm_iter_t *iter, const char **perm_name)
{
	if (!iter || !perm_name)
		return STATUS_ERR;

	const class_datum_t *cladatum =
		iter->p->class_val_to_struct[iter->target_class - 1];
	if (!cladatum) {
		*perm_name = NULL;
		return STATUS_SUCCESS;
	}

	while (iter->current_bit < cladatum->permissions.nprim &&
	       iter->current_bit < sizeof(iter->perm_data) * 8) {
		uint32_t bit = iter->current_bit++;
		if (!(iter->perm_data & (UINT32_C(1) << bit)))
			continue;

		struct perm_search_data d = { .val = bit + 1, .name = NULL };
		int rc = hashtab_map(cladatum->permissions.table,
				     find_perm_name, &d);
		if (!rc && cladatum->comdatum) {
			rc = hashtab_map(cladatum->comdatum->permissions.table,
					 find_perm_name, &d);
		}
		if (rc == 1 && d.name) {
			*perm_name = d.name;
			return STATUS_SUCCESS;
		}
	}

	*perm_name = NULL;
	return STATUS_SUCCESS;
}

/* --- Xperm value sub-iterator (struct in av_rule_internal.h) --- */

int sepol_xperm_iter_create_from_datum(sepol_handle_t *handle,
				       const avtab_extended_perms_t *xperms,
				       sepol_xperm_iter_t **xperm_iter)
{
	if (!xperm_iter)
		return STATUS_ERR;
	if (!xperms) {
		*xperm_iter = NULL;
		return STATUS_ERR;
	}

	sepol_xperm_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*xperm_iter = NULL;
		return STATUS_ERR;
	}
	memcpy(tmp->perms, xperms->perms, sizeof(tmp->perms));
	tmp->current_bit = 0;

	*xperm_iter = tmp;
	return STATUS_SUCCESS;
}

int sepol_xperm_iter_create(sepol_handle_t *handle,
			    const sepol_avtab_iter_t *iter,
			    sepol_xperm_iter_t **xperm_iter)
{
	if (!xperm_iter)
		return STATUS_ERR;
	if (!iter) {
		*xperm_iter = NULL;
		return STATUS_ERR;
	}

	if (!iter->last_datum || !iter->last_datum->xperms) {
		ERR(handle, "no xperms data on current avtab entry");
		*xperm_iter = NULL;
		return STATUS_ERR;
	}

	return sepol_xperm_iter_create_from_datum(
		handle, iter->last_datum->xperms, xperm_iter);
}

void sepol_xperm_iter_destroy(sepol_xperm_iter_t *xperm_iter)
{
	free(xperm_iter);
}

int sepol_xperm_iter_next(sepol_handle_t *handle __attribute__((unused)),
			  sepol_xperm_iter_t *xperm_iter, uint16_t *value,
			  int *has_next)
{
	if (!xperm_iter || !value || !has_next)
		return STATUS_ERR;

	while (xperm_iter->current_bit < 256) {
		uint16_t bit = xperm_iter->current_bit++;
		if (xperm_test(bit, xperm_iter->perms)) {
			*value = bit;
			*has_next = 1;
			return STATUS_SUCCESS;
		}
	}
	*value = 0;
	*has_next = 0;
	return STATUS_SUCCESS;
}

char *sepol_policydb_av_to_string(const sepol_policydb_t *policydb,
				  uint32_t class_val, uint32_t av)
{
	if (!policydb)
		return NULL;
	return sepol_av_to_string(&policydb->p, class_val, av);
}

char *sepol_policydb_extended_perms_to_string(uint8_t specified, uint8_t driver,
					      const uint32_t perms[8])
{
	avtab_extended_perms_t xperms;

	if (!perms)
		return NULL;

	memset(&xperms, 0, sizeof(xperms));
	xperms.specified = specified;
	xperms.driver = driver;
	memcpy(xperms.perms, perms, sizeof(xperms.perms));
	return sepol_extended_perms_to_string(&xperms);
}

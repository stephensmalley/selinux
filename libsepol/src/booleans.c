#include <string.h>
#include <stdlib.h>

#include "handle.h"
#include "private.h"
#include "debug.h"

#include <sepol/booleans.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include "boolean_internal.h"

static int bool_update(sepol_handle_t *handle, policydb_t *policydb,
		       const sepol_bool_key_t *key, const sepol_bool_t *data)
{
	const char *cname;
	char *name;
	int value;
	cond_bool_datum_t *datum;

	sepol_bool_key_unpack(key, &cname);
	if (!cname) {
		ERR(handle, "boolean key name is NULL");
		return STATUS_ERR;
	}
	name = strdup(cname);
	value = sepol_bool_get_value(data);

	if (!name)
		goto omem;

	datum = hashtab_search(policydb->p_bools.table, name);
	if (!datum) {
		ERR(handle, "boolean %s no longer in policy", name);
		goto err;
	}
	if (value != 0 && value != 1) {
		ERR(handle, "illegal value %d for boolean %s", value, name);
		goto err;
	}

	free(name);
	datum->state = value;
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");

err:
	free(name);
	ERR(handle, "could not update boolean %s", cname);
	return STATUS_ERR;
}

static int bool_to_record(sepol_handle_t *handle, const policydb_t *policydb,
			  int bool_idx, sepol_bool_t **record)
{
	const char *name = NULL;
	cond_bool_datum_t *booldatum;
	int value;
	sepol_bool_t *tmp_record = NULL;

	if ((unsigned)bool_idx >= policydb->p_bools.nprim)
		goto err;
	name = policydb->p_bool_val_to_name[bool_idx];
	booldatum = policydb->bool_val_to_struct[bool_idx];
	if (!booldatum)
		goto err;
	value = booldatum->state;

	if (sepol_bool_create(handle, &tmp_record) < 0)
		goto err;

	if (sepol_bool_set_name(handle, tmp_record, name) < 0)
		goto err;

	sepol_bool_set_value(tmp_record, value);

	*record = tmp_record;
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not convert boolean %s to record",
	    name ? name : "(unknown)");
	sepol_bool_free(tmp_record);
	*record = NULL;
	return STATUS_ERR;
}

int sepol_bool_set(sepol_handle_t *handle, sepol_policydb_t *p,
		   const sepol_bool_key_t *key, const sepol_bool_t *data)
{
	policydb_t *policydb;
	const char *name;

	if (!handle || !p || !key || !data)
		return STATUS_ERR;

	policydb = &p->p;
	sepol_bool_key_unpack(key, &name);

	if (bool_update(handle, policydb, key, data) < 0)
		goto err;

	if (evaluate_conds(policydb) < 0) {
		ERR(handle, "error while re-evaluating conditionals");
		goto err;
	}

	return STATUS_SUCCESS;

err:
	ERR(handle, "could not set boolean %s", name);
	return STATUS_ERR;
}

int sepol_bool_count(sepol_handle_t *handle __attribute__((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	const policydb_t *policydb = &p->p;
	*response = policydb->p_bools.table->nel;

	return STATUS_SUCCESS;
}

int sepol_bool_exists(sepol_handle_t *handle __attribute__((unused)),
		      const sepol_policydb_t *p, const sepol_bool_key_t *key,
		      int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	const policydb_t *policydb = &p->p;

	const char *cname;
	sepol_bool_key_unpack(key, &cname);

	*response = cname &&
		    (hashtab_search(policydb->p_bools.table, cname) != NULL);
	return STATUS_SUCCESS;
}

int sepol_bool_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_bool_key_t *key, sepol_bool_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	const policydb_t *policydb = &p->p;
	cond_bool_datum_t *booldatum = NULL;

	const char *cname;
	sepol_bool_key_unpack(key, &cname);

	if (!cname) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	booldatum = hashtab_search(policydb->p_bools.table, cname);
	if (!booldatum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	if (bool_to_record(handle, policydb, booldatum->s.value - 1, response) <
	    0)
		goto err;

	return STATUS_SUCCESS;

err:
	ERR(handle, "could not query boolean %s", cname);
	return STATUS_ERR;
}

int sepol_bool_iterate(sepol_handle_t *handle, const sepol_policydb_t *p,
		       int (*fn)(const sepol_bool_t *boolean, void *fn_arg),
		       void *arg)
{
	if (!p || !fn) {
		ERR(handle, "policydb or callback is NULL");
		return STATUS_ERR;
	}

	const policydb_t *policydb = &p->p;
	unsigned int nbools = policydb->p_bools.nprim;
	sepol_bool_t *boolean = NULL;
	unsigned int i;

	/* For each boolean */
	for (i = 0; i < nbools; i++) {
		int status;

		if (bool_to_record(handle, policydb, i, &boolean) < 0)
			goto err;

		/* Invoke handler */
		status = fn(boolean, arg);
		if (status < 0)
			goto err;

		sepol_bool_free(boolean);
		boolean = NULL;

		/* Handler requested exit */
		if (status > 0)
			break;
	}

	return STATUS_SUCCESS;

err:
	ERR(handle, "could not iterate over booleans");
	sepol_bool_free(boolean);
	return STATUS_ERR;
}

DEFINE_VALUE_TO_NAME(sepol_bool_value_to_name, "boolean", p_bools,
		     p_bool_val_to_name)

int sepol_bool_query_by_value(sepol_handle_t *handle, const sepol_policydb_t *p,
			      uint32_t value, sepol_bool_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	if (value < 1 || value > p->p.p_bools.nprim) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	if (!p->p.bool_val_to_struct[value - 1]) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return bool_to_record(handle, &p->p, value - 1, response);
}

/* ---- Boolean iterator ---- */

struct sepol_bool_iter {
	const policydb_t *policydb;
	uint32_t idx;
};

int sepol_bool_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_bool_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_bool_iter_t *new_iter = malloc(sizeof(sepol_bool_iter_t));
	if (!new_iter) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	new_iter->policydb = &p->p;
	new_iter->idx = 0;

	*iter = new_iter;
	return STATUS_SUCCESS;
}

void sepol_bool_iter_destroy(sepol_bool_iter_t *iter)
{
	free(iter);
}

int sepol_bool_iter_next(sepol_handle_t *handle, sepol_bool_iter_t *iter,
			 sepol_bool_t **item)
{
	if (!item)
		return STATUS_ERR;
	if (!iter) {
		*item = NULL;
		return STATUS_ERR;
	}

	while (iter->idx < iter->policydb->p_bools.nprim) {
		unsigned int idx = iter->idx;
		cond_bool_datum_t *datum =
			iter->policydb->bool_val_to_struct[idx];
		iter->idx++;
		if (datum) {
			int status = bool_to_record(handle, iter->policydb, idx,
						    item);
			if (status)
				return status;
			return STATUS_SUCCESS;
		}
	}

	*item = NULL;
	return STATUS_SUCCESS;
}

#include <sepol/roles.h>

#include <sepol/policydb/expand.h>
#include <sepol/policydb/policydb.h>

#include "debug.h"
#include "private.h"

struct sepol_role_iter {
	const policydb_t *policydb;
	uint32_t idx;
};

static int role_datum_to_record(sepol_handle_t *handle,
				const policydb_t *policydb,
				const role_datum_t *role_datum,
				sepol_role_t **record)
{
	sepol_role_t *new_role = NULL;

	if (role_datum->s.value == 0 ||
	    role_datum->s.value > policydb->p_roles.nprim) {
		*record = NULL;
		return STATUS_ERR;
	}

	if (sepol_role_create(handle, &new_role))
		goto err;

	if (sepol_role_set_name(
		    handle, new_role,
		    policydb->p_role_val_to_name[role_datum->s.value - 1]))
		goto err;

	/*
	 * role_datum->types is a type_set_t: its .types ebitmap alone is
	 * only the *positive* member list as written in policy source and
	 * is incomplete whenever the role's type set uses "*"/"~" wildcards
	 * or attribute negation (role_datum->types.flags / .negset). Expand
	 * it the same way the rest of libsepol does (see policydb_role_cache()
	 * populating role_datum->cache) to get the actual, fully resolved
	 * type membership rather than silently reporting a partial set.
	 */
	ebitmap_t expanded_types;
	if (type_set_expand((type_set_t *)&role_datum->types, &expanded_types,
			    (policydb_t *)policydb, 1)) {
		/*
		 * type_set_expand() always ebitmap_init()s expanded_types
		 * before it can fail, and may have partially populated it
		 * before hitting the failure (e.g. OOM partway through a
		 * negated/attribute type set); destroy it here rather than
		 * leaking those ebitmap nodes.
		 */
		ebitmap_destroy(&expanded_types);
		goto err;
	}

	ebitmap_node_t *enode;
	uint32_t bit;
	ebitmap_for_each_positive_bit(&expanded_types, enode, bit) {
		if (bit >= policydb->p_types.nprim) {
			ebitmap_destroy(&expanded_types);
			goto err;
		}
		if (sepol_role_add_type(handle, new_role,
					policydb->p_type_val_to_name[bit])) {
			ebitmap_destroy(&expanded_types);
			goto err;
		}
	}
	ebitmap_destroy(&expanded_types);

	if (role_datum->bounds &&
	    (role_datum->bounds > policydb->p_roles.nprim ||
	     sepol_role_set_bounds(
		     handle, new_role,
		     policydb->p_role_val_to_name[role_datum->bounds - 1])))
		goto err;

	switch (role_datum->flavor) {
	case ROLE_ROLE:
		if (sepol_role_set_flavor(handle, new_role, SEPOL_ROLE_ROLE))
			goto err;
		break;
	case ROLE_ATTRIB:
		if (sepol_role_set_flavor(handle, new_role, SEPOL_ROLE_ATTRIB))
			goto err;
		break;
	default:
		/*
		 * role_datum->flavor is read straight from the binary
		 * policy (policydb_read()) without being validated against
		 * this enum, so a corrupt/crafted policy could carry an
		 * out-of-range value here. Reject it explicitly instead of
		 * silently reporting the zero-initialized ROLE_ROLE default
		 * from sepol_role_create(), which would misrepresent the
		 * actual on-disk data to API callers.
		 */
		goto err;
	}

	ebitmap_for_each_positive_bit(&role_datum->roles, enode, bit) {
		if (bit >= policydb->p_roles.nprim)
			goto err;
		if (sepol_role_add_subrole(handle, new_role,
					   policydb->p_role_val_to_name[bit]))
			goto err;
	}

	*record = new_role;
	return STATUS_SUCCESS;

err:
	*record = NULL;
	sepol_role_free(new_role);
	return STATUS_ERR;
}

DEFINE_VALUE_TO_NAME(sepol_role_value_to_name, "role", p_roles,
		     p_role_val_to_name)

int sepol_role_query_by_value(sepol_handle_t *handle, const sepol_policydb_t *p,
			      uint32_t value, sepol_role_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	if (value < 1 || value > p->p.p_roles.nprim) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	role_datum_t *role_datum = p->p.role_val_to_struct[value - 1];
	if (!role_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return role_datum_to_record(handle, &p->p, role_datum, response);
}

int sepol_role_count(sepol_handle_t *handle __attribute__((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	*response = p->p.p_roles.table->nel;
	return STATUS_SUCCESS;
}

int sepol_role_exists(sepol_handle_t *handle __attribute__((unused)),
		      const sepol_policydb_t *p, const sepol_role_key_t *key,
		      int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	const char *name;
	sepol_role_key_unpack(key, &name);

	*response = name && (hashtab_search(p->p.p_roles.table, name) != NULL);

	return STATUS_SUCCESS;
}

int sepol_role_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_role_key_t *key, sepol_role_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	const char *name;
	sepol_role_key_unpack(key, &name);

	if (!name) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	role_datum_t *role_datum = hashtab_search(p->p.p_roles.table, name);
	if (!role_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return role_datum_to_record(handle, &p->p, role_datum, response);
}

int sepol_role_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_role_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		ERR(handle, "invalid argument to sepol_role_iter_create");
		*iter = NULL;
		return STATUS_ERR;
	}
	sepol_role_iter_t *tmp = malloc(sizeof(sepol_role_iter_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->policydb = &p->p;
	tmp->idx = 0;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_role_iter_destroy(sepol_role_iter_t *iter)
{
	free(iter);
}

int sepol_role_iter_next(sepol_handle_t *handle, sepol_role_iter_t *iter,
			 sepol_role_t **item)
{
	if (!item)
		return STATUS_ERR;
	if (!iter) {
		*item = NULL;
		return STATUS_ERR;
	}

	while (iter->idx < iter->policydb->p_roles.nprim) {
		role_datum_t *datum =
			iter->policydb->role_val_to_struct[iter->idx];
		iter->idx++;
		if (datum) {
			sepol_role_t *role;
			int status = role_datum_to_record(
				handle, iter->policydb, datum, &role);
			*item = role;
			if (status)
				return status;
			return STATUS_SUCCESS;
		}
	}

	*item = NULL;
	return STATUS_SUCCESS;
}

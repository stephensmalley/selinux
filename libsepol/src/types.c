#include <sepol/types.h>

#include <sepol/policydb/policydb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "sepol/policydb/ebitmap.h"
#include "sepol/policydb/hashtab.h"
#include "sepol/policydb/util.h"
#include "sepol/type_record.h"
#include "private.h"

struct sepol_type_iter {
	const sepol_policydb_t *p;
	hashtab_iter_t hashtab_iter;
};

static int type_datum_to_record(sepol_handle_t *handle, const policydb_t *p,
				const type_datum_t *type_datum,
				const char *name, sepol_type_t **type)
{
	sepol_type_t *new_type = NULL;

	if (type_datum->s.value == 0 ||
	    type_datum->s.value > p->p_types.nprim) {
		*type = NULL;
		return STATUS_ERR;
	}

	if (sepol_type_create(handle, &new_type))
		goto err;

	/* Copy name */
	if (!name)
		name = p->p_type_val_to_name[type_datum->s.value - 1];
	if (sepol_type_set_name(handle, new_type, name))
		goto err;

	/* Copy flavor */
	switch (type_datum->flavor) {
	case TYPE_TYPE:
		if (!type_datum->primary)
			sepol_type_set_flavor(handle, new_type,
					      SEPOL_TYPE_ALIAS);
		else
			sepol_type_set_flavor(handle, new_type,
					      SEPOL_TYPE_TYPE);
		break;
	case TYPE_ATTRIB:
		sepol_type_set_flavor(handle, new_type, SEPOL_TYPE_ATTRIB);
		break;
	case TYPE_ALIAS:
		sepol_type_set_flavor(handle, new_type, SEPOL_TYPE_ALIAS);
		break;
	default:
		ERR(handle, "unknown type flavor");
		goto err;
	}

	/* Copy types */
	const ebitmap_t *subtypes_bitmap = NULL;
	ebitmap_node_t *node;
	uint32_t bit;
	if (p->policy_type == POLICY_KERN) {
		/*
		 * In kernel policy, attribute type relations are stored in a
		 * global bitmap. These tables are derived/rebuilt after
		 * loading a binary policy (see policydb_read()/
		 * expand_module()) and may be absent -- e.g. for a policydb
		 * freshly created via sepol_policydb_create(), which
		 * defaults to POLICY_KERN but has no maps yet; treat that
		 * as "no membership information available" rather than
		 * dereferencing a NULL array.
		 */
		if (type_datum->flavor == TYPE_ATTRIB) {
			if (p->attr_type_map)
				subtypes_bitmap =
					&p->attr_type_map[type_datum->s.value -
							  1];
		} else {
			if (p->type_attr_map)
				subtypes_bitmap =
					&p->type_attr_map[type_datum->s.value -
							  1];
		}
	} else {
		subtypes_bitmap = &type_datum->types;
	}
	if (subtypes_bitmap) {
		ebitmap_for_each_positive_bit(subtypes_bitmap, node, bit) {
			if (bit >= p->p_types.nprim)
				goto err;
			if (type_datum->s.value != bit + 1 &&
			    sepol_type_add_subtype(handle, new_type,
						   p->p_type_val_to_name[bit]))
				goto err;
		}
	}

	/* Copy flags */
	if ((type_datum->flags & TYPE_FLAGS_PERMISSIVE ||
	     /* Kernel policy stores the permissive flag separately, in
	      * the policydb-wide permissive_map bitmap keyed by type
	      * value, rather than in type_datum->flags. */
	     (p->policy_type == POLICY_KERN &&
	      ebitmap_get_bit(&p->permissive_map, type_datum->s.value))) &&
	    sepol_type_set_flag(handle, new_type, SEPOL_TYPE_FLAGS_PERMISSIVE))
		goto err;
	if (type_datum->flags & TYPE_FLAGS_EXPAND_ATTR_TRUE &&
	    sepol_type_set_flag(handle, new_type,
				SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE))
		goto err;
	if (type_datum->flags & TYPE_FLAGS_EXPAND_ATTR_FALSE &&
	    sepol_type_set_flag(handle, new_type,
				SEPOL_TYPE_FLAGS_EXPAND_ATTR_FALSE))
		goto err;

	/* Copy alias' primary name */
	if (!type_datum->primary && type_datum->flavor == TYPE_TYPE) {
		if (sepol_type_set_alias_of(
			    handle, new_type,
			    p->p_type_val_to_name[type_datum->s.value - 1]))
			goto err;
	} else if (type_datum->flavor == TYPE_ALIAS) {
		if (type_datum->primary < 1 ||
		    type_datum->primary > p->p_types.nprim)
			goto err;
		if (sepol_type_set_alias_of(
			    handle, new_type,
			    p->p_type_val_to_name[type_datum->primary - 1]))
			goto err;
	}

	/* Copy bounds name */
	if (type_datum->bounds &&
	    (type_datum->bounds > p->p_types.nprim ||
	     sepol_type_set_bounds(
		     handle, new_type,
		     p->p_type_val_to_name[type_datum->bounds - 1])))
		goto err;

	*type = new_type;
	return STATUS_SUCCESS;

err:
	*type = NULL;
	if (new_type)
		sepol_type_free(new_type);

	return STATUS_ERR;
}

int sepol_type_modify(sepol_handle_t *handle, sepol_policydb_t *p,
		      const sepol_type_key_t *key, const sepol_type_t *data)
{
	policydb_t *policydb;
	const char *cname;
	const char *alias_of, *bounds_name;
	const char **subtypes = NULL;
	uint32_t num_subtypes = 0;
	uint32_t flavor;
	uint32_t i;
	char *name = NULL;
	type_datum_t *typdatum = NULL;
	type_datum_t *bounds_datum = NULL;
	hashtab_key_t scope_key = NULL;
	scope_datum_t *scope_datum = NULL;
	int new = 0;
	/*
	 * Built up from validated subtype names before touching any
	 * existing type_datum, so a lookup failure never leaves a
	 * previously-valid type wiped out in the live policydb (see
	 * below).
	 */
	ebitmap_t new_types;

	ebitmap_init(&new_types);

	if (!handle || !p || !key || !data)
		return STATUS_ERR;

	policydb = &p->p;

	/*
	 * Kernel-format policydbs represent type<->attribute membership
	 * via the derived attr_type_map/type_attr_map cross-reference
	 * tables rather than type_datum->types (see type_datum_to_record()
	 * below). This function only updates type_datum itself, so it
	 * cannot correctly add or modify attribute membership -- and,
	 * more importantly, cannot safely grow those tables when adding a
	 * brand new type -- on such a policydb; refuse rather than risk
	 * an inconsistent or corrupted policydb.
	 */
	if (policydb->policy_type == POLICY_KERN) {
		ERR(handle,
		    "sepol_type_modify is not supported on a kernel-format "
		    "policydb");
		return STATUS_ERR;
	}

	sepol_type_key_unpack(key, &cname);
	if (!cname)
		return STATUS_ERR;

	flavor = sepol_type_get_flavor(data);
	if (flavor == SEPOL_TYPE_ALIAS) {
		ERR(handle, "sepol_type_modify does not support aliases");
		return STATUS_ERR;
	}

	alias_of = sepol_type_get_alias_of(data);
	if (alias_of) {
		ERR(handle,
		    "sepol_type_modify does not support setting alias-of "
		    "on non-alias type %s",
		    cname);
		return STATUS_ERR;
	}

	bounds_name = sepol_type_get_bounds(data);

	if (sepol_type_get_subtypes(handle, data, &subtypes, &num_subtypes))
		return STATUS_ERR;

	if (flavor != SEPOL_TYPE_ATTRIB && num_subtypes > 0) {
		ERR(handle, "type %s is not an attribute but has member types",
		    cname);
		goto err;
	}

	/*
	 * Resolve all name references before mutating the policydb, so a
	 * lookup failure never leaves a partially constructed entry
	 * behind.
	 */
	if (bounds_name) {
		bounds_datum =
			hashtab_search(policydb->p_types.table, bounds_name);
		if (!bounds_datum) {
			ERR(handle, "undefined bounds type %s for type %s",
			    bounds_name, cname);
			goto err;
		}
	}

	for (i = 0; i < num_subtypes; i++) {
		type_datum_t *subdatum =
			hashtab_search(policydb->p_types.table, subtypes[i]);
		if (!subdatum) {
			ERR(handle, "undefined type %s for attribute %s",
			    subtypes[i], cname);
			goto err;
		}
		if (ebitmap_set_bit(&new_types, subdatum->s.value - 1, 1))
			goto omem;
	}

	/*
	 * All name references are validated and new_types is fully built;
	 * only now do we look up (and possibly destroy/reinitialize) the
	 * target type_datum. The only remaining fallible step below the
	 * comment marker (allocation for a brand new type) leaves
	 * `new_types` untouched, so on OOM a modified *existing* type is
	 * never left blanked out -- it either fully succeeds or the
	 * lookup/destroy never happened.
	 */

	/* See if the type already exists; if so, we will modify it */
	typdatum = hashtab_search(policydb->p_types.table, cname);
	if (typdatum) {
		uint32_t value_cp = typdatum->s.value;
		type_datum_destroy(typdatum);
		type_datum_init(typdatum);
		typdatum->s.value = value_cp;
	} else {
		typdatum = malloc(sizeof(type_datum_t));
		if (!typdatum)
			goto omem;
		type_datum_init(typdatum);
		new = 1;
	}

	/*
	 * This function does not support aliases (rejected above), so the
	 * result is always a genuine primary name rather than one sharing
	 * another type's value.
	 */
	typdatum->primary = 1;
	typdatum->flavor = (flavor == SEPOL_TYPE_ATTRIB) ? TYPE_ATTRIB :
							   TYPE_TYPE;

	if (sepol_type_has_flag(data, SEPOL_TYPE_FLAGS_PERMISSIVE))
		typdatum->flags |= TYPE_FLAGS_PERMISSIVE;
	if (sepol_type_has_flag(data, SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE))
		typdatum->flags |= TYPE_FLAGS_EXPAND_ATTR_TRUE;
	if (sepol_type_has_flag(data, SEPOL_TYPE_FLAGS_EXPAND_ATTR_FALSE))
		typdatum->flags |= TYPE_FLAGS_EXPAND_ATTR_FALSE;

	typdatum->bounds = bounds_datum ? bounds_datum->s.value : 0;

	/* Transfer ownership of the validated subtype bitmap to typdatum */
	typdatum->types = new_types;
	ebitmap_init(&new_types);

	/* If there were no errors, and this is a new type, add it to the policy */
	if (new) {
		void *tmp_ptr;

		if (policydb->p_types.nprim == UINT32_MAX) {
			ERR(handle, "too many types");
			goto err;
		}

		/*
		 * Prepare (but do not yet insert) a scope_datum for the new
		 * type up front, alongside the rest of this function's
		 * "resolve everything fallible before committing" style.
		 * Mirrors symtab_insert()'s scope bookkeeping (policydb.c):
		 * without a scope_datum, is_id_enabled() (avrule_block.c)
		 * treats a type as "not declared", so it would otherwise be
		 * silently dropped by any later expand_module()/
		 * link_modules() call even though it is fully present in
		 * p_types/type_val_to_struct. A type added through this
		 * public API is always an unconditional, top-level
		 * declaration -- there is no avrule-block/conditional
		 * context here -- which is exactly decl_id 1, the id
		 * checkpolicy assigns to the first declaration of a
		 * policy's global avrule block (see module_compiler.c's
		 * init_decl_stack()).
		 */
		scope_key = strdup(cname);
		if (!scope_key)
			goto omem;
		scope_datum = malloc(sizeof(*scope_datum));
		if (!scope_datum)
			goto omem;
		scope_datum->scope = SCOPE_DECL;
		scope_datum->decl_ids = NULL;
		scope_datum->decl_ids_len = 0;
		if (add_i_to_a(1, &scope_datum->decl_ids_len,
			       &scope_datum->decl_ids) == -1)
			goto omem;

		tmp_ptr = reallocarray(policydb->type_val_to_struct,
				       policydb->p_types.nprim + 1,
				       sizeof(type_datum_t *));
		if (!tmp_ptr)
			goto omem;
		policydb->type_val_to_struct = tmp_ptr;
		policydb->type_val_to_struct[policydb->p_types.nprim] = NULL;

		tmp_ptr = reallocarray(policydb->sym_val_to_name[SYM_TYPES],
				       policydb->p_types.nprim + 1,
				       sizeof(char *));
		if (!tmp_ptr)
			goto omem;
		policydb->sym_val_to_name[SYM_TYPES] = tmp_ptr;
		policydb->p_type_val_to_name[policydb->p_types.nprim] = NULL;

		name = strdup(cname);
		if (!name)
			goto omem;

		typdatum->s.value = policydb->p_types.nprim + 1;
		if (hashtab_insert(policydb->p_types.table, name,
				   (hashtab_datum_t)typdatum) < 0)
			goto omem;
		policydb->p_types.nprim++;

		policydb->p_type_val_to_name[typdatum->s.value - 1] = name;
		policydb->type_val_to_struct[typdatum->s.value - 1] = typdatum;
		name = NULL;

		/* policydb now owns typdatum; error path must not free it */
		new = 0;

		/*
		 * The type itself is now fully committed above; register
		 * its scope so it survives a later expand/link pass. This
		 * insert can only fail on OOM here -- scope[SYM_TYPES].table
		 * and p_types.table are kept in lockstep by every insertion
		 * path in this file and in policydb.c, so `cname` cannot
		 * already be present. On that (OOM) failure the type is
		 * left in the pre-existing documented, memory-safe-but-
		 * inconsistent partially-populated state described in
		 * types.h.
		 */
		if (hashtab_insert(policydb->scope[SYM_TYPES].table, scope_key,
				   scope_datum) < 0)
			goto omem;
		scope_key = NULL;
		scope_datum = NULL;
	}

	free(subtypes);
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");
err:
	ERR(handle, "could not load type %s into policy", cname);
	free(name);
	free(subtypes);
	ebitmap_destroy(&new_types);
	free(scope_key);
	if (scope_datum) {
		free(scope_datum->decl_ids);
		free(scope_datum);
	}
	if (new && typdatum) {
		type_datum_destroy(typdatum);
		free(typdatum);
	}
	return STATUS_ERR;
}

DEFINE_VALUE_TO_NAME(sepol_type_value_to_name, "type", p_types,
		     p_type_val_to_name)

int sepol_type_query_by_value(sepol_handle_t *handle, const sepol_policydb_t *p,
			      uint32_t value, sepol_type_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	if (value < 1 || value > p->p.p_types.nprim) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	type_datum_t *type_datum = p->p.type_val_to_struct[value - 1];
	if (!type_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return type_datum_to_record(handle, &p->p, type_datum, NULL, response);
}

/* Return the number of types */
int sepol_type_count(sepol_handle_t *handle __attribute__((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	*response = p->p.p_types.table->nel;
	return STATUS_SUCCESS;
}

/* Check if the specified type exists */
int sepol_type_exists(sepol_handle_t *handle __attribute__((unused)),
		      const sepol_policydb_t *policydb,
		      const sepol_type_key_t *key, int *response)
{
	if (!policydb || !response)
		return STATUS_ERR;

	const char *name;
	sepol_type_key_unpack(key, &name);

	*response = name &&
		    hashtab_search(policydb->p.p_types.table, name) != NULL;

	return STATUS_SUCCESS;
}

/* Query a type - returns the type or NULL if not found */
int sepol_type_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_type_key_t *key, sepol_type_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	const char *name;
	sepol_type_key_unpack(key, &name);

	if (!name) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	type_datum_t *type_datum = hashtab_search(p->p.p_types.table, name);
	if (!type_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return type_datum_to_record(handle, &p->p, type_datum, name, response);
}

/* Iterators */
int sepol_type_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_type_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		ERR(handle, "invalid argument to sepol_type_iter_create");
		*iter = NULL;
		return STATUS_ERR;
	}
	sepol_type_iter_t *new = malloc(sizeof(sepol_type_iter_t));
	if (!new) {
		ERR(handle, "cannot allocate memory for sepol_type_iter_t");
		*iter = NULL;
		return STATUS_ERR;
	}
	new->p = p;
	hashtab_iter_init(p->p.p_types.table, &new->hashtab_iter);

	*iter = new;

	return STATUS_SUCCESS;
}

void sepol_type_iter_destroy(sepol_type_iter_t *iter)
{
	free(iter);
}

int sepol_type_iter_next(sepol_handle_t *handle, sepol_type_iter_t *iter,
			 sepol_type_t **item)
{
	char *key;
	type_datum_t *datum;

	if (!item)
		return STATUS_ERR;
	if (!iter) {
		*item = NULL;
		return STATUS_ERR;
	}

	hashtab_iter_next(&iter->hashtab_iter, &key, (hashtab_datum_t *)&datum);
	if (!key) {
		*item = NULL;
		return STATUS_SUCCESS;
	}

	return type_datum_to_record(handle, &iter->p->p, datum, key, item);
}

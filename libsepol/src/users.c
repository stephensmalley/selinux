#include <sepol/users.h>

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "private.h"
#include "debug.h"
#include "handle.h"

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/expand.h>
#include "sepol/policydb/util.h"
#include "user_internal.h"
#include "cat_set_internal.h"
#include "mls.h"

struct sepol_user_iter {
	const policydb_t *policydb;
	uint32_t idx;
};

static int user_to_record(sepol_handle_t *handle, const policydb_t *policydb,
			  uint32_t user_idx, sepol_user_t **record)
{
	const char *name;
	user_datum_t *usrdatum;
	ebitmap_t *roles;
	ebitmap_node_t *rnode;
	unsigned bit;

	sepol_user_t *tmp_record = NULL;

	if (user_idx >= policydb->p_users.nprim)
		goto err;

	name = policydb->p_user_val_to_name[user_idx];
	usrdatum = policydb->user_val_to_struct[user_idx];

	if (!usrdatum)
		goto err;

	roles = &(usrdatum->roles.roles);

	if (sepol_user_create(handle, &tmp_record) < 0)
		goto err;

	if (sepol_user_set_name(handle, tmp_record, name) < 0)
		goto err;

	/* Extract roles */
	ebitmap_for_each_positive_bit(roles, rnode, bit) {
		if (bit >= policydb->p_roles.nprim)
			goto err;
		char *role = policydb->p_role_val_to_name[bit];
		if (sepol_user_add_role(handle, tmp_record, role) < 0)
			goto err;
	}

	/* Extract MLS info */
	if (policydb->mls) {
		context_struct_t context;
		char *str;

		context_init(&context);
		if (mls_level_cpy(&context.range.level[0],
				  &usrdatum->exp_dfltlevel) < 0) {
			ERR(handle, "could not copy MLS level");
			context_destroy(&context);
			goto err;
		}
		if (mls_level_cpy(&context.range.level[1],
				  &usrdatum->exp_dfltlevel) < 0) {
			ERR(handle, "could not copy MLS level");
			context_destroy(&context);
			goto err;
		}
		if (mls_to_string(handle, policydb, &context, &str) < 0) {
			context_destroy(&context);
			goto err;
		}
		context_destroy(&context);

		if (sepol_user_set_mlslevel(handle, tmp_record, str) < 0) {
			free(str);
			goto err;
		}
		free(str);

		context_init(&context);
		if (mls_range_cpy(&context.range, &usrdatum->exp_range) < 0) {
			ERR(handle, "could not copy MLS range");
			context_destroy(&context);
			goto err;
		}
		if (mls_to_string(handle, policydb, &context, &str) < 0) {
			context_destroy(&context);
			goto err;
		}
		context_destroy(&context);

		if (sepol_user_set_mlsrange(handle, tmp_record, str) < 0) {
			free(str);
			goto err;
		}
		free(str);
	}

	*record = tmp_record;
	return STATUS_SUCCESS;

err:
	*record = NULL;
	sepol_user_free(tmp_record);
	return STATUS_ERR;
}

int sepol_user_modify(sepol_handle_t *handle, sepol_policydb_t *p,
		      const sepol_user_key_t *key, const sepol_user_t *user)
{
	policydb_t *policydb;

	/* For user data */
	const char *cname, *cmls_level, *cmls_range;
	char *name = NULL;

	const char **roles = NULL;
	unsigned int num_roles = 0;

	/* Low-level representation */
	user_datum_t *usrdatum = NULL;
	role_datum_t *roldatum;
	unsigned int i;

	hashtab_key_t scope_key = NULL;
	scope_datum_t *scope_datum = NULL;

	context_struct_t context;
	unsigned bit;
	int new = 0;
	int have_mls = 0;

	ebitmap_node_t *rnode;

	/*
	 * Resolved/validated new state, built up before touching any
	 * existing user_datum. This way a validation failure (e.g. an
	 * undefined role name, or a malformed MLS level/range -- both
	 * trivially caused by a bad caller argument, not just OOM) never
	 * leaves a previously-valid user blanked out or partially updated
	 * in the live policydb.
	 */
	ebitmap_t new_roles;
	ebitmap_t new_cache;
	mls_level_t new_dfltlevel;
	mls_range_t new_range;

	ebitmap_init(&new_roles);
	ebitmap_init(&new_cache);
	mls_level_init(&new_dfltlevel);
	mls_range_init(&new_range);

	if (!handle || !p || !key || !user)
		return STATUS_ERR;

	policydb = &p->p;

	/* First, extract all the data */
	sepol_user_key_unpack(key, &cname);
	if (!cname) {
		ERR(handle, "user key name is NULL");
		return STATUS_ERR;
	}

	cmls_level = sepol_user_get_mlslevel(user);
	cmls_range = sepol_user_get_mlsrange(user);

	/* Make sure that worked properly */
	if (sepol_user_get_roles(handle, user, &roles, &num_roles) < 0)
		goto err;

	/* For every role */
	for (i = 0; i < num_roles; i++) {
		/* Search for the role */
		roldatum = hashtab_search(policydb->p_roles.table, roles[i]);
		if (!roldatum) {
			ERR(handle, "undefined role %s for user %s", roles[i],
			    cname);
			goto err;
		}

		/* Set the role and every role it dominates */
		ebitmap_for_each_positive_bit(&roldatum->dominates, rnode,
					      bit) {
			if (ebitmap_set_bit(&new_roles, bit, 1))
				goto omem;
		}
	}

	/* For MLS systems */
	if (policydb->mls) {
		/* MLS level */
		if (cmls_level == NULL) {
			ERR(handle,
			    "MLS is enabled, but no MLS "
			    "default level was defined for user %s",
			    cname);
			goto err;
		}

		context_init(&context);
		if (mls_from_string(handle, policydb, cmls_level, &context) <
		    0) {
			context_destroy(&context);
			goto err;
		}
		if (mls_level_cpy(&new_dfltlevel, &context.range.level[0]) <
		    0) {
			ERR(handle, "could not copy MLS level %s", cmls_level);
			context_destroy(&context);
			goto err;
		}
		context_destroy(&context);

		/* MLS range */
		if (cmls_range == NULL) {
			ERR(handle,
			    "MLS is enabled, but no MLS "
			    "range was defined for user %s",
			    cname);
			goto err;
		}

		context_init(&context);
		if (mls_from_string(handle, policydb, cmls_range, &context) <
		    0) {
			context_destroy(&context);
			goto err;
		}
		if (mls_range_cpy(&new_range, &context.range) < 0) {
			ERR(handle, "could not copy MLS range %s", cmls_range);
			context_destroy(&context);
			goto err;
		}
		context_destroy(&context);

		have_mls = 1;
	} else if (cmls_level != NULL || cmls_range != NULL) {
		ERR(handle,
		    "MLS is disabled, but MLS level/range "
		    "was found for user %s",
		    cname);
		goto err;
	}

	/*
	 * Pre-compute the expanded role cache from the validated,
	 * already-fully-expanded new_roles bitmap (flags=0, so this is
	 * just an OOM-checked deep copy -- see role_set_expand()). Doing
	 * this before touching the live user_datum means a failure here
	 * (the only way role_set_expand can fail with flags=0 and no
	 * rolemap) never leaves an existing, previously-valid user with
	 * its roles/MLS replaced but its cache blanked.
	 */
	{
		role_set_t tmp_role_set = { .roles = new_roles, .flags = 0 };
		if (role_set_expand(&tmp_role_set, &new_cache, policydb, NULL,
				    NULL)) {
			ERR(handle, "unable to expand role set for user %s",
			    cname);
			goto omem;
		}
	}

	/*
	 * All names and MLS strings are validated; only now do we look up
	 * (and possibly destroy/reinitialize) the target user_datum.
	 */
	usrdatum = hashtab_search(policydb->p_users.table, cname);

	/* If it does, we will modify it */
	if (usrdatum) {
		uint32_t value_cp = usrdatum->s.value;
		user_datum_destroy(usrdatum);
		user_datum_init(usrdatum);
		usrdatum->s.value = value_cp;

		/* Otherwise, create a new one */
	} else {
		usrdatum = (user_datum_t *)malloc(sizeof(user_datum_t));
		if (!usrdatum)
			goto omem;
		user_datum_init(usrdatum);
		new = 1;
	}

	/* Transfer ownership of the validated roles/MLS/cache data to usrdatum */
	usrdatum->roles.roles = new_roles;
	ebitmap_init(&new_roles);
	usrdatum->cache = new_cache;
	ebitmap_init(&new_cache);
	if (have_mls) {
		usrdatum->exp_dfltlevel = new_dfltlevel;
		usrdatum->exp_range = new_range;
		mls_level_init(&new_dfltlevel);
		mls_range_init(&new_range);
	}

	/* If there are no errors, and this is a new user, add the user to policy */
	if (new) {
		void *tmp_ptr;

		if (policydb->p_users.nprim == UINT32_MAX) {
			ERR(handle, "too many users");
			goto err;
		}

		/*
		 * Prepare (but do not yet insert) a scope_datum for the new
		 * user up front, mirroring sepol_type_modify()'s scope
		 * bookkeeping in types.c (which in turn mirrors
		 * symtab_insert() in policydb.c): without a scope_datum,
		 * is_id_enabled() (avrule_block.c) treats a user as "not
		 * declared", so it would otherwise be silently dropped by
		 * any later expand_module()/link_modules() call even though
		 * it is fully present in p_users/user_val_to_struct. A user
		 * added through this public API is always an unconditional,
		 * top-level declaration -- there is no avrule-block/
		 * conditional context here -- which is exactly decl_id 1,
		 * the id checkpolicy assigns to the first declaration of a
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

		/* Ensure reverse lookup array has enough space */
		tmp_ptr = reallocarray(policydb->user_val_to_struct,
				       policydb->p_users.nprim + 1,
				       sizeof(user_datum_t *));
		if (!tmp_ptr)
			goto omem;
		policydb->user_val_to_struct = tmp_ptr;
		policydb->user_val_to_struct[policydb->p_users.nprim] = NULL;

		tmp_ptr = reallocarray(policydb->sym_val_to_name[SYM_USERS],
				       policydb->p_users.nprim + 1,
				       sizeof(char *));
		if (!tmp_ptr)
			goto omem;
		policydb->sym_val_to_name[SYM_USERS] = tmp_ptr;
		policydb->p_user_val_to_name[policydb->p_users.nprim] = NULL;

		/* Need to copy the user name */
		name = strdup(cname);
		if (!name)
			goto omem;

		/* Store user */
		usrdatum->s.value = policydb->p_users.nprim + 1;
		if (hashtab_insert(policydb->p_users.table, name,
				   (hashtab_datum_t)usrdatum) < 0)
			goto omem;
		policydb->p_users.nprim++;

		/* Set up reverse entry */
		policydb->p_user_val_to_name[usrdatum->s.value - 1] = name;
		policydb->user_val_to_struct[usrdatum->s.value - 1] = usrdatum;
		name = NULL;

		/* policydb now owns usrdatum; prevent error path from freeing */
		new = 0;

		/*
		 * The user itself is now fully committed above; register
		 * its scope so it survives a later expand/link pass. This
		 * insert can only fail on OOM here -- scope[SYM_USERS].table
		 * and p_users.table are kept in lockstep by every insertion
		 * path in this file and in policydb.c, so `cname` cannot
		 * already be present. On that (OOM) failure the user is
		 * left in the pre-existing documented, memory-safe-but-
		 * inconsistent partially-populated state described in
		 * users.h.
		 */
		if (hashtab_insert(policydb->scope[SYM_USERS].table, scope_key,
				   scope_datum) < 0)
			goto omem;
		scope_key = NULL;
		scope_datum = NULL;
	}

	free(roles);
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");

err:
	ERR(handle, "could not load %s into policy", cname);

	free(name);
	free(roles);
	ebitmap_destroy(&new_roles);
	ebitmap_destroy(&new_cache);
	mls_level_destroy(&new_dfltlevel);
	mls_range_destroy(&new_range);
	free(scope_key);
	if (scope_datum) {
		free(scope_datum->decl_ids);
		free(scope_datum);
	}
	if (new && usrdatum) {
		user_datum_destroy(usrdatum);
		free(usrdatum);
	}
	return STATUS_ERR;
}

DEFINE_VALUE_TO_NAME(sepol_user_value_to_name, "user", p_users,
		     p_user_val_to_name)

int sepol_user_query_by_value(sepol_handle_t *handle, const sepol_policydb_t *p,
			      uint32_t value, sepol_user_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	if (value < 1 || value > p->p.p_users.nprim) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	if (!p->p.user_val_to_struct[value - 1]) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return user_to_record(handle, &p->p, value - 1, response);
}

int sepol_user_exists(sepol_handle_t *handle __attribute__((unused)),
		      const sepol_policydb_t *p, const sepol_user_key_t *key,
		      int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	const policydb_t *policydb = &p->p;

	const char *cname;
	sepol_user_key_unpack(key, &cname);

	*response = cname &&
		    (hashtab_search(policydb->p_users.table, cname) != NULL);

	return STATUS_SUCCESS;
}

int sepol_user_count(sepol_handle_t *handle __attribute__((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	if (!p || !response)
		return STATUS_ERR;

	const policydb_t *policydb = &p->p;
	*response = policydb->p_users.table->nel;

	return STATUS_SUCCESS;
}

int sepol_user_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_user_key_t *key, sepol_user_t **response)
{
	if (!response)
		return STATUS_ERR;
	if (!p) {
		*response = NULL;
		return STATUS_ERR;
	}

	const policydb_t *policydb = &p->p;
	user_datum_t *usrdatum = NULL;

	const char *cname;
	sepol_user_key_unpack(key, &cname);

	if (!cname) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	usrdatum = hashtab_search(policydb->p_users.table, cname);

	if (!usrdatum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	if (user_to_record(handle, policydb, usrdatum->s.value - 1, response) <
	    0)
		goto err;

	return STATUS_SUCCESS;

err:
	ERR(handle, "could not query user %s", cname);
	return STATUS_ERR;
}

int sepol_user_iterate(sepol_handle_t *handle, const sepol_policydb_t *p,
		       int (*fn)(const sepol_user_t *user, void *fn_arg),
		       void *arg)
{
	if (!p || !fn) {
		ERR(handle, "policydb or callback is NULL");
		return STATUS_ERR;
	}

	const policydb_t *policydb = &p->p;
	unsigned int nusers = policydb->p_users.nprim;
	sepol_user_t *user = NULL;
	unsigned int i;

	/* For each user */
	for (i = 0; i < nusers; i++) {
		int status;

		if (user_to_record(handle, policydb, i, &user) < 0)
			goto err;

		/* Invoke handler */
		status = fn(user, arg);
		if (status < 0)
			goto err;

		sepol_user_free(user);
		user = NULL;

		/* Handler requested exit */
		if (status > 0)
			break;
	}

	return STATUS_SUCCESS;

err:
	ERR(handle, "could not iterate over users");
	sepol_user_free(user);
	return STATUS_ERR;
}

/* Users iterator */
int sepol_user_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_user_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_user_iter_t *new_iter = malloc(sizeof(sepol_user_iter_t));
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

void sepol_user_iter_destroy(sepol_user_iter_t *iter)
{
	free(iter);
}

int sepol_user_iter_next(sepol_handle_t *handle, sepol_user_iter_t *iter,
			 sepol_user_t **item)
{
	if (!item)
		return STATUS_ERR;
	if (!iter) {
		*item = NULL;
		return STATUS_ERR;
	}

	while (iter->idx < iter->policydb->p_users.nprim) {
		unsigned int idx = iter->idx;
		iter->idx++;
		if (iter->policydb->user_val_to_struct[idx]) {
			sepol_user_t *user;
			int status = user_to_record(handle, iter->policydb, idx,
						    &user);
			*item = user;
			if (status)
				return status;
			return STATUS_SUCCESS;
		}
	}

	*item = NULL;
	return STATUS_SUCCESS;
}

static const user_datum_t *user_datum_by_value(const sepol_policydb_t *p,
					       uint32_t value)
{
	if (!p || value < 1 || value > p->p.p_users.nprim)
		return NULL;
	return p->p.user_val_to_struct[value - 1];
}

uint32_t sepol_user_get_dflt_level_sens(const sepol_policydb_t *p,
					uint32_t user_value)
{
	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u)
		return 0;
	return u->exp_dfltlevel.sens;
}

int sepol_user_get_dflt_level_cat(sepol_handle_t *handle
				  __attribute__((unused)),
				  const sepol_policydb_t *p,
				  uint32_t user_value,
				  sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;

	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&u->exp_dfltlevel.cat,
						cat_iter);
}

uint32_t sepol_user_get_range_low_sens(const sepol_policydb_t *p,
				       uint32_t user_value)
{
	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u)
		return 0;
	return u->exp_range.level[0].sens;
}

uint32_t sepol_user_get_range_high_sens(const sepol_policydb_t *p,
					uint32_t user_value)
{
	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u)
		return 0;
	return u->exp_range.level[1].sens;
}

int sepol_user_get_range_low_cat(sepol_handle_t *handle __attribute__((unused)),
				 const sepol_policydb_t *p, uint32_t user_value,
				 sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;

	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&u->exp_range.level[0].cat,
						cat_iter);
}

int sepol_user_get_range_high_cat(sepol_handle_t *handle
				  __attribute__((unused)),
				  const sepol_policydb_t *p,
				  uint32_t user_value,
				  sepol_cat_set_iter_t **cat_iter)
{
	if (!cat_iter)
		return STATUS_ERR;

	const user_datum_t *u = user_datum_by_value(p, user_value);
	if (!u) {
		*cat_iter = NULL;
		return STATUS_SUCCESS;
	}
	return cat_set_iter_create_from_ebitmap(&u->exp_range.level[1].cat,
						cat_iter);
}

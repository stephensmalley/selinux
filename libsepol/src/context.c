#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sepol/context.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/sidtab.h>
#include "context_internal.h"

#include "debug.h"
#include "context.h"
#include "handle.h"
#include "mls.h"
#include "private.h"

/* ----- Compatibility ---- */
int policydb_context_isvalid(const policydb_t *p, const context_struct_t *c)
{
	return context_is_valid(p, c);
}

int sepol_check_context(const char *context)
{
	return sepol_context_to_sid(context, strlen(context) + 1, NULL);
}

/* ---- End compatibility --- */

/*
 * Return 1 if the fields in the security context
 * structure `c' are valid.  Return 0 otherwise.
 */
int context_is_valid(const policydb_t *p, const context_struct_t *c)
{
	role_datum_t *role;
	user_datum_t *usrdatum;

	if (!c->role || c->role > p->p_roles.nprim)
		return 0;

	if (!c->user || c->user > p->p_users.nprim)
		return 0;

	if (!c->type || c->type > p->p_types.nprim)
		return 0;

	if (c->role != OBJECT_R_VAL) {
		/*
		 * Role must be authorized for the type.
		 */
		role = p->role_val_to_struct[c->role - 1];
		if (!role || !ebitmap_get_bit(&role->cache, c->type - 1))
			/* role may not be associated with type */
			return 0;

		/*
		 * User must be authorized for the role.
		 */
		usrdatum = p->user_val_to_struct[c->user - 1];
		if (!usrdatum)
			return 0;

		if (!ebitmap_get_bit(&usrdatum->cache, c->role - 1))
			/* user may not be associated with role */
			return 0;
	}

	if (!mls_context_isvalid(p, c))
		return 0;

	return 1;
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
int context_to_string(sepol_handle_t *handle, const policydb_t *policydb,
		      const context_struct_t *context, char **result,
		      size_t *result_len)
{
	char *scontext = NULL;
	size_t scontext_len = 0;
	char *ptr;

	if (!context->user || context->user > policydb->p_users.nprim ||
	    !context->role || context->role > policydb->p_roles.nprim ||
	    !context->type || context->type > policydb->p_types.nprim)
		return STATUS_ERR;

	/* Compute the size of the context. */
	scontext_len +=
		strlen(policydb->p_user_val_to_name[context->user - 1]) + 1;
	scontext_len +=
		strlen(policydb->p_role_val_to_name[context->role - 1]) + 1;
	scontext_len += strlen(policydb->p_type_val_to_name[context->type - 1]);
	scontext_len += mls_compute_context_len(policydb, context);

	/* We must null terminate the string */
	scontext_len += 1;

	/* Allocate space for the context; caller must free this space. */
	scontext = malloc(scontext_len);
	if (!scontext)
		goto omem;
	scontext[scontext_len - 1] = '\0';

	/*
	 * Copy the user name, role name and type name into the context.
	 */
	ptr = scontext;
	sprintf(ptr, "%s:%s:%s",
		policydb->p_user_val_to_name[context->user - 1],
		policydb->p_role_val_to_name[context->role - 1],
		policydb->p_type_val_to_name[context->type - 1]);

	ptr += strlen(policydb->p_user_val_to_name[context->user - 1]) + 1 +
	       strlen(policydb->p_role_val_to_name[context->role - 1]) + 1 +
	       strlen(policydb->p_type_val_to_name[context->type - 1]);

	mls_sid_to_context(policydb, context, &ptr);

	*result = scontext;
	*result_len = scontext_len;
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory, could not convert "
		    "context to string");
	free(scontext);
	return STATUS_ERR;
}

/*
 * Create a context structure from the given record
 */
int context_from_record(sepol_handle_t *handle, const policydb_t *policydb,
			context_struct_t **cptr, const sepol_context_t *record)
{
	context_struct_t *scontext = NULL;
	user_datum_t *usrdatum;
	role_datum_t *roldatum;
	type_datum_t *typdatum;

	*cptr = NULL;

	if (!record) {
		ERR(handle, "context record is NULL");
		return STATUS_ERR;
	}

	const char *user_str = sepol_context_get_user(record);
	const char *role_str = sepol_context_get_role(record);
	const char *type_str = sepol_context_get_type(record);
	if (!user_str || !role_str || !type_str) {
		ERR(handle, "context record has NULL user, role, or type");
		return STATUS_ERR;
	}
	/* Hashtab keys are not constant - suppress warnings */
	char *user = strdup(user_str);
	char *role = strdup(role_str);
	char *type = strdup(type_str);
	const char *mls = sepol_context_get_mls(record);

	scontext = (context_struct_t *)malloc(sizeof(context_struct_t));
	if (!user || !role || !type || !scontext) {
		ERR(handle, "out of memory");
		goto err;
	}
	context_init(scontext);

	/* User */
	usrdatum = (user_datum_t *)hashtab_search(policydb->p_users.table,
						  (hashtab_key_t)user);
	if (!usrdatum) {
		ERR(handle, "user %s is not defined", user);
		goto err_destroy;
	}
	scontext->user = usrdatum->s.value;

	/* Role */
	roldatum = (role_datum_t *)hashtab_search(policydb->p_roles.table,
						  (hashtab_key_t)role);
	if (!roldatum) {
		ERR(handle, "role %s is not defined", role);
		goto err_destroy;
	}
	scontext->role = roldatum->s.value;

	/* Type */
	typdatum = (type_datum_t *)hashtab_search(policydb->p_types.table,
						  (hashtab_key_t)type);
	if (!typdatum || typdatum->flavor == TYPE_ATTRIB) {
		ERR(handle, "type %s is not defined", type);
		goto err_destroy;
	}
	scontext->type = typdatum->s.value;

	/* MLS */
	if (mls && !policydb->mls) {
		ERR(handle, "MLS is disabled, but MLS context \"%s\" found",
		    mls);
		goto err_destroy;
	} else if (!mls && policydb->mls) {
		ERR(handle, "MLS is enabled, but no MLS context found");
		goto err_destroy;
	}
	if (mls && (mls_from_string(handle, policydb, mls, scontext) < 0))
		goto err_destroy;

	/* Validity check */
	if (!context_is_valid(policydb, scontext)) {
		if (mls) {
			ERR(handle, "invalid security context: \"%s:%s:%s:%s\"",
			    user, role, type, mls);
		} else {
			ERR(handle, "invalid security context: \"%s:%s:%s\"",
			    user, role, type);
		}
		goto err_destroy;
	}

	*cptr = scontext;
	free(user);
	free(type);
	free(role);
	return STATUS_SUCCESS;

err_destroy:
	errno = EINVAL;
	context_destroy(scontext);

err:
	free(scontext);
	free(user);
	free(type);
	free(role);
	ERR(handle, "could not create context structure");
	return STATUS_ERR;
}

/*
 * Create a record from the given context structure
 */
int context_to_record(sepol_handle_t *handle, const policydb_t *policydb,
		      const context_struct_t *context, sepol_context_t **record)
{
	sepol_context_t *tmp_record = NULL;
	char *mls = NULL;

	if (sepol_context_create(handle, &tmp_record) < 0)
		goto err;

	if (sepol_context_set_user(
		    handle, tmp_record,
		    policydb->p_user_val_to_name[context->user - 1]) < 0)
		goto err;

	if (sepol_context_set_role(
		    handle, tmp_record,
		    policydb->p_role_val_to_name[context->role - 1]) < 0)
		goto err;

	if (sepol_context_set_type(
		    handle, tmp_record,
		    policydb->p_type_val_to_name[context->type - 1]) < 0)
		goto err;

	if (policydb->mls) {
		if (mls_to_string(handle, policydb, context, &mls) < 0)
			goto err;

		if (sepol_context_set_mls(handle, tmp_record, mls) < 0)
			goto err;
	}

	free(mls);
	*record = tmp_record;
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not create context record");
	sepol_context_free(tmp_record);
	free(mls);
	return STATUS_ERR;
}

/*
 * Create a context structure from the provided string.
 */
int context_from_string(sepol_handle_t *handle, const policydb_t *policydb,
			context_struct_t **cptr, const char *con_str,
			size_t con_str_len)
{
	char *con_cpy = NULL;
	sepol_context_t *ctx_record = NULL;

	*cptr = NULL;

	if (zero_or_saturated(con_str_len)) {
		ERR(handle, "Invalid context length");
		goto err;
	}

	/* sepol_context_from_string expects a NULL-terminated string */
	con_cpy = malloc(con_str_len + 1);
	if (!con_cpy) {
		ERR(handle, "out of memory");
		goto err;
	}

	memcpy(con_cpy, con_str, con_str_len);
	con_cpy[con_str_len] = '\0';

	if (sepol_context_from_string(handle, con_cpy, &ctx_record) < 0)
		goto err;

	/* Now create from the data structure */
	if (context_from_record(handle, policydb, cptr, ctx_record) < 0)
		goto err;

	free(con_cpy);
	sepol_context_free(ctx_record);
	return STATUS_SUCCESS;

err:
	ERR(handle, "could not create context structure");
	free(con_cpy);
	sepol_context_free(ctx_record);
	return STATUS_ERR;
}

int sepol_context_check(sepol_handle_t *handle,
			const sepol_policydb_t *policydb,
			const sepol_context_t *context)
{
	if (!policydb || !context)
		return STATUS_ERR;

	context_struct_t *con = NULL;
	int ret = context_from_record(handle, &policydb->p, &con, context);
	if (con) {
		context_destroy(con);
		free(con);
	}
	return ret;
}

/*
 * Populate ctx from policy-internal values (1-based) and optional MLS range text.
 */
static int values_prepare_context(sepol_handle_t *handle, const policydb_t *p,
				  uint32_t user_val, uint32_t role_val,
				  uint32_t type_val, const char *mls_range,
				  context_struct_t *ctx)
{
	type_datum_t *typdatum;

	if (user_val < 1 || user_val > p->p_users.nprim ||
	    !p->p_user_val_to_name[user_val - 1]) {
		ERR(handle, "invalid user value %u", user_val);
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (role_val < 1 || role_val > p->p_roles.nprim ||
	    !p->p_role_val_to_name[role_val - 1]) {
		ERR(handle, "invalid role value %u", role_val);
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (type_val < 1 || type_val > p->p_types.nprim ||
	    !p->p_type_val_to_name[type_val - 1]) {
		ERR(handle, "invalid type value %u", type_val);
		errno = EINVAL;
		return STATUS_ERR;
	}

	typdatum = p->type_val_to_struct[type_val - 1];
	if (!typdatum || typdatum->flavor == TYPE_ATTRIB) {
		ERR(handle, "invalid type value %u", type_val);
		errno = EINVAL;
		return STATUS_ERR;
	}

	ctx->user = user_val;
	ctx->role = role_val;
	ctx->type = type_val;

	if (p->mls) {
		if (!mls_range || !*mls_range) {
			ERR(handle, "MLS is enabled but MLS range is missing");
			errno = EINVAL;
			return STATUS_ERR;
		}
		if (mls_from_string(handle, p, mls_range, ctx) < 0)
			return STATUS_ERR;
	} else {
		if (mls_range && *mls_range) {
			ERR(handle,
			    "MLS is disabled, but MLS range \"%s\" was supplied",
			    mls_range);
			errno = EINVAL;
			return STATUS_ERR;
		}
	}

	if (!context_is_valid(p, ctx)) {
		ERR(handle, "invalid security context from values");
		errno = EINVAL;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int sepol_values_to_context_string(sepol_handle_t *handle,
				   const sepol_policydb_t *policydb,
				   uint32_t user_val, uint32_t role_val,
				   uint32_t type_val, const char *mls_range,
				   char **out, size_t *out_len)
{
	const policydb_t *p;
	context_struct_t ctx;
	int rc;

	if (!policydb || !out || !out_len)
		return STATUS_ERR;

	*out = NULL;
	*out_len = 0;

	p = &policydb->p;
	context_init(&ctx);

	rc = values_prepare_context(handle, p, user_val, role_val, type_val,
				    mls_range, &ctx);
	if (rc < 0)
		goto out;

	rc = context_to_string(handle, p, &ctx, out, out_len);
out:
	context_destroy(&ctx);
	return rc;
}

int sepol_values_to_context_record(sepol_handle_t *handle,
				   const sepol_policydb_t *policydb,
				   uint32_t user_val, uint32_t role_val,
				   uint32_t type_val, const char *mls_range,
				   sepol_context_t **record)
{
	const policydb_t *p;
	context_struct_t ctx;
	int rc;

	if (!policydb || !record)
		return STATUS_ERR;

	*record = NULL;

	p = &policydb->p;
	context_init(&ctx);

	rc = values_prepare_context(handle, p, user_val, role_val, type_val,
				    mls_range, &ctx);
	if (rc < 0)
		goto out;

	rc = context_to_record(handle, p, &ctx, record);
out:
	context_destroy(&ctx);
	return rc;
}

static int policydb_sid_lookup_context(sepol_handle_t *handle,
				       const sepol_policydb_t *policydb,
				       uint32_t sid, context_struct_t **ctx_out)
{
	sidtab_t sidtab;
	context_struct_t *ctx;
	int rc;

	/*
	 * handle may legitimately be NULL here, same as in
	 * sepol_values_to_context_string()/_record() above: ERR()
	 * (via msg_write()) falls back to sepol_compat_handle when handle
	 * is NULL, and nothing else in this function dereferences handle
	 * directly.
	 */
	if (!policydb || !ctx_out)
		return STATUS_ERR;

	*ctx_out = NULL;
	memset(&sidtab, 0, sizeof(sidtab));

	rc = policydb_load_isids((policydb_t *)&policydb->p, &sidtab);
	if (rc < 0) {
		ERR(handle, "failed to load initial SID table from policy");
		/*
		 * policydb_load_isids() may have partially populated sidtab
		 * (sepol_sidtab_init() succeeded, then a later insert failed)
		 * before returning an error; destroy it to avoid leaking the
		 * hash table and any contexts already inserted into it.
		 */
		sepol_sidtab_destroy(&sidtab);
		return STATUS_ERR;
	}

	ctx = sepol_sidtab_search(&sidtab, sid);
	if (!ctx) {
		ERR(handle, "SID %u not found in policy", sid);
		sepol_sidtab_destroy(&sidtab);
		return STATUS_ERR;
	}

	/*
	 * context_to_string/record only read fields from ctx; deep-copy the
	 * struct (context_cpy(), not a shallow assignment) so we can destroy
	 * sidtab before returning without leaving *ctx_out's MLS range
	 * pointing at ebitmap nodes that sepol_sidtab_destroy() just freed.
	 */
	*ctx_out = malloc(sizeof(**ctx_out));
	if (!*ctx_out) {
		ERR(handle, "out of memory");
		sepol_sidtab_destroy(&sidtab);
		return STATUS_ERR;
	}
	if (context_cpy(*ctx_out, ctx) < 0) {
		ERR(handle, "out of memory");
		free(*ctx_out);
		*ctx_out = NULL;
		sepol_sidtab_destroy(&sidtab);
		return STATUS_ERR;
	}
	sepol_sidtab_destroy(&sidtab);
	return STATUS_SUCCESS;
}

int sepol_policydb_sid_to_context_string(sepol_handle_t *handle,
					 const sepol_policydb_t *policydb,
					 uint32_t sid, char **out,
					 size_t *out_len)
{
	context_struct_t *ctx = NULL;
	int rc;

	if (!out || !out_len)
		return STATUS_ERR;

	*out = NULL;
	*out_len = 0;

	rc = policydb_sid_lookup_context(handle, policydb, sid, &ctx);
	if (rc < 0)
		return rc;

	rc = context_to_string(handle, &policydb->p, ctx, out, out_len);
	context_destroy(ctx);
	free(ctx);
	return rc;
}

int sepol_policydb_sid_to_context_record(sepol_handle_t *handle,
					 const sepol_policydb_t *policydb,
					 uint32_t sid, sepol_context_t **record)
{
	context_struct_t *ctx = NULL;
	int rc;

	if (!record)
		return STATUS_ERR;

	*record = NULL;

	rc = policydb_sid_lookup_context(handle, policydb, sid, &ctx);
	if (rc < 0)
		return rc;

	rc = context_to_record(handle, &policydb->p, ctx, record);
	context_destroy(ctx);
	free(ctx);
	return rc;
}

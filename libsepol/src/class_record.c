#include <sepol/class_record.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sepol/policydb/util.h"
#include "debug.h"

struct sepol_class {
	char *name;
	char *common;
	char **perms;
	uint32_t num_perms;
	sepol_constraint_t **constraints;
	uint32_t num_constraints;
	sepol_constraint_t **validatetrans;
	uint32_t num_validatetrans;
	int default_user;
	int default_role;
	int default_type;
	int default_range;
};

struct sepol_class_key {
	char *name;
};

struct sepol_constraint {
	char **perms;
	uint32_t num_perms;
	sepol_constraint_expr_t **exprs;
	uint32_t num_exprs;
};

struct sepol_constraint_expr {
	uint32_t expr_type;
	uint32_t attr;
	uint32_t op;
	char **names;
	uint32_t num_names;
};

/* Key */
int sepol_class_key_create(sepol_handle_t *handle, const char *name,
			   sepol_class_key_t **key)
{
	if (!key)
		return STATUS_ERR;
	if (!name) {
		ERR(handle, "name is NULL");
		*key = NULL;
		return STATUS_ERR;
	}
	sepol_class_key_t *tmp_key = malloc(sizeof(sepol_class_key_t));
	if (!tmp_key)
		goto omem;
	tmp_key->name = strdup(name);
	if (!tmp_key->name)
		goto omem;

	*key = tmp_key;
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");
	free(tmp_key);
	*key = NULL;
	return STATUS_ERR;
}

void sepol_class_key_unpack(const sepol_class_key_t *key, const char **name)
{
	*name = key ? key->name : NULL;
}

int sepol_class_key_extract(sepol_handle_t *handle, const sepol_class_t *cls,
			    sepol_class_key_t **key)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	if (!cls->name) {
		ERR(handle, "class name is NULL");
		return STATUS_ERR;
	}
	return sepol_class_key_create(handle, cls->name, key);
}

void sepol_class_key_free(sepol_class_key_t *key)
{
	if (!key)
		return;
	free(key->name);
	free(key);
}

int sepol_class_compare(const sepol_class_t *cls, const sepol_class_key_t *key)
{
	if (!cls || !key || !cls->name || !key->name)
		return -1;
	return strcmp(cls->name, key->name);
}

int sepol_class_compare2(const sepol_class_t *cls, const sepol_class_t *cls2)
{
	if (!cls || !cls2 || !cls->name || !cls2->name)
		return -1;
	return strcmp(cls->name, cls2->name);
}

/* Class name */
const char *sepol_class_get_name(const sepol_class_t *cls)
{
	return cls ? cls->name : NULL;
}

int sepol_class_set_name(sepol_handle_t *handle, sepol_class_t *cls,
			 const char *name)
{
	if (!cls || !name) {
		ERR(handle, "class or name is NULL");
		return STATUS_ERR;
	}
	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	free(cls->name);
	cls->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Common name */
const char *sepol_class_get_common(const sepol_class_t *cls)
{
	return cls ? cls->common : NULL;
}

int sepol_class_set_common(sepol_handle_t *handle, sepol_class_t *cls,
			   const char *common)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	if (common) {
		char *tmp_common = strdup(common);
		if (!tmp_common) {
			ERR(handle, "out of memory");
			return STATUS_ERR;
		}
		free(cls->common);
		cls->common = tmp_common;
	} else {
		free(cls->common);
		cls->common = NULL;
	}
	return STATUS_SUCCESS;
}

/* Class-specific permissions */
int sepol_class_has_perm(const sepol_class_t *cls, const char *perm)
{
	if (!cls)
		return 0;
	return string_list_contains(cls->perms, cls->num_perms, perm);
}

int sepol_class_get_perms(sepol_handle_t *handle, const sepol_class_t *cls,
			  const char ***perms, uint32_t *num_perms)
{
	if (!perms || !num_perms)
		return STATUS_ERR;
	if (!cls) {
		*perms = NULL;
		*num_perms = 0;
		return STATUS_ERR;
	}
	return string_list_scopy(handle, cls->perms, cls->num_perms, perms,
				 num_perms);
}

int sepol_class_add_perm(sepol_handle_t *handle, sepol_class_t *cls,
			 const char *perm)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	return string_list_add_unique(handle, &cls->perms, &cls->num_perms,
				      perm);
}

int sepol_class_del_perm(sepol_handle_t *handle, sepol_class_t *cls,
			 const char *perm)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	return string_list_del(cls->perms, &cls->num_perms, perm);
}

/*
 * sepol_class_t stores two separate but identically-shaped arrays of
 * sepol_constraint_t* (constraints and validatetrans). The following three
 * helpers implement the shared get/add/del logic once; the public
 * constraint/validatetrans functions below are thin wrappers that select
 * which array/count pair to operate on.
 */
static int constraint_array_copy_out(sepol_handle_t *handle,
				     sepol_constraint_t *const *arr,
				     uint32_t count,
				     const sepol_constraint_t ***out_arr,
				     uint32_t *out_count)
{
	if (!out_arr || !out_count)
		return STATUS_ERR;

	if (count == 0) {
		*out_arr = NULL;
		*out_count = 0;
		return STATUS_SUCCESS;
	}

	const sepol_constraint_t **tmp =
		calloc(count, sizeof(const sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < count; i++)
		tmp[i] = arr[i];

	*out_arr = tmp;
	*out_count = count;

	return STATUS_SUCCESS;
}

static int constraint_array_add(sepol_handle_t *handle,
				sepol_constraint_t ***arr, uint32_t *count,
				sepol_constraint_t *constraint,
				const char *desc)
{
	if (!constraint) {
		ERR(handle, "class or %s is NULL", desc);
		return STATUS_ERR;
	}
	if (*count == UINT32_MAX) {
		ERR(handle, "too many %ss", desc);
		return STATUS_ERR;
	}
	sepol_constraint_t **tmp =
		reallocarray(*arr, *count + 1, sizeof(sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	*arr = tmp;
	(*arr)[*count] = constraint;
	(*count)++;

	return STATUS_SUCCESS;
}

/*
 * Removes exactly the constraint object identified by `constraint`'s
 * pointer identity, not by deep value equality. sepol_class_add_constraint()/
 * sepol_class_add_validatetrans() explicitly document that a constraint is
 * "stored by reference (not copied)", and legitimate policies can and do
 * have multiple structurally-identical constrain/validatetrans rules
 * (nothing about the add path deduplicates by value) -- so matching by
 * value here would delete every value-equal sibling object too, freeing
 * ones the caller never asked to remove and may still hold a pointer to
 * (a real use-after-free/double-free risk for the caller), not just the
 * one instance actually passed in.
 */
static int constraint_array_del(sepol_handle_t *handle,
				sepol_constraint_t **arr, uint32_t *count,
				const sepol_constraint_t *constraint)
{
	if (!constraint)
		return STATUS_ERR;

	for (uint32_t i = *count; i > 0; i--) {
		if (arr[i - 1] == constraint) {
			sepol_constraint_free(arr[i - 1]);
			(*count)--;
			if (i - 1 < *count)
				arr[i - 1] = arr[*count];
			return STATUS_SUCCESS;
		}
	}
	ERR(handle, "constraint not found");
	return STATUS_ERR;
}

/* Constraints */
int sepol_class_get_constraints(sepol_handle_t *handle,
				const sepol_class_t *cls,
				const sepol_constraint_t ***constraints,
				uint32_t *num_constraints)
{
	if (!constraints || !num_constraints)
		return STATUS_ERR;
	if (!cls) {
		*constraints = NULL;
		*num_constraints = 0;
		return STATUS_ERR;
	}

	return constraint_array_copy_out(handle, cls->constraints,
					 cls->num_constraints, constraints,
					 num_constraints);
}

int sepol_class_add_constraint(sepol_handle_t *handle, sepol_class_t *cls,
			       sepol_constraint_t *constraint)
{
	if (!cls) {
		ERR(handle, "class or constraint is NULL");
		return STATUS_ERR;
	}

	return constraint_array_add(handle, &cls->constraints,
				    &cls->num_constraints, constraint,
				    "constraint");
}

int sepol_class_del_constraint(sepol_handle_t *handle, sepol_class_t *cls,
			       const sepol_constraint_t *constraint)
{
	if (!cls)
		return STATUS_ERR;

	return constraint_array_del(handle, cls->constraints,
				    &cls->num_constraints, constraint);
}

/* Validate transitions */
int sepol_class_get_validatetrans(sepol_handle_t *handle,
				  const sepol_class_t *cls,
				  const sepol_constraint_t ***validatetrans,
				  uint32_t *num_validatetrans)
{
	if (!validatetrans || !num_validatetrans)
		return STATUS_ERR;
	if (!cls) {
		*validatetrans = NULL;
		*num_validatetrans = 0;
		return STATUS_ERR;
	}

	return constraint_array_copy_out(handle, cls->validatetrans,
					 cls->num_validatetrans, validatetrans,
					 num_validatetrans);
}

int sepol_class_add_validatetrans(sepol_handle_t *handle, sepol_class_t *cls,
				  sepol_constraint_t *validatetrans)
{
	if (!cls) {
		ERR(handle, "class or validatetrans is NULL");
		return STATUS_ERR;
	}

	return constraint_array_add(handle, &cls->validatetrans,
				    &cls->num_validatetrans, validatetrans,
				    "validatetrans");
}

int sepol_class_del_validatetrans(sepol_handle_t *handle, sepol_class_t *cls,
				  const sepol_constraint_t *validatetrans)
{
	if (!cls)
		return STATUS_ERR;

	return constraint_array_del(handle, cls->validatetrans,
				    &cls->num_validatetrans, validatetrans);
}

/* Defaults */
int sepol_class_get_default_user(const sepol_class_t *cls)
{
	return cls ? cls->default_user : 0;
}

int sepol_class_set_default_user(sepol_handle_t *handle, sepol_class_t *cls,
				 int default_user)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	cls->default_user = default_user;
	return STATUS_SUCCESS;
}

int sepol_class_get_default_role(const sepol_class_t *cls)
{
	return cls ? cls->default_role : 0;
}

int sepol_class_set_default_role(sepol_handle_t *handle, sepol_class_t *cls,
				 int default_role)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	cls->default_role = default_role;
	return STATUS_SUCCESS;
}

int sepol_class_get_default_type(const sepol_class_t *cls)
{
	return cls ? cls->default_type : 0;
}

int sepol_class_set_default_type(sepol_handle_t *handle, sepol_class_t *cls,
				 int default_type)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	cls->default_type = default_type;
	return STATUS_SUCCESS;
}

int sepol_class_get_default_range(const sepol_class_t *cls)
{
	return cls ? cls->default_range : 0;
}

int sepol_class_set_default_range(sepol_handle_t *handle, sepol_class_t *cls,
				  int default_range)
{
	if (!cls) {
		ERR(handle, "class is NULL");
		return STATUS_ERR;
	}
	cls->default_range = default_range;
	return STATUS_SUCCESS;
}

/* Create/Clone/Destroy */
int sepol_class_create(sepol_handle_t *handle, sepol_class_t **class_ptr)
{
	sepol_class_t *tmp;

	if (!class_ptr)
		return STATUS_ERR;

	tmp = malloc(sizeof(sepol_class_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		*class_ptr = NULL;
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_class_t));
	*class_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_class_clone(sepol_handle_t *handle, const sepol_class_t *cls,
		      sepol_class_t **class_ptr)
{
	sepol_class_t *tmp = NULL;

	if (!class_ptr)
		return STATUS_ERR;
	if (!cls) {
		*class_ptr = NULL;
		return STATUS_ERR;
	}

	if (sepol_class_create(handle, &tmp))
		goto err;

	if (sepol_class_set_name(handle, tmp, cls->name))
		goto err;
	if (sepol_class_set_common(handle, tmp, cls->common))
		goto err;
	for (size_t i = 0; i < cls->num_perms; i++) {
		if (sepol_class_add_perm(handle, tmp, cls->perms[i]))
			goto err;
	}
	for (size_t i = 0; i < cls->num_constraints; i++) {
		sepol_constraint_t *cloned_constraint = NULL;
		if (sepol_constraint_clone(handle, cls->constraints[i],
					   &cloned_constraint))
			goto err;
		if (sepol_class_add_constraint(handle, tmp,
					       cloned_constraint)) {
			sepol_constraint_free(cloned_constraint);
			goto err;
		}
	}
	for (size_t i = 0; i < cls->num_validatetrans; i++) {
		sepol_constraint_t *cloned_vt = NULL;
		if (sepol_constraint_clone(handle, cls->validatetrans[i],
					   &cloned_vt))
			goto err;
		if (sepol_class_add_validatetrans(handle, tmp, cloned_vt)) {
			sepol_constraint_free(cloned_vt);
			goto err;
		}
	}
	if (sepol_class_set_default_user(handle, tmp, cls->default_user))
		goto err;
	if (sepol_class_set_default_role(handle, tmp, cls->default_role))
		goto err;
	if (sepol_class_set_default_type(handle, tmp, cls->default_type))
		goto err;
	if (sepol_class_set_default_range(handle, tmp, cls->default_range))
		goto err;

	*class_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_class_free(tmp);
	*class_ptr = NULL;
	return STATUS_ERR;
}

void sepol_class_free(sepol_class_t *cls)
{
	if (!cls)
		return;

	free(cls->name);
	free(cls->common);
	for (size_t i = 0; i < cls->num_perms; i++)
		free(cls->perms[i]);
	free(cls->perms);
	for (size_t i = 0; i < cls->num_constraints; i++)
		sepol_constraint_free(cls->constraints[i]);
	free(cls->constraints);
	for (size_t i = 0; i < cls->num_validatetrans; i++)
		sepol_constraint_free(cls->validatetrans[i]);
	free(cls->validatetrans);
	free(cls);
}

/* Constraints */
int sepol_constraint_create(sepol_handle_t *handle,
			    sepol_constraint_t **constraint_ptr)
{
	sepol_constraint_t *tmp;

	if (!constraint_ptr)
		return STATUS_ERR;

	tmp = malloc(sizeof(sepol_constraint_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		*constraint_ptr = NULL;
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_constraint_t));
	*constraint_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_constraint_clone(sepol_handle_t *handle,
			   const sepol_constraint_t *constraint,
			   sepol_constraint_t **constraint_ptr)
{
	if (!constraint_ptr)
		return STATUS_ERR;
	if (!constraint) {
		*constraint_ptr = NULL;
		return STATUS_ERR;
	}

	sepol_constraint_t *tmp;
	if (sepol_constraint_create(handle, &tmp)) {
		*constraint_ptr = NULL;
		return STATUS_ERR;
	}

	for (size_t i = 0; i < constraint->num_perms; i++) {
		if (sepol_constraint_add_perm(handle, tmp,
					      constraint->perms[i]))
			goto err;
	}

	for (size_t i = 0; i < constraint->num_exprs; i++) {
		sepol_constraint_expr_t *cloned_expr = NULL;
		if (sepol_constraint_expr_clone(handle, constraint->exprs[i],
						&cloned_expr))
			goto err;
		if (sepol_constraint_insert_expr(handle, tmp, i, cloned_expr)) {
			sepol_constraint_expr_free(cloned_expr);
			goto err;
		}
	}
	*constraint_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_constraint_free(tmp);
	*constraint_ptr = NULL;
	return STATUS_ERR;
}

void sepol_constraint_free(sepol_constraint_t *constraint)
{
	if (!constraint)
		return;

	for (size_t i = 0; i < constraint->num_perms; i++)
		free(constraint->perms[i]);
	free(constraint->perms);
	for (size_t i = 0; i < constraint->num_exprs; i++)
		sepol_constraint_expr_free(constraint->exprs[i]);
	free(constraint->exprs);
	free(constraint);
}

/* Constrained permissions */
int sepol_constraint_has_perm(const sepol_constraint_t *constraint,
			      const char *perm)
{
	if (!constraint)
		return 0;
	return string_list_contains(constraint->perms, constraint->num_perms,
				    perm);
}

int sepol_constraint_get_perms(sepol_handle_t *handle,
			       const sepol_constraint_t *constraint,
			       const char ***perms, uint32_t *num_perms)
{
	if (!perms || !num_perms)
		return STATUS_ERR;
	if (!constraint) {
		*perms = NULL;
		*num_perms = 0;
		return STATUS_ERR;
	}
	return string_list_scopy(handle, constraint->perms,
				 constraint->num_perms, perms, num_perms);
}

int sepol_constraint_add_perm(sepol_handle_t *handle,
			      sepol_constraint_t *constraint, const char *perm)
{
	if (!constraint) {
		ERR(handle, "constraint is NULL");
		return STATUS_ERR;
	}
	return string_list_add_unique(handle, &constraint->perms,
				      &constraint->num_perms, perm);
}

int sepol_constraint_del_perm(sepol_handle_t *handle,
			      sepol_constraint_t *constraint, const char *perm)
{
	if (!constraint) {
		ERR(handle, "constraint is NULL");
		return STATUS_ERR;
	}
	return string_list_del(constraint->perms, &constraint->num_perms, perm);
}

/* Constraint sub expresessions */
int sepol_constraint_get_exprs(sepol_handle_t *handle,
			       const sepol_constraint_t *constraint,
			       const sepol_constraint_expr_t ***exprs,
			       uint32_t *num_exprs)
{
	if (!exprs || !num_exprs)
		return STATUS_ERR;
	if (!constraint) {
		*exprs = NULL;
		*num_exprs = 0;
		return STATUS_ERR;
	}

	if (constraint->num_exprs == 0) {
		*exprs = NULL;
		*num_exprs = 0;
		return STATUS_SUCCESS;
	}

	const sepol_constraint_expr_t **tmp = calloc(
		constraint->num_exprs, sizeof(const sepol_constraint_expr_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < constraint->num_exprs; i++)
		tmp[i] = constraint->exprs[i];

	*exprs = tmp;
	*num_exprs = constraint->num_exprs;

	return STATUS_SUCCESS;
}

int sepol_constraint_insert_expr(sepol_handle_t *handle,
				 sepol_constraint_t *constraint, uint32_t index,
				 sepol_constraint_expr_t *expr)
{
	if (!constraint || !expr) {
		ERR(handle, "constraint or expr is NULL");
		return STATUS_ERR;
	}
	if (index > constraint->num_exprs) {
		ERR(handle, "index out of bounds");
		return STATUS_ERR;
	}
	if (constraint->num_exprs == UINT32_MAX) {
		ERR(handle, "too many expressions");
		return STATUS_ERR;
	}
	sepol_constraint_expr_t **tmp_array =
		reallocarray(constraint->exprs, constraint->num_exprs + 1,
			     sizeof(sepol_constraint_expr_t *));
	if (!tmp_array) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	constraint->exprs = tmp_array;
	constraint->exprs[constraint->num_exprs] = NULL;

	constraint->num_exprs++;
	for (uint32_t i = 0; i < constraint->num_exprs; i++) {
		if (i >= index) {
			sepol_constraint_expr_t *tmp = constraint->exprs[i];
			constraint->exprs[i] = expr;
			expr = tmp;
		}
	}
	return STATUS_SUCCESS;
}

int sepol_constraint_remove_expr(sepol_handle_t *handle,
				 sepol_constraint_t *constraint, uint32_t index)
{
	if (!constraint) {
		ERR(handle, "constraint is NULL");
		return STATUS_ERR;
	}
	if (index >= constraint->num_exprs)
		return STATUS_ERR;

	sepol_constraint_expr_free(constraint->exprs[index]);

	for (uint32_t i = index; i < constraint->num_exprs - 1; i++)
		constraint->exprs[i] = constraint->exprs[i + 1];

	constraint->num_exprs--;
	return STATUS_SUCCESS;
}

/* Constraint expresessions */
int sepol_constraint_expr_create(sepol_handle_t *handle,
				 sepol_constraint_expr_t **expr_ptr)
{
	sepol_constraint_expr_t *tmp;

	if (!expr_ptr)
		return STATUS_ERR;

	tmp = malloc(sizeof(sepol_constraint_expr_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		*expr_ptr = NULL;
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_constraint_expr_t));
	*expr_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_clone(sepol_handle_t *handle,
				const sepol_constraint_expr_t *expr,
				sepol_constraint_expr_t **expr_ptr)
{
	if (!expr_ptr)
		return STATUS_ERR;
	if (!expr) {
		*expr_ptr = NULL;
		return STATUS_ERR;
	}

	sepol_constraint_expr_t *tmp;
	if (sepol_constraint_expr_create(handle, &tmp)) {
		*expr_ptr = NULL;
		return STATUS_ERR;
	}

	tmp->expr_type = expr->expr_type;
	tmp->attr = expr->attr;
	tmp->op = expr->op;
	for (uint32_t i = 0; i < expr->num_names; i++) {
		if (sepol_constraint_expr_add_name(handle, tmp, expr->names[i]))
			goto err;
	}
	*expr_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_constraint_expr_free(tmp);
	*expr_ptr = NULL;
	return STATUS_ERR;
}

void sepol_constraint_expr_free(sepol_constraint_expr_t *expr)
{
	if (!expr)
		return;

	for (uint32_t i = 0; i < expr->num_names; i++)
		free(expr->names[i]);
	free(expr->names);
	free(expr);
}

/* Constraint expr type */
uint32_t sepol_constraint_expr_get_type(const sepol_constraint_expr_t *expr)
{
	return expr ? expr->expr_type : 0;
}

int sepol_constraint_expr_set_type(sepol_handle_t *handle,
				   sepol_constraint_expr_t *expr, uint32_t type)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	expr->expr_type = type;
	return STATUS_SUCCESS;
}

/* Constraint expr attr */
int sepol_constraint_expr_has_attr(const sepol_constraint_expr_t *expr,
				   uint32_t attr)
{
	return expr ? (expr->attr & attr) != 0 : 0;
}

int sepol_constraint_expr_set_attr(sepol_handle_t *handle,
				   sepol_constraint_expr_t *expr, uint32_t attr)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	expr->attr |= attr;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_unset_attr(sepol_handle_t *handle,
				     sepol_constraint_expr_t *expr,
				     uint32_t attr)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	expr->attr &= ~attr;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_clear_attr(sepol_handle_t *handle,
				     sepol_constraint_expr_t *expr)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	expr->attr = 0;
	return STATUS_SUCCESS;
}

/* Constraint expr attr or names operator */
uint32_t sepol_constraint_expr_get_op(const sepol_constraint_expr_t *expr)
{
	return expr ? expr->op : 0;
}

int sepol_constraint_expr_set_op(sepol_handle_t *handle,
				 sepol_constraint_expr_t *expr, uint32_t op)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	expr->op = op;
	return STATUS_SUCCESS;
}

/* Constraint names */
int sepol_constraint_expr_has_name(const sepol_constraint_expr_t *expr,
				   const char *name)
{
	if (!expr)
		return 0;
	return string_list_contains(expr->names, expr->num_names, name);
}

int sepol_constraint_expr_get_names(sepol_handle_t *handle,
				    const sepol_constraint_expr_t *expr,
				    const char ***names, uint32_t *num_names)
{
	if (!names || !num_names)
		return STATUS_ERR;
	if (!expr) {
		*names = NULL;
		*num_names = 0;
		return STATUS_ERR;
	}
	return string_list_scopy(handle, expr->names, expr->num_names, names,
				 num_names);
}

int sepol_constraint_expr_add_name(sepol_handle_t *handle,
				   sepol_constraint_expr_t *expr,
				   const char *name)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	return string_list_add_unique(handle, &expr->names, &expr->num_names,
				      name);
}

int sepol_constraint_expr_del_name(sepol_handle_t *handle,
				   sepol_constraint_expr_t *expr,
				   const char *name)
{
	if (!expr) {
		ERR(handle, "expr is NULL");
		return STATUS_ERR;
	}
	return string_list_del(expr->names, &expr->num_names, name);
}

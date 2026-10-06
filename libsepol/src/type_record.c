#include <sepol/type_record.h>

#include <stdlib.h>
#include <string.h>

#include "sepol/policydb/util.h"
#include "debug.h"

struct sepol_type {
	/* This type's name */
	char *name;

	/* This type's flavor */
	uint32_t flavor;
	/* This type attribute's subtypes */
	uint32_t num_types;
	char **types;
	/* This type's flags */
	uint32_t flags;

	/* This type's bounds type, if exists */
	char *bounds;

	/* This alias' primary type name */
	char *alias_of;
};

struct sepol_type_key {
	/* This type's name */
	char *name;
};

int sepol_type_key_create(sepol_handle_t *handle, const char *name,
			  sepol_type_key_t **key_ptr)
{
	if (!key_ptr)
		return STATUS_ERR;
	if (!name) {
		ERR(handle, "name is NULL");
		*key_ptr = NULL;
		return STATUS_ERR;
	}
	sepol_type_key_t *tmp_key = malloc(sizeof(sepol_type_key_t));

	if (!tmp_key) {
		ERR(handle, "out of memory, could not create selinux type key");
		*key_ptr = NULL;
		return STATUS_ERR;
	}

	tmp_key->name = strdup(name);
	if (!tmp_key->name) {
		ERR(handle, "out of memory, could not create selinux type key");
		free(tmp_key);
		*key_ptr = NULL;
		return STATUS_ERR;
	}

	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}

void sepol_type_key_unpack(const sepol_type_key_t *key, const char **name)
{
	*name = key ? key->name : NULL;
}

int sepol_type_key_extract(sepol_handle_t *handle, const sepol_type_t *type,
			   sepol_type_key_t **key_ptr)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	if (!type->name) {
		ERR(handle, "type name is NULL");
		return STATUS_ERR;
	}
	if (sepol_type_key_create(handle, type->name, key_ptr) < 0)
		return STATUS_ERR;
	return STATUS_SUCCESS;
}

void sepol_type_key_free(sepol_type_key_t *key)
{
	if (!key)
		return;
	free(key->name);
	free(key);
}

int sepol_type_compare(const sepol_type_t *type, const sepol_type_key_t *key)
{
	if (!type || !key || !type->name || !key->name)
		return -1;
	return strcmp(type->name, key->name);
}

int sepol_type_compare2(const sepol_type_t *type, const sepol_type_t *type2)
{
	if (!type || !type2 || !type->name || !type2->name)
		return -1;
	return strcmp(type->name, type2->name);
}

/* Name */
const char *sepol_type_get_name(const sepol_type_t *type)
{
	return type ? type->name : NULL;
}

int sepol_type_set_name(sepol_handle_t *handle, sepol_type_t *type,
			const char *name)
{
	if (!type || !name) {
		ERR(handle, "type or name is NULL");
		return STATUS_ERR;
	}
	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory, could not set name");
		return STATUS_ERR;
	}
	free(type->name);
	type->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Flavor */
uint32_t sepol_type_get_flavor(const sepol_type_t *type)
{
	return type ? type->flavor : 0;
}

int sepol_type_set_flavor(sepol_handle_t *handle, sepol_type_t *type,
			  uint32_t flavor)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	type->flavor = flavor;
	return STATUS_SUCCESS;
}

/* Subtypes/Attributes */
int sepol_type_has_subtype(const sepol_type_t *type, const char *subtype)
{
	if (!type)
		return 0;
	return string_list_contains(type->types, type->num_types, subtype);
}

int sepol_type_get_subtypes(sepol_handle_t *handle, const sepol_type_t *type,
			    const char ***subtypes, uint32_t *num_subtypes)
{
	if (!subtypes || !num_subtypes)
		return STATUS_ERR;
	if (!type) {
		*subtypes = NULL;
		*num_subtypes = 0;
		return STATUS_ERR;
	}

	return string_list_scopy(handle, type->types, type->num_types, subtypes,
				 num_subtypes);
}

int sepol_type_add_subtype(sepol_handle_t *handle, sepol_type_t *type,
			   const char *subtype)
{
	if (!type || !subtype)
		return STATUS_ERR;

	if (sepol_type_has_subtype(type, subtype))
		return STATUS_SUCCESS;

	return string_list_add(handle, &type->types, &type->num_types, subtype);
}

int sepol_type_del_subtype(sepol_handle_t *handle __attribute__((unused)),
			   sepol_type_t *type, const char *subtype)
{
	if (!type || !subtype)
		return STATUS_ERR;

	return string_list_del(type->types, &type->num_types, subtype);
}

/* Flags */
int sepol_type_has_flag(const sepol_type_t *type, uint32_t flag)
{
	if (!type)
		return 0;
	return (type->flags & flag) != 0;
}

int sepol_type_set_flag(sepol_handle_t *handle, sepol_type_t *type,
			uint32_t flag)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	type->flags |= flag;
	return STATUS_SUCCESS;
}

int sepol_type_unset_flag(sepol_handle_t *handle, sepol_type_t *type,
			  uint32_t flag)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	type->flags &= ~flag;
	return STATUS_SUCCESS;
}

/* Aliases */
const char *sepol_type_get_alias_of(const sepol_type_t *type)
{
	return type ? type->alias_of : NULL;
}

int sepol_type_set_alias_of(sepol_handle_t *handle, sepol_type_t *type,
			    const char *name)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	if (!name) {
		free(type->alias_of);
		type->alias_of = NULL;
		return STATUS_SUCCESS;
	}
	char *tmp = strdup(name);
	if (!tmp) {
		ERR(handle,
		    "out of memory, cannot set selinux alias primary type name");
		return STATUS_ERR;
	}
	free(type->alias_of);
	type->alias_of = tmp;
	return STATUS_SUCCESS;
}

/* Bounds */
const char *sepol_type_get_bounds(const sepol_type_t *type)
{
	return type ? type->bounds : NULL;
}

int sepol_type_set_bounds(sepol_handle_t *handle, sepol_type_t *type,
			  const char *bounds)
{
	if (!type) {
		ERR(handle, "type is NULL");
		return STATUS_ERR;
	}
	if (!bounds) {
		free(type->bounds);
		type->bounds = NULL;
		return STATUS_SUCCESS;
	}
	char *tmp = strdup(bounds);
	if (!tmp) {
		ERR(handle,
		    "out of memory, cannot set selinux type bounds name");
		return STATUS_ERR;
	}
	free(type->bounds);
	type->bounds = tmp;
	return STATUS_SUCCESS;
}

/* Create/Clone/Destroy */
int sepol_type_create(sepol_handle_t *handle, sepol_type_t **type_ptr)
{
	sepol_type_t *tmp;

	if (!type_ptr)
		return STATUS_ERR;

	tmp = malloc(sizeof(sepol_type_t));
	if (!tmp) {
		ERR(handle, "out of memory, could not create type record");
		*type_ptr = NULL;
		return STATUS_ERR;
	}

	memset(tmp, 0, sizeof(sepol_type_t));
	*type_ptr = tmp;

	return STATUS_SUCCESS;
}

int sepol_type_clone(sepol_handle_t *handle, const sepol_type_t *type,
		     sepol_type_t **type_ptr)
{
	if (!type_ptr)
		return STATUS_ERR;
	if (!type) {
		*type_ptr = NULL;
		return STATUS_ERR;
	}

	sepol_type_t *tmp;
	if (sepol_type_create(handle, &tmp)) {
		*type_ptr = NULL;
		return STATUS_ERR;
	}

	if (sepol_type_set_name(handle, tmp, type->name))
		goto err;
	if (type->bounds && sepol_type_set_bounds(handle, tmp, type->bounds))
		goto err;
	if (type->alias_of &&
	    sepol_type_set_alias_of(handle, tmp, type->alias_of))
		goto err;
	for (size_t i = 0; i < type->num_types; i++) {
		if (sepol_type_add_subtype(handle, tmp, type->types[i]))
			goto err;
	}
	tmp->flags = type->flags;
	if (sepol_type_set_flavor(handle, tmp, type->flavor))
		goto err;

	*type_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_type_free(tmp);
	*type_ptr = NULL;
	return STATUS_ERR;
}

void sepol_type_free(sepol_type_t *type)
{
	if (!type)
		return;

	free(type->name);
	for (size_t i = 0; i < type->num_types; i++)
		free(type->types[i]);
	free(type->types);
	free(type->bounds);
	free(type->alias_of);
	free(type);
}

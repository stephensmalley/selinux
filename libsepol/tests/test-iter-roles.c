#include "test-iter-roles.h"

#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/role_record.h>
#include <sepol/roles.h>

#include "helpers.h"

extern sepol_handle_t *handle;
extern sepol_policydb_t *empty_policy;
extern sepol_policydb_t *iter_policy;

struct expected_role {
	int seen;

	const char *name;
	uint32_t ntypes;
	const char *types[32]; /* authorized types */
	char *bounds; /* bounded role */
	uint32_t flavor; /* role or attribute */
	uint32_t nsubroles;
	const char *subroles[32]; /* roles within attribute */
};

struct expected_role expected_roles[] = {
	{ 0, "ROLE1", 1, { "TYPE1" }, NULL, SEPOL_ROLE_ROLE, 0, {} },
	{ 0, "ROLE2", 1, { "TYPE2" }, NULL, SEPOL_ROLE_ROLE, 0, {} },
	/*
	 * ROLE3's types are declared as "{ ATTR1 -TYPE3 }" (iter.conf), where
	 * ATTR1 itself has members { TYPE2, TYPE3 }. This only resolves to
	 * the correct authorized type set, { TYPE2 }, if the attribute
	 * membership is expanded and the negset subtraction is applied
	 * (type_set_expand()); naively reading type_set_t.types verbatim
	 * would instead report a single bogus "type" named "ATTR1".
	 */
	{ 0, "ROLE3", 1, { "TYPE2" }, NULL, SEPOL_ROLE_ROLE, 0, {} },
	{ 0,
	  "ATTR_ROLE1",
	  0,
	  {},
	  NULL,
	  SEPOL_ROLE_ATTRIB,
	  2,
	  { "ROLE1", "ROLE2" } },
	{ 0, "object_r", 0, {}, NULL, SEPOL_ROLE_ROLE, 0, {} },
	{ 0, NULL, 0, {}, NULL, 0, 0, {} },
};

static void unseen(void)
{
	for (struct expected_role *e = expected_roles; e->name; e++) {
		e->seen = 0;
	}
}

static void seen(const sepol_role_t *item)
{
	const char *actual_name = sepol_role_get_name(item);
	uint32_t nactual_types;
	const char **actual_types;
	CU_ASSERT_EQUAL_FATAL(sepol_role_get_types(handle, item, &actual_types,
						   &nactual_types),
			      0);
	uint32_t actual_flavor = sepol_role_get_flavor(item);
	const char *actual_bounds = sepol_role_get_bounds(item);
	uint32_t nactual_subroles;
	const char **actual_subroles;
	CU_ASSERT_EQUAL_FATAL(sepol_role_get_subroles(handle, item,
						      &actual_subroles,
						      &nactual_subroles),
			      0);

	struct expected_role *e;
	for (e = expected_roles; e->name; e++) {
		if (strcmp(actual_name, e->name) == 0)
			break;
	}
	CU_ASSERT_PTR_NOT_NULL_FATAL(e->name);
	e->seen = 1;

	CU_ASSERT_EQUAL(nactual_types, e->ntypes);
	/* qsort()'s base is declared nonnull; skip the call entirely for
	 * an empty (possibly NULL) array rather than relying on nmemb==0
	 * making the NULL harmless. */
	if (nactual_types > 0)
		qsort(actual_types, nactual_types, sizeof(char *), qstrcmp);
	for (size_t i = 0; i < nactual_types && i < e->ntypes; i++) {
		CU_ASSERT_STRING_EQUAL(actual_types[i], e->types[i]);
	}

	CU_ASSERT_EQUAL(actual_flavor, e->flavor);

	CU_ASSERT_EQUAL(nactual_subroles, e->nsubroles);
	/* qsort()'s base is declared nonnull; skip the call entirely for
	 * an empty (possibly NULL) array rather than relying on nmemb==0
	 * making the NULL harmless. */
	if (nactual_subroles > 0)
		qsort(actual_subroles, nactual_subroles, sizeof(char *),
		      qstrcmp);
	for (size_t i = 0; i < nactual_subroles && i < e->nsubroles; i++) {
		CU_ASSERT_STRING_EQUAL(actual_subroles[i], e->subroles[i]);
	}

	if (e->bounds) {
		CU_ASSERT_STRING_EQUAL(actual_bounds, e->bounds);
	} else {
		CU_ASSERT_PTR_NULL(actual_bounds);
	}

	free(actual_types);
	free(actual_subroles);
}

void test_iter_roles_empty(void)
{
	sepol_role_iter_t *role_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_iter_create(handle, empty_policy, &role_iter), 0);

	/* object_r is always implicitly defined, so drain it */
	sepol_role_t *item;
	int count = 0;
	while (1) {
		CU_ASSERT_EQUAL_FATAL(
			sepol_role_iter_next(handle, role_iter, &item), 0);
		if (!item)
			break;
		sepol_role_free(item);
		count++;
	}
	CU_ASSERT(count <= 1);

	sepol_role_iter_destroy(role_iter);
}

void test_iter_roles_non_empty(void)
{
	unseen();
	sepol_role_t *item;
	sepol_role_iter_t *role_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_iter_create(handle, iter_policy, &role_iter), 0);

	while (1) {
		CU_ASSERT_EQUAL(sepol_role_iter_next(handle, role_iter, &item),
				0);
		if (!item)
			break;
		seen(item);
		sepol_role_free(item);
	}
	CU_ASSERT_EQUAL(sepol_role_iter_next(handle, role_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	for (struct expected_role *e = expected_roles; e->name; e++) {
		CU_ASSERT_TRUE(e->seen);
	}

	sepol_role_iter_destroy(role_iter);
}

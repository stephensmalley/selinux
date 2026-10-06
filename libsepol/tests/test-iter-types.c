#include "test-iter-types.h"

#include <CUnit/CUnit.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/type_record.h>
#include <sepol/types.h>

#include "helpers.h"

extern sepol_handle_t *handle;
extern sepol_policydb_t *empty_policy;
extern sepol_policydb_t *iter_policy;

struct expected_type {
	int seen;

	const char *name;
	const char *alias_of;
	uint32_t flavor;
	uint32_t flags;
	size_t nsubtypes;
	const char *subtypes[32];
};

struct expected_type expected_types[] = {
	{ 0, "TYPE1", NULL, SEPOL_TYPE_TYPE, SEPOL_TYPE_FLAGS_PERMISSIVE, 0, {} },
	{ 0, "TYPE2", NULL, SEPOL_TYPE_TYPE, 0, 0, {} },
	{ 0, "TYPE3", NULL, SEPOL_TYPE_TYPE, 0, 0, {} },
	{ 0, "ALIAS1", "TYPE1", SEPOL_TYPE_ALIAS, 0, 0, {} },
	{ 0, "ALIAS2", "TYPE3", SEPOL_TYPE_ALIAS, 0, 0, {} },
	{ 0, "ATTR1", NULL, SEPOL_TYPE_ATTRIB, 0, 2, { "TYPE2", "TYPE3" } },
	{ 0, NULL, NULL, 0, 0, 0, {} },
};

static void unseen(void)
{
	for (struct expected_type *e = expected_types; e->name; e++) {
		e->seen = 0;
	}
}

void test_iter_types_empty(void)
{
	sepol_type_iter_t *type_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_type_iter_create(handle, empty_policy, &type_iter), 0);

	sepol_type_t *item;
	CU_ASSERT_EQUAL(sepol_type_iter_next(handle, type_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);
	/* all values after end should return NULL as item */
	CU_ASSERT_EQUAL(sepol_type_iter_next(handle, type_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	sepol_type_iter_destroy(type_iter);
}

static void seen(const sepol_type_t *item)
{
	const char *actual_name = sepol_type_get_name(item);
	uint32_t actual_flavor = sepol_type_get_flavor(item);
	uint32_t nactual_subtypes;
	const char **actual_subtypes;
	CU_ASSERT_EQUAL_FATAL(sepol_type_get_subtypes(handle, item,
						      &actual_subtypes,
						      &nactual_subtypes),
			      0);
	const char *actual_alias_of = sepol_type_get_alias_of(item);

	struct expected_type *e;
	for (e = expected_types; e->name; e++) {
		if (strcmp(actual_name, e->name) == 0)
			break;
	}
	CU_ASSERT_PTR_NOT_NULL_FATAL(e->name);
	e->seen = 1;

	CU_ASSERT_EQUAL(actual_flavor, e->flavor);

	for (size_t i = 0; i < sizeof(uint32_t) * CHAR_BIT; i++) {
		if ((1u << i) & e->flags) {
			CU_ASSERT_TRUE(sepol_type_has_flag(item, 1u << i));
		} else {
			CU_ASSERT_FALSE(sepol_type_has_flag(item, 1u << i));
		}
	}

	CU_ASSERT_EQUAL(nactual_subtypes, e->nsubtypes);
	/* qsort()'s base is declared nonnull; skip the call entirely for
	 * an empty (possibly NULL) array rather than relying on nmemb==0
	 * making the NULL harmless. */
	if (nactual_subtypes > 0)
		qsort(actual_subtypes, nactual_subtypes, sizeof(char *),
		      qstrcmp);
	for (size_t i = 0; i < nactual_subtypes && i < e->nsubtypes; i++) {
		CU_ASSERT_STRING_EQUAL(actual_subtypes[i], e->subtypes[i]);
	}

	if (e->alias_of) {
		CU_ASSERT_STRING_EQUAL(actual_alias_of, e->alias_of);
	} else {
		CU_ASSERT_PTR_NULL(actual_alias_of);
	}

	free(actual_subtypes);
}

void test_iter_types_non_empty(void)
{
	unseen();
	sepol_type_t *item;
	sepol_type_iter_t *type_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_type_iter_create(handle, iter_policy, &type_iter), 0);

	while (1) {
		CU_ASSERT_EQUAL(sepol_type_iter_next(handle, type_iter, &item),
				0);
		if (!item)
			break;
		seen(item);
		sepol_type_free(item);
	}
	CU_ASSERT_EQUAL(sepol_type_iter_next(handle, type_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	for (struct expected_type *e = expected_types; e->name; e++) {
		CU_ASSERT_TRUE(e->seen);
	}

	sepol_type_iter_destroy(type_iter);
}

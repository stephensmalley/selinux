#include "test-iter-users.h"
#include "helpers.h"
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/types.h>
#include <sepol/user_record.h>
#include <sepol/users.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdlib.h>

extern sepol_handle_t *handle;
extern sepol_policydb_t *empty_policy;
extern sepol_policydb_t *iter_policy;

struct expected_user {
	int seen;

	const char *name;
	const char *mls_level;
	const char *mls_range;
	size_t nroles;
	const char *roles[32];
};

struct expected_user expected_users[] = {
	{ 0, "USER1", "s0", "s0-s0:c0.c3", 1, { "ROLE1" } },
	{ 0, NULL, NULL, NULL, 0, {} },
};

static void unseen(void)
{
	for (struct expected_user *e = expected_users; e->name; e++) {
		e->seen = 0;
	}
}

static void seen(sepol_user_t *item)
{
	const char *actual_name = sepol_user_get_name(item);
	const char *actual_mls_level = sepol_user_get_mlslevel(item);
	const char *actual_mls_range = sepol_user_get_mlsrange(item);
	uint32_t nactual_roles;
	const char **actual_roles;
	CU_ASSERT_EQUAL_FATAL(sepol_user_get_roles(handle, item, &actual_roles,
						   &nactual_roles),
			      0);

	struct expected_user *e;
	for (e = expected_users; e->name; e++) {
		if (!strcmp(actual_name, e->name))
			break;
	}
	CU_ASSERT_PTR_NOT_NULL_FATAL(e->name);
	e->seen = 1;

	if (iter_policy->p.mls) {
		CU_ASSERT_STRING_EQUAL(actual_mls_level, e->mls_level);
		CU_ASSERT_STRING_EQUAL(actual_mls_range, e->mls_range);
	}

	CU_ASSERT_EQUAL(nactual_roles, e->nroles);
	/* qsort()'s base is declared nonnull; skip the call entirely for
	 * an empty (possibly NULL) array rather than relying on nmemb==0
	 * making the NULL harmless. */
	if (nactual_roles > 0)
		qsort(actual_roles, nactual_roles, sizeof(char *), qstrcmp);
	for (size_t i = 0; i < nactual_roles && i < e->nroles; i++) {
		CU_ASSERT_STRING_EQUAL(actual_roles[i], e->roles[i]);
	}

	free(actual_roles);
}

void test_iter_users_empty(void)
{
	unseen();
	sepol_user_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_user_iter_create(handle, empty_policy, &iter), 0);

	sepol_user_t *item;
	CU_ASSERT_EQUAL(sepol_user_iter_next(handle, iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);
	/* all values after end should return NULL as item */
	CU_ASSERT_EQUAL(sepol_user_iter_next(handle, iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	sepol_user_iter_destroy(iter);
}

void test_iter_users_non_empty(void)
{
	unseen();
	sepol_user_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_user_iter_create(handle, iter_policy, &iter), 0);

	sepol_user_t *item;
	while (1) {
		CU_ASSERT_EQUAL(sepol_user_iter_next(handle, iter, &item), 0);
		if (!item)
			break;
		seen(item);
		sepol_user_free(item);
	}
	CU_ASSERT_EQUAL(sepol_user_iter_next(handle, iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	for (struct expected_user *e = expected_users; e->name; e++) {
		CU_ASSERT_TRUE(e->seen);
	}

	sepol_user_iter_destroy(iter);
}

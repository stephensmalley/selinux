#include "test-iter.h"

#include <CUnit/CUError.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/type_record.h>
#include <sepol/types.h>

#include "parse_util.h"
#include "test-iter-types.h"
#include "test-iter-users.h"
#include "test-iter-roles.h"
#include "test-iter-classes.h"

extern int mls;

sepol_handle_t *handle;
sepol_policydb_t *empty_policy;
sepol_policydb_t *iter_policy;

struct policy_entry {
	sepol_policydb_t **sepol_policy;
	const char *name;
};

struct policy_entry entries[] = {
	{ .sepol_policy = &empty_policy, .name = NULL },
	{ .sepol_policy = &iter_policy, .name = "iter.conf" },
	{ .sepol_policy = NULL, .name = NULL },
};

int iter_test_init(void)
{
	handle = sepol_handle_create();
	if (!handle)
		return -1;

	for (struct policy_entry *entry = entries; entry->sepol_policy;
	     entry++) {
		if (sepol_policydb_create(entry->sepol_policy))
			goto err;
		policydb_t *pol = &(*entry->sepol_policy)->p;
		pol->policy_type = POLICY_BASE;
		pol->policyvers = MOD_POLICYDB_VERSION_MAX;
		pol->mls = mls;
		if (entry->name) {
			char filename[PATH_MAX] = { 0 };
			if (snprintf(filename, PATH_MAX,
				     "policies/test-iter/%s%s", entry->name,
				     mls ? ".mls" : ".std") < 0)
				goto err;
			if (read_source_policy(pol, filename, "test"))
				goto err;
		} else {
			if (policydb_index_classes(pol))
				goto err;
			if (policydb_index_others(handle, pol, 0))
				goto err;
		}
	}
	return 0;

err:
	for (struct policy_entry *entry = entries; entry->sepol_policy;
	     entry++) {
		if (*entry->sepol_policy) {
			sepol_policydb_free(*entry->sepol_policy);
			*entry->sepol_policy = NULL;
		}
	}
	sepol_handle_destroy(handle);
	handle = NULL;
	return -1;
}

int iter_test_cleanup(void)
{
	for (struct policy_entry *entry = entries; entry->sepol_policy;
	     entry++) {
		sepol_policydb_free(*entry->sepol_policy);
	}
	sepol_handle_destroy(handle);

	return 0;
}

int iter_add_tests(CU_pSuite suite)
{
	if (CU_add_test(suite, "iter_types_empty", test_iter_types_empty) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_types_non_empty",
			test_iter_types_non_empty) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_users_empty", test_iter_users_empty) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_users_non_empty",
			test_iter_users_non_empty) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_roles_empty", test_iter_roles_empty) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_roles_non_empty",
			test_iter_roles_non_empty) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_classes_empty", test_iter_classes_empty) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_classes_non_empty",
			test_iter_classes_non_empty) == NULL)
		return CU_get_error();
	return 0;
}

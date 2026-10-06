#include "test-tier2.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include <sepol/booleans.h>
#include <sepol/cat_set.h>
#include <sepol/classes.h>
#include <sepol/common_perm.h>
#include <sepol/filename_trans.h>
#include <sepol/users.h>
#include <sepol/constants.h>
#include <sepol/handle.h>
#include <sepol/mls_iter.h>
#include <sepol/ocontext.h>
#include <sepol/permissive.h>
#include <sepol/polcap.h>
#include <sepol/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/policydb.h>
#include <sepol/range_trans.h>
#include <sepol/role_rule.h>
#include <sepol/roles.h>
#include <sepol/types.h>

#include "parse_util.h"

extern int mls;

static sepol_handle_t *handle;
static sepol_policydb_t *policy;
static policydb_t basemod;

/* Drains and destroys a category-set iterator returned by one of the
 * ocontext `_get_mls_range_{low,high}_cat()` getters, sanity-checking
 * that iteration itself is well-formed. The fixture's ocontext entries
 * all use a bare `s0` MLS level (no explicit category list), so the
 * iterator is expected to be empty; this only exercises the
 * create/next/destroy plumbing for the getter in question. */
static void drain_cat_iter(sepol_cat_set_iter_t *cat_iter)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(cat_iter);
	uint32_t cat_val;
	CU_ASSERT_EQUAL(sepol_cat_set_iter_next(handle, cat_iter, &cat_val), 0);
	sepol_cat_set_iter_destroy(cat_iter);
}

int tier2_test_init(void)
{
	char filename[PATH_MAX];
	int basemod_inited = 0;

	handle = sepol_handle_create();
	if (!handle)
		return -1;

	if (sepol_policydb_create(&policy)) {
		sepol_handle_destroy(handle);
		handle = NULL;
		return -1;
	}

	if (policydb_init(&basemod))
		goto err;
	basemod_inited = 1;

	basemod.policy_type = POLICY_BASE;
	basemod.policyvers = MOD_POLICYDB_VERSION_MAX;
	basemod.mls = mls;

	if (snprintf(filename, PATH_MAX, "policies/test-iter/%s%s", "iter.conf",
		     mls ? ".mls" : ".std") < 0)
		goto err;

	if (read_source_policy(&basemod, filename, "test-tier2"))
		goto err;

	if (link_modules(NULL, &basemod, NULL, 0, 0))
		goto err;

	if (expand_module(NULL, &basemod, &policy->p, 0, 0))
		goto err;

	return 0;

err:
	if (basemod_inited)
		policydb_destroy(&basemod);
	sepol_policydb_free(policy);
	policy = NULL;
	sepol_handle_destroy(handle);
	handle = NULL;
	return -1;
}

int tier2_test_cleanup(void)
{
	sepol_policydb_free(policy);
	policydb_destroy(&basemod);
	sepol_handle_destroy(handle);
	return 0;
}

static uint32_t role_value(const char *name)
{
	role_datum_t *d = hashtab_search(policy->p.p_roles.table, name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	return d->s.value;
}

static uint32_t type_value(const char *name)
{
	type_datum_t *d = hashtab_search(policy->p.p_types.table, name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	return d->s.value;
}

static uint32_t class_value(const char *name)
{
	class_datum_t *d = hashtab_search(policy->p.p_classes.table, name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	return d->s.value;
}

static uint32_t user_value(const char *name)
{
	user_datum_t *d = hashtab_search(policy->p.p_users.table, name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	return d->s.value;
}

static uint32_t perm_value(const class_datum_t *cls, const char *name)
{
	perm_datum_t *d = hashtab_search(cls->permissions.table, name);
	if (!d && cls->comdatum)
		d = hashtab_search(cls->comdatum->permissions.table, name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	return d->s.value;
}

static void test_role_allow_iter(void)
{
	sepol_role_allow_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_allow_iter_create(handle, policy, &iter), 0);

	uint32_t role1_val = role_value("ROLE1");
	uint32_t role2_val = role_value("ROLE2");
	uint32_t role, new_role;
	int count = 0, found = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_role_allow_iter_next(
					      handle, iter, &role, &new_role),
				      0);
		if (role == 0)
			break;
		count++;
		if (role == role1_val && new_role == role2_val)
			found = 1;
	}
	CU_ASSERT(count >= 1);
	CU_ASSERT(found);

	sepol_role_allow_iter_destroy(iter);
}

static void test_role_trans_iter(void)
{
	sepol_role_trans_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_trans_iter_create(handle, policy, &iter), 0);

	uint32_t role1_val = role_value("ROLE1");
	uint32_t type1_val = type_value("TYPE1");
	uint32_t class01_val = class_value("CLASS01");
	uint32_t role2_val = role_value("ROLE2");
	uint32_t role, type, tclass, new_role;
	int count = 0, found = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(
			sepol_role_trans_iter_next(handle, iter, &role, &type,
						   &tclass, &new_role),
			0);
		if (role == 0)
			break;
		count++;
		if (role == role1_val && type == type1_val &&
		    tclass == class01_val && new_role == role2_val)
			found = 1;
	}
	CU_ASSERT(count >= 1);
	CU_ASSERT(found);

	sepol_role_trans_iter_destroy(iter);
}

static void test_filename_trans_iter(void)
{
	sepol_filename_trans_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_filename_trans_iter_create(handle, policy, &iter), 0);

	uint32_t type1_val = type_value("TYPE1");
	uint32_t type2_val = type_value("TYPE2");
	uint32_t type3_val = type_value("TYPE3");
	uint32_t class01_val = class_value("CLASS01");
	uint32_t source_type, target_type, target_class, default_type;
	const char *filename;
	int count = 0, found = 0;

	/*
	 * iter.conf declares a single named filename transition:
	 *   type_transition TYPE1 TYPE3 : CLASS01 TYPE2 "testfile";
	 * i.e. source=TYPE1, target=TYPE3, class=CLASS01, name="testfile",
	 * default_type=TYPE2. The other (unnamed) type_transition rules in
	 * the fixture are plain type-transition av rules, not filename
	 * transitions, and must not show up here.
	 */
	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_filename_trans_iter_next(
					      handle, iter, &source_type,
					      &target_type, &target_class,
					      &filename, &default_type),
				      0);
		if (source_type == 0) {
			CU_ASSERT_PTR_NULL(filename);
			break;
		}
		count++;
		CU_ASSERT_PTR_NOT_NULL_FATAL(filename);
		if (source_type == type1_val && target_type == type3_val &&
		    target_class == class01_val && default_type == type2_val &&
		    strcmp(filename, "testfile") == 0)
			found = 1;
	}
	CU_ASSERT_EQUAL(count, 1);
	CU_ASSERT(found);

	sepol_filename_trans_iter_destroy(iter);
}

static void test_range_trans_iter(void)
{
	sepol_range_trans_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_range_trans_iter_create(handle, policy, &iter), 0);

	uint32_t source_type, target_type, target_class;
	int count = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_range_trans_iter_next(
					      handle, iter, &source_type,
					      &target_type, &target_class),
				      0);
		if (source_type == 0)
			break;
		count++;

		uint32_t low_sens = sepol_range_trans_iter_get_low_sens(iter);
		uint32_t high_sens = sepol_range_trans_iter_get_high_sens(iter);
		CU_ASSERT(low_sens > 0);
		CU_ASSERT(high_sens > 0);
		CU_ASSERT(high_sens >= low_sens);
	}

	if (mls) {
		CU_ASSERT(count >= 1);
	} else {
		CU_ASSERT_EQUAL(count, 0);
	}

	sepol_range_trans_iter_destroy(iter);
}

static void test_isid_iter(void)
{
	sepol_isid_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_isid_iter_create(handle, policy, &iter), 0);

	uint32_t sid;
	int count = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_isid_iter_next(handle, iter, &sid),
				      0);
		if (sid == 0)
			break;
		count++;

		uint32_t user = sepol_isid_iter_get_context_user(iter);
		uint32_t role = sepol_isid_iter_get_context_role(iter);
		uint32_t type = sepol_isid_iter_get_context_type(iter);
		CU_ASSERT(user > 0);
		CU_ASSERT(role > 0);
		CU_ASSERT(type > 0);

		if (mls) {
			uint32_t low_sens =
				sepol_isid_iter_get_mls_range_low_sens(iter);
			CU_ASSERT(low_sens > 0);
		}
	}
	CU_ASSERT(count >= 1);

	sepol_isid_iter_destroy(iter);
}

static void test_fsuse_iter(void)
{
	sepol_fsuse_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_fsuse_iter_create(handle, policy, &iter),
			      0);

	const char *name;
	uint32_t behavior;
	int found_ext3 = 0, found_devpts = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_fsuse_iter_next(handle, iter, &name,
							    &behavior),
				      0);
		if (!name)
			break;

		uint32_t user = sepol_fsuse_iter_get_context_user(iter);
		CU_ASSERT(user > 0);

		if (strcmp(name, "ext3") == 0) {
			found_ext3 = 1;
			CU_ASSERT_EQUAL(behavior, SECURITY_FS_USE_XATTR);
		}
		if (strcmp(name, "devpts") == 0) {
			found_devpts = 1;
			CU_ASSERT_EQUAL(behavior, SECURITY_FS_USE_TRANS);
		}
	}
	CU_ASSERT(found_ext3);
	CU_ASSERT(found_devpts);

	sepol_fsuse_iter_destroy(iter);
}

static void test_genfscon_iter(void)
{
	sepol_genfscon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_genfscon_iter_create(handle, policy, &iter),
			      0);

	const char *fstype, *path;
	uint32_t sclass;
	int found_root = 0, found_sys = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_genfscon_iter_next(handle, iter,
							       &fstype, &path,
							       &sclass),
				      0);
		if (!fstype)
			break;

		uint32_t user = sepol_genfscon_iter_get_context_user(iter);
		uint32_t type = sepol_genfscon_iter_get_context_type(iter);
		CU_ASSERT(user > 0);
		CU_ASSERT(type > 0);

		if (strcmp(fstype, "proc") == 0) {
			if (strcmp(path, "/") == 0)
				found_root = 1;
			if (strcmp(path, "/sys") == 0)
				found_sys = 1;
		}
	}
	CU_ASSERT(found_root);
	CU_ASSERT(found_sys);

	sepol_genfscon_iter_destroy(iter);
}

static void test_polcap_iter(void)
{
	sepol_polcap_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_polcap_iter_create(handle, policy, &iter),
			      0);

	uint32_t cap_num;
	const char *cap_name;
	int found_netpeer = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_polcap_iter_next(handle, iter,
							     &cap_num,
							     &cap_name),
				      0);
		if (!cap_name)
			break;
		if (strcmp(cap_name, "network_peer_controls") == 0)
			found_netpeer = 1;
	}
	CU_ASSERT(found_netpeer);

	sepol_polcap_iter_destroy(iter);
}

static void test_common_iter(void)
{
	sepol_common_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_common_iter_create(handle, policy, &iter),
			      0);

	const char *name;
	uint32_t value;
	int found_common1 = 0;
	uint32_t common1_value = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(
			sepol_common_iter_next(handle, iter, &name, &value), 0);
		if (!name)
			break;
		CU_ASSERT(value > 0);
		if (strcmp(name, "COMMON1") == 0) {
			found_common1 = 1;
			common1_value = value;
		}
	}
	CU_ASSERT(found_common1);
	sepol_common_iter_destroy(iter);

	if (!found_common1)
		return;

	sepol_common_perm_iter_t *piter;
	CU_ASSERT_EQUAL_FATAL(sepol_common_perm_iter_create(
				      handle, policy, common1_value, &piter),
			      0);

	const char *perm_name;
	int found_commonperm1 = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_common_perm_iter_next(handle, piter,
								  &perm_name),
				      0);
		if (!perm_name)
			break;
		if (strcmp(perm_name, "COMMONPERM1") == 0)
			found_commonperm1 = 1;
	}
	CU_ASSERT(found_commonperm1);
	sepol_common_perm_iter_destroy(piter);
}

static void test_cat_iter(void)
{
	sepol_cat_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_cat_iter_create(handle, policy, &iter), 0);

	const char *name;
	uint32_t value;
	int isalias;
	int count = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_cat_iter_next(handle, iter, &name,
							  &value, &isalias),
				      0);
		if (!name)
			break;
		CU_ASSERT(value > 0);
		count++;
	}

	if (mls) {
		CU_ASSERT(count >= 4);
	} else {
		CU_ASSERT_EQUAL(count, 0);
	}

	sepol_cat_iter_destroy(iter);
}

static void test_sens_iter(void)
{
	sepol_sens_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_sens_iter_create(handle, policy, &iter), 0);

	const char *name;
	uint32_t sens_value;
	int isalias;
	int count = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_sens_iter_next(handle, iter, &name,
							   &sens_value,
							   &isalias),
				      0);
		if (!name)
			break;
		CU_ASSERT(sens_value > 0);
		count++;

		sepol_cat_set_iter_t *cat_iter = NULL;
		CU_ASSERT_EQUAL_FATAL(
			sepol_sens_iter_get_level_cat(handle, iter, &cat_iter),
			0);
		CU_ASSERT_PTR_NOT_NULL(cat_iter);
		sepol_cat_set_iter_destroy(cat_iter);
	}

	if (mls) {
		CU_ASSERT(count >= 1);
	} else {
		CU_ASSERT_EQUAL(count, 0);
	}

	sepol_sens_iter_destroy(iter);
}

static void test_permissive_iter(void)
{
	sepol_permissive_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_permissive_iter_create(handle, policy, &iter), 0);

	uint32_t type1_val = type_value("TYPE1");
	uint32_t type_val;
	int found_type1 = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(
			sepol_permissive_iter_next(handle, iter, &type_val), 0);
		if (type_val == 0)
			break;
		if (type_val == type1_val)
			found_type1 = 1;
	}
	CU_ASSERT(found_type1);

	sepol_permissive_iter_destroy(iter);
}

static void test_range_trans_mls_cat(void)
{
	if (!mls)
		return;

	sepol_range_trans_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_range_trans_iter_create(handle, policy, &iter), 0);

	uint32_t src, tgt, cls;
	int found_with_cats = 0;

	/*
	 * Asserts inside this loop are intentionally non-fatal: a
	 * CU_ASSERT_*_FATAL() here would longjmp out of the function on the
	 * first failure and skip both sepol_cat_set_iter_destroy() calls
	 * below and the final sepol_range_trans_iter_destroy(), leaking the
	 * iterator(s) on top of the reported assertion failure. Guard every
	 * subsequent dereference with an explicit check instead so the loop
	 * (and the destroys) can still terminate safely.
	 */
	while (1) {
		int rc = sepol_range_trans_iter_next(handle, iter, &src, &tgt,
						     &cls);
		CU_ASSERT_EQUAL(rc, 0);
		if (rc != 0 || src == 0)
			break;

		sepol_cat_set_iter_t *high_cat = NULL;
		CU_ASSERT_EQUAL(sepol_range_trans_iter_get_high_cat(iter,
								    &high_cat),
				0);
		CU_ASSERT_PTR_NOT_NULL(high_cat);
		if (high_cat) {
			uint32_t cat_val;
			CU_ASSERT_EQUAL(sepol_cat_set_iter_next(
						handle, high_cat, &cat_val),
					0);
			if (cat_val > 0)
				found_with_cats = 1;
			sepol_cat_set_iter_destroy(high_cat);
		}

		sepol_cat_set_iter_t *low_cat = NULL;
		CU_ASSERT_EQUAL(
			sepol_range_trans_iter_get_low_cat(iter, &low_cat), 0);
		CU_ASSERT_PTR_NOT_NULL(low_cat);
		if (low_cat)
			sepol_cat_set_iter_destroy(low_cat);
	}
	CU_ASSERT(found_with_cats);

	sepol_range_trans_iter_destroy(iter);
}

static void test_fsuse_context_values(void)
{
	sepol_fsuse_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_fsuse_iter_create(handle, policy, &iter),
			      0);

	uint32_t user1_val = hashtab_search(policy->p.p_users.table, "USER1") ?
				     ((user_datum_t *)hashtab_search(
					      policy->p.p_users.table, "USER1"))
					     ->s.value :
				     0;
	uint32_t role1_val = role_value("ROLE1");
	uint32_t type1_val = type_value("TYPE1");

	const char *name;
	uint32_t behavior;
	int found = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_fsuse_iter_next(handle, iter, &name,
							    &behavior),
				      0);
		if (!name)
			break;

		if (strcmp(name, "ext3") == 0) {
			found = 1;
			CU_ASSERT_EQUAL(sepol_fsuse_iter_get_context_user(iter),
					user1_val);
			CU_ASSERT_EQUAL(sepol_fsuse_iter_get_context_role(iter),
					role1_val);
			CU_ASSERT_EQUAL(sepol_fsuse_iter_get_context_type(iter),
					type1_val);

			if (mls) {
				uint32_t low_sens =
					sepol_fsuse_iter_get_mls_range_low_sens(
						iter);
				CU_ASSERT(low_sens > 0);
				CU_ASSERT_EQUAL(
					sepol_fsuse_iter_get_mls_range_high_sens(
						iter),
					low_sens);

				sepol_cat_set_iter_t *low_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_fsuse_iter_get_mls_range_low_cat(
						iter, &low_cat),
					0);
				drain_cat_iter(low_cat);

				sepol_cat_set_iter_t *high_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_fsuse_iter_get_mls_range_high_cat(
						iter, &high_cat),
					0);
				drain_cat_iter(high_cat);
			}
		}
	}
	CU_ASSERT(found);

	sepol_fsuse_iter_destroy(iter);
}

static void test_genfscon_context_values(void)
{
	sepol_genfscon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_genfscon_iter_create(handle, policy, &iter),
			      0);

	uint32_t type1_val = type_value("TYPE1");

	const char *fstype, *path;
	uint32_t sclass;
	int found = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_genfscon_iter_next(handle, iter,
							       &fstype, &path,
							       &sclass),
				      0);
		if (!fstype)
			break;

		if (strcmp(fstype, "proc") == 0 && strcmp(path, "/") == 0) {
			found = 1;
			CU_ASSERT_EQUAL(
				sepol_genfscon_iter_get_context_type(iter),
				type1_val);
			CU_ASSERT(sepol_genfscon_iter_get_context_user(iter) >
				  0);
			CU_ASSERT(sepol_genfscon_iter_get_context_role(iter) >
				  0);

			if (mls) {
				uint32_t low_sens =
					sepol_genfscon_iter_get_mls_range_low_sens(
						iter);
				CU_ASSERT(low_sens > 0);
				CU_ASSERT_EQUAL(
					sepol_genfscon_iter_get_mls_range_high_sens(
						iter),
					low_sens);

				sepol_cat_set_iter_t *low_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_genfscon_iter_get_mls_range_low_cat(
						iter, &low_cat),
					0);
				drain_cat_iter(low_cat);

				sepol_cat_set_iter_t *high_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_genfscon_iter_get_mls_range_high_cat(
						iter, &high_cat),
					0);
				drain_cat_iter(high_cat);
			}
		}
	}
	CU_ASSERT(found);

	sepol_genfscon_iter_destroy(iter);
}

static void test_sens_level_cat_bits(void)
{
	if (!mls)
		return;

	sepol_sens_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_sens_iter_create(handle, policy, &iter), 0);

	const char *name;
	uint32_t sens_value;
	int isalias;
	int found_s0 = 0;

	/*
	 * As in test_range_trans_mls_cat() above, asserts in this loop are
	 * intentionally non-fatal so a failure can't skip
	 * sepol_cat_set_iter_destroy()/sepol_sens_iter_destroy() and leak
	 * the iterator(s).
	 */
	while (1) {
		int rc = sepol_sens_iter_next(handle, iter, &name, &sens_value,
					      &isalias);
		CU_ASSERT_EQUAL(rc, 0);
		if (rc != 0 || !name)
			break;

		if (strcmp(name, "s0") == 0) {
			found_s0 = 1;
			CU_ASSERT(!isalias);

			sepol_cat_set_iter_t *cat_iter = NULL;
			CU_ASSERT_EQUAL(sepol_sens_iter_get_level_cat(
						handle, iter, &cat_iter),
					0);
			CU_ASSERT_PTR_NOT_NULL(cat_iter);

			if (cat_iter) {
				uint32_t cat_val;
				int cat_count = 0;
				int found_cats[4] = { 0, 0, 0, 0 };
				while (1) {
					int cat_rc = sepol_cat_set_iter_next(
						handle, cat_iter, &cat_val);
					CU_ASSERT_EQUAL(cat_rc, 0);
					if (cat_rc != 0 || cat_val == 0)
						break;
					cat_count++;
					if (cat_val >= 1 && cat_val <= 4)
						found_cats[cat_val - 1] = 1;
				}
				CU_ASSERT(cat_count >= 4);
				CU_ASSERT(found_cats[0]);
				CU_ASSERT(found_cats[1]);
				CU_ASSERT(found_cats[2]);
				CU_ASSERT(found_cats[3]);

				sepol_cat_set_iter_destroy(cat_iter);
			}
		}
	}
	CU_ASSERT(found_s0);

	sepol_sens_iter_destroy(iter);
}

static void test_common_perm_iter_invalid(void)
{
	sepol_common_perm_iter_t *piter;
	int rc = sepol_common_perm_iter_create(handle, policy, 0, &piter);
	CU_ASSERT_NOT_EQUAL(rc, 0);

	rc = sepol_common_perm_iter_create(handle, policy, 9999, &piter);
	CU_ASSERT_NOT_EQUAL(rc, 0);
}

static void test_role_allow_no_self(void)
{
	sepol_role_allow_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_allow_iter_create(handle, policy, &iter), 0);

	uint32_t role, new_role;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_role_allow_iter_next(
					      handle, iter, &role, &new_role),
				      0);
		if (role == 0)
			break;
		CU_ASSERT(role > 0);
		CU_ASSERT(new_role > 0);
		CU_ASSERT(role != new_role);
	}

	sepol_role_allow_iter_destroy(iter);
}

static void test_cat_value_to_name(void)
{
	if (!mls)
		return;

	sepol_cat_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_cat_iter_create(handle, policy, &iter), 0);

	const char *name;
	uint32_t value;
	int isalias;
	int resolved = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_cat_iter_next(handle, iter, &name,
							  &value, &isalias),
				      0);
		if (!name)
			break;
		if (isalias)
			continue;

		const char *resolved_name = NULL;
		CU_ASSERT_EQUAL_FATAL(sepol_cat_value_to_name(handle, policy,
							      value,
							      &resolved_name),
				      0);
		CU_ASSERT_PTR_NOT_NULL(resolved_name);
		if (resolved_name) {
			CU_ASSERT_STRING_EQUAL(resolved_name, name);
			resolved++;
		}
	}
	CU_ASSERT(resolved >= 4);

	const char *bad_name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_cat_value_to_name(handle, policy, 0, &bad_name), 0);
	CU_ASSERT_PTR_NULL(bad_name);
	CU_ASSERT_NOT_EQUAL(
		sepol_cat_value_to_name(handle, policy, 9999, &bad_name), 0);
	CU_ASSERT_PTR_NULL(bad_name);

	sepol_cat_iter_destroy(iter);
}

static void test_sens_value_to_name(void)
{
	if (!mls)
		return;

	const char *name = NULL;
	CU_ASSERT_EQUAL_FATAL(
		sepol_sens_value_to_name(handle, policy, 1, &name), 0);
	CU_ASSERT_PTR_NOT_NULL(name);

	const char *bad_name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_sens_value_to_name(handle, policy, 0, &bad_name), 0);
	CU_ASSERT_PTR_NULL(bad_name);
	CU_ASSERT_NOT_EQUAL(
		sepol_sens_value_to_name(handle, policy, 9999, &bad_name), 0);
	CU_ASSERT_PTR_NULL(bad_name);
}

static void test_common_value_to_name(void)
{
	sepol_common_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_common_iter_create(handle, policy, &iter),
			      0);

	const char *name;
	uint32_t value;
	int resolved = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(
			sepol_common_iter_next(handle, iter, &name, &value), 0);
		if (!name)
			break;

		const char *resolved_name = NULL;
		CU_ASSERT_EQUAL_FATAL(
			sepol_common_value_to_name(handle, policy, value,
						   &resolved_name),
			0);
		CU_ASSERT_PTR_NOT_NULL(resolved_name);
		if (resolved_name) {
			CU_ASSERT_STRING_EQUAL(resolved_name, name);
			resolved++;
		}
	}
	CU_ASSERT(resolved >= 1);

	sepol_common_iter_destroy(iter);
}

static void test_isid_name(void)
{
	sepol_isid_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_isid_iter_create(handle, policy, &iter), 0);

	uint32_t sid;
	int found_kernel = 0;

	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_isid_iter_next(handle, iter, &sid),
				      0);
		if (sid == 0)
			break;

		const char *name = sepol_isid_iter_get_name(iter);
		if (name && strcmp(name, "kernel") == 0) {
			found_kernel = 1;
			CU_ASSERT(sepol_isid_iter_get_context_user(iter) > 0);
			CU_ASSERT(sepol_isid_iter_get_context_role(iter) > 0);
			CU_ASSERT(sepol_isid_iter_get_context_type(iter) > 0);

			if (mls) {
				uint32_t low_sens =
					sepol_isid_iter_get_mls_range_low_sens(
						iter);
				CU_ASSERT(low_sens > 0);
				CU_ASSERT_EQUAL(
					sepol_isid_iter_get_mls_range_high_sens(
						iter),
					low_sens);

				sepol_cat_set_iter_t *low_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_isid_iter_get_mls_range_low_cat(
						iter, &low_cat),
					0);
				drain_cat_iter(low_cat);

				sepol_cat_set_iter_t *high_cat = NULL;
				CU_ASSERT_EQUAL_FATAL(
					sepol_isid_iter_get_mls_range_high_cat(
						iter, &high_cat),
					0);
				drain_cat_iter(high_cat);
			}
		}
	}
	CU_ASSERT(found_kernel);

	sepol_isid_iter_destroy(iter);
}

static void test_portcon_iter(void)
{
	sepol_portcon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_portcon_iter_create(handle, policy, &iter),
			      0);

	int count = 0;
	uint8_t protocol;
	uint16_t low_port, high_port;
	int rc, has_next;
	while (1) {
		rc = sepol_portcon_iter_next(handle, iter, &protocol, &low_port,
					     &high_port, &has_next);
		CU_ASSERT_EQUAL_FATAL(rc, 0);
		if (!has_next)
			break;
		CU_ASSERT(protocol == 6 || protocol == 17);
		CU_ASSERT(sepol_portcon_iter_get_context_user(iter) > 0);
		CU_ASSERT(sepol_portcon_iter_get_context_role(iter) > 0);
		CU_ASSERT(sepol_portcon_iter_get_context_type(iter) > 0);

		if (mls) {
			uint32_t low_sens =
				sepol_portcon_iter_get_mls_range_low_sens(iter);
			CU_ASSERT(low_sens > 0);
			CU_ASSERT_EQUAL(
				sepol_portcon_iter_get_mls_range_high_sens(
					iter),
				low_sens);

			sepol_cat_set_iter_t *low_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_portcon_iter_get_mls_range_low_cat(
					iter, &low_cat),
				0);
			drain_cat_iter(low_cat);

			sepol_cat_set_iter_t *high_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_portcon_iter_get_mls_range_high_cat(
					iter, &high_cat),
				0);
			drain_cat_iter(high_cat);
		}

		count++;
	}
	CU_ASSERT(count >= 2);

	sepol_portcon_iter_destroy(iter);
}

static void test_netifcon_iter(void)
{
	sepol_netifcon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_netifcon_iter_create(handle, policy, &iter),
			      0);

	int count = 0;
	const char *name;
	int rc;
	while (1) {
		rc = sepol_netifcon_iter_next(handle, iter, &name);
		CU_ASSERT_EQUAL_FATAL(rc, 0);
		if (!name)
			break;
		CU_ASSERT_STRING_EQUAL(name, "eth0");
		CU_ASSERT(sepol_netifcon_iter_get_context_user(iter) > 0);
		CU_ASSERT(sepol_netifcon_iter_get_context_role(iter) > 0);
		CU_ASSERT(sepol_netifcon_iter_get_context_type(iter) > 0);
		CU_ASSERT(sepol_netifcon_iter_get_msg_context_user(iter) > 0);
		CU_ASSERT(sepol_netifcon_iter_get_msg_context_role(iter) > 0);
		CU_ASSERT(sepol_netifcon_iter_get_msg_context_type(iter) > 0);

		if (mls) {
			uint32_t low_sens =
				sepol_netifcon_iter_get_mls_range_low_sens(
					iter);
			CU_ASSERT(low_sens > 0);
			CU_ASSERT_EQUAL(
				sepol_netifcon_iter_get_mls_range_high_sens(
					iter),
				low_sens);

			sepol_cat_set_iter_t *low_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_netifcon_iter_get_mls_range_low_cat(
					iter, &low_cat),
				0);
			drain_cat_iter(low_cat);

			sepol_cat_set_iter_t *high_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_netifcon_iter_get_mls_range_high_cat(
					iter, &high_cat),
				0);
			drain_cat_iter(high_cat);

			uint32_t msg_low_sens =
				sepol_netifcon_iter_get_msg_mls_range_low_sens(
					iter);
			CU_ASSERT(msg_low_sens > 0);
			CU_ASSERT_EQUAL(
				sepol_netifcon_iter_get_msg_mls_range_high_sens(
					iter),
				msg_low_sens);

			sepol_cat_set_iter_t *msg_low_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_netifcon_iter_get_msg_mls_range_low_cat(
					iter, &msg_low_cat),
				0);
			drain_cat_iter(msg_low_cat);

			sepol_cat_set_iter_t *msg_high_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_netifcon_iter_get_msg_mls_range_high_cat(
					iter, &msg_high_cat),
				0);
			drain_cat_iter(msg_high_cat);
		}

		count++;
	}
	CU_ASSERT(count == 1);

	sepol_netifcon_iter_destroy(iter);
}

static void test_nodecon_iter(void)
{
	sepol_nodecon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_nodecon_iter_create(handle, policy, &iter),
			      0);

	int count = 0;
	uint32_t addr, mask;
	int rc, has_next;
	while (1) {
		rc = sepol_nodecon_iter_next(handle, iter, &addr, &mask,
					     &has_next);
		CU_ASSERT_EQUAL_FATAL(rc, 0);
		if (!has_next)
			break;
		CU_ASSERT(sepol_nodecon_iter_get_context_user(iter) > 0);
		CU_ASSERT(sepol_nodecon_iter_get_context_role(iter) > 0);
		CU_ASSERT(sepol_nodecon_iter_get_context_type(iter) > 0);

		if (mls) {
			uint32_t low_sens =
				sepol_nodecon_iter_get_mls_range_low_sens(iter);
			CU_ASSERT(low_sens > 0);
			CU_ASSERT_EQUAL(
				sepol_nodecon_iter_get_mls_range_high_sens(
					iter),
				low_sens);

			sepol_cat_set_iter_t *low_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_nodecon_iter_get_mls_range_low_cat(
					iter, &low_cat),
				0);
			drain_cat_iter(low_cat);

			sepol_cat_set_iter_t *high_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_nodecon_iter_get_mls_range_high_cat(
					iter, &high_cat),
				0);
			drain_cat_iter(high_cat);
		}

		count++;
	}
	CU_ASSERT(count >= 1);

	sepol_nodecon_iter_destroy(iter);

	sepol_nodecon6_iter_t *iter6;
	CU_ASSERT_EQUAL_FATAL(
		sepol_nodecon6_iter_create(handle, policy, &iter6), 0);

	count = 0;
	const uint32_t *addr6, *mask6;
	while (1) {
		rc = sepol_nodecon6_iter_next(handle, iter6, &addr6, &mask6);
		CU_ASSERT_EQUAL_FATAL(rc, 0);
		if (!addr6)
			break;
		CU_ASSERT(sepol_nodecon6_iter_get_context_user(iter6) > 0);
		CU_ASSERT(sepol_nodecon6_iter_get_context_role(iter6) > 0);
		CU_ASSERT(sepol_nodecon6_iter_get_context_type(iter6) > 0);

		if (mls) {
			uint32_t low_sens =
				sepol_nodecon6_iter_get_mls_range_low_sens(
					iter6);
			CU_ASSERT(low_sens > 0);
			CU_ASSERT_EQUAL(
				sepol_nodecon6_iter_get_mls_range_high_sens(
					iter6),
				low_sens);

			sepol_cat_set_iter_t *low_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_nodecon6_iter_get_mls_range_low_cat(
					iter6, &low_cat),
				0);
			drain_cat_iter(low_cat);

			sepol_cat_set_iter_t *high_cat = NULL;
			CU_ASSERT_EQUAL_FATAL(
				sepol_nodecon6_iter_get_mls_range_high_cat(
					iter6, &high_cat),
				0);
			drain_cat_iter(high_cat);
		}

		count++;
	}
	CU_ASSERT(count >= 1);

	sepol_nodecon6_iter_destroy(iter6);
}

static void test_ibpkeycon_iter(void)
{
	sepol_ibpkeycon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_ibpkeycon_iter_create(handle, policy, &iter), 0);

	uint64_t subnet_prefix;
	uint16_t low_pkey, high_pkey;
	int has_next;
	int count = 0;
	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_ibpkeycon_iter_next(
					      handle, iter, &subnet_prefix,
					      &low_pkey, &high_pkey, &has_next),
				      0);
		if (!has_next)
			break;

		/* fe80:: subnet prefix; raw byte layout is host-endian
		 * dependent, so just check it is non-zero. */
		CU_ASSERT(subnet_prefix != 0);
		CU_ASSERT_EQUAL(low_pkey, 0);
		CU_ASSERT_EQUAL(high_pkey, 0xffff);
		CU_ASSERT(sepol_ibpkeycon_iter_get_context_user(iter) > 0);
		CU_ASSERT(sepol_ibpkeycon_iter_get_context_role(iter) > 0);
		CU_ASSERT(sepol_ibpkeycon_iter_get_context_type(iter) > 0);

		count++;
	}
	CU_ASSERT_EQUAL(count, 1);

	sepol_ibpkeycon_iter_destroy(iter);
}

static void test_ibendportcon_iter(void)
{
	sepol_ibendportcon_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_ibendportcon_iter_create(handle, policy, &iter), 0);

	const char *dev_name;
	uint8_t port;
	int count = 0;
	while (1) {
		CU_ASSERT_EQUAL_FATAL(sepol_ibendportcon_iter_next(
					      handle, iter, &dev_name, &port),
				      0);
		if (!dev_name)
			break;

		CU_ASSERT_STRING_EQUAL(dev_name, "mlx4_0");
		CU_ASSERT_EQUAL(port, 1);
		CU_ASSERT(sepol_ibendportcon_iter_get_context_user(iter) > 0);
		CU_ASSERT(sepol_ibendportcon_iter_get_context_role(iter) > 0);
		CU_ASSERT(sepol_ibendportcon_iter_get_context_type(iter) > 0);

		count++;
	}
	CU_ASSERT_EQUAL(count, 1);

	sepol_ibendportcon_iter_destroy(iter);
}

static void test_bool_iter(void)
{
	sepol_bool_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_bool_iter_create(handle, policy, &iter), 0);

	int count = 0;
	int found_bool1 = 0;
	sepol_bool_t *item;
	int rc;
	while (1) {
		rc = sepol_bool_iter_next(handle, iter, &item);
		CU_ASSERT_EQUAL_FATAL(rc, 0);
		if (!item)
			break;
		const char *name = sepol_bool_get_name(item);
		CU_ASSERT_PTR_NOT_NULL(name);
		if (name && strcmp(name, "BOOL1") == 0)
			found_bool1 = 1;
		sepol_bool_free(item);
		count++;
	}
	CU_ASSERT(count == 2);
	CU_ASSERT(found_bool1);

	sepol_bool_iter_destroy(iter);
}

static void test_permissive_flags(void)
{
	uint32_t type1_val = type_value("TYPE1");
	uint32_t type2_val = type_value("TYPE2");
	type_datum_t *type1_datum = policy->p.type_val_to_struct[type1_val - 1];
	type_datum_t *type2_datum = policy->p.type_val_to_struct[type2_val - 1];
	CU_ASSERT_PTR_NOT_NULL_FATAL(type1_datum);
	CU_ASSERT_PTR_NOT_NULL_FATAL(type2_datum);

	/*
	 * iter.conf declares "permissive TYPE1;", which sets both
	 * permissive_map's bit and type_datum->flags at expansion time, so
	 * the two are already in sync and this test cannot exercise the
	 * resync logic by observing them together. It also can't be
	 * observed through sepol_type_query_by_value()/sepol_type_has_flag()
	 * -- type_datum_to_record() ORs in permissive_map regardless of
	 * type_datum->flags (see type.c), so the public read path can never
	 * distinguish a synced flag from a stale one. Desync the two
	 * directly and assert on type_datum->flags itself, which is the
	 * only thing sepol_policydb_set_permissive_flags() actually writes.
	 */
	type1_datum->flags &= ~(uint32_t)TYPE_FLAGS_PERMISSIVE;
	CU_ASSERT_TRUE_FATAL(
		ebitmap_get_bit(&policy->p.permissive_map, type1_val));
	CU_ASSERT_FALSE((type1_datum->flags & TYPE_FLAGS_PERMISSIVE) != 0);
	CU_ASSERT_FALSE((type2_datum->flags & TYPE_FLAGS_PERMISSIVE) != 0);

	CU_ASSERT_EQUAL(sepol_policydb_set_permissive_flags(handle, policy), 0);

	CU_ASSERT_TRUE((type1_datum->flags & TYPE_FLAGS_PERMISSIVE) != 0);
	/* A non-permissive type must not be marked permissive as a
	 * side effect. */
	CU_ASSERT_FALSE((type2_datum->flags & TYPE_FLAGS_PERMISSIVE) != 0);
}

static void test_rebuild_attr_map(void)
{
	uint32_t type1_val = type_value("TYPE1");
	uint32_t attr1_val = type_value("ATTR1");
	type_datum_t *attr1_datum = policy->p.type_val_to_struct[attr1_val - 1];
	CU_ASSERT_PTR_NOT_NULL_FATAL(attr1_datum);
	CU_ASSERT_EQUAL_FATAL(attr1_datum->flavor, TYPE_ATTRIB);

	/* iter.conf declares "attribute ATTR1;" with "typeattribute TYPE2
	 * ATTR1;" and "typeattribute TYPE3 ATTR1;" -- TYPE1 is *not* a
	 * member. Corrupt the derived reverse map as if it were stale from
	 * before a membership change, so this test actually exercises the
	 * rebuild logic instead of trivially passing on whatever the
	 * initial expand-time state happened to be: falsely mark TYPE1 as
	 * a member of ATTR1 in the reverse map (type_attr_map), while
	 * ATTR1's real forward map (attr_type_map) still correctly omits
	 * TYPE1. A correct rebuild must prune this stale reverse bit even
	 * though it never touches attr_type_map itself. */
	uint32_t type3_val = type_value("TYPE3");
	CU_ASSERT_TRUE_FATAL(ebitmap_get_bit(
		&policy->p.attr_type_map[attr1_val - 1], type3_val - 1));
	CU_ASSERT_EQUAL_FATAL(
		ebitmap_set_bit(&policy->p.type_attr_map[type1_val - 1],
				attr1_val - 1, 1),
		0);

	sepol_type_t *type1 = NULL, *type3 = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_query_by_value(handle, policy,
							type1_val, &type1),
			      0);
	CU_ASSERT_TRUE(sepol_type_has_subtype(type1, "ATTR1"));
	sepol_type_free(type1);

	/*
	 * type_attr_map[i] must always have its own bit i set ("a type is
	 * always a member of itself" -- the same "degenerate case" that
	 * policydb_read() sets unconditionally for every valid type or
	 * attribute at initial policy load, see policydb.c). This is *not*
	 * observable via sepol_type_has_subtype()/type_datum_to_record():
	 * that public conversion deliberately excludes the self-bit from
	 * a type's reported subtype/attribute-membership list (it would
	 * be nonsensical for a type to be listed as its own subtype), so
	 * it cannot be used to catch a rebuild that drops this bit. Check
	 * the internal ebitmap directly instead -- services.c's AV
	 * decision hot path reads type_attr_map[] directly, so losing
	 * this bit silently breaks matching for any allow rule written
	 * against a literal (non-attribute) type.
	 */
	uint32_t attr1_val_for_self = attr1_val;
	CU_ASSERT_TRUE_FATAL(ebitmap_get_bit(
		&policy->p.type_attr_map[type1_val - 1], type1_val - 1));
	CU_ASSERT_TRUE_FATAL(ebitmap_get_bit(
		&policy->p.type_attr_map[type3_val - 1], type3_val - 1));
	CU_ASSERT_TRUE_FATAL(ebitmap_get_bit(
		&policy->p.type_attr_map[attr1_val_for_self - 1],
		attr1_val_for_self - 1));

	CU_ASSERT_EQUAL(sepol_policydb_rebuild_attr_map(handle, policy), 0);

	/* After a correct rebuild, TYPE1's stale membership must be gone... */
	type1 = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_query_by_value(handle, policy,
							type1_val, &type1),
			      0);
	CU_ASSERT_FALSE(sepol_type_has_subtype(type1, "ATTR1"));
	sepol_type_free(type1);

	/* ...and TYPE3's real, unrelated membership must be intact. */
	CU_ASSERT_EQUAL_FATAL(sepol_type_query_by_value(handle, policy,
							type3_val, &type3),
			      0);
	CU_ASSERT_TRUE(sepol_type_has_subtype(type3, "ATTR1"));
	sepol_type_free(type3);

	/*
	 * ...and every type/attribute's mandatory self-membership bit
	 * must have survived the rebuild too (the actual regression this
	 * covers: an earlier version of sepol_policydb_rebuild_attr_map()
	 * cleared type_attr_map[] wholesale and only ever restored bits
	 * for *attribute* membership, permanently losing the self-bit for
	 * every plain type -- and for any attribute with no members --
	 * in the policy).
	 */
	CU_ASSERT_TRUE(ebitmap_get_bit(&policy->p.type_attr_map[type1_val - 1],
				       type1_val - 1));
	CU_ASSERT_TRUE(ebitmap_get_bit(&policy->p.type_attr_map[type3_val - 1],
				       type3_val - 1));
	CU_ASSERT_TRUE(ebitmap_get_bit(
		&policy->p.type_attr_map[attr1_val_for_self - 1],
		attr1_val_for_self - 1));
}

static void test_bool_query_by_value(void)
{
	sepol_bool_t *b = NULL;
	cond_bool_datum_t *d = hashtab_search(policy->p.p_bools.table, "BOOL1");
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);

	CU_ASSERT_EQUAL_FATAL(
		sepol_bool_query_by_value(handle, policy, d->s.value, &b), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(b);
	CU_ASSERT_STRING_EQUAL(sepol_bool_get_name(b), "BOOL1");
	sepol_bool_free(b);

	CU_ASSERT_EQUAL(sepol_bool_query_by_value(handle, policy, 0, &b), 0);
	CU_ASSERT_PTR_NULL(b);
	CU_ASSERT_EQUAL(sepol_bool_query_by_value(handle, policy, 9999, &b), 0);
	CU_ASSERT_PTR_NULL(b);
}

static void test_user_mls_accessors(void)
{
	if (!mls)
		return;

	uint32_t uv = user_value("USER1");

	uint32_t sens = sepol_user_get_dflt_level_sens(policy, uv);
	CU_ASSERT(sens > 0);

	sens = sepol_user_get_range_low_sens(policy, uv);
	CU_ASSERT(sens > 0);

	sens = sepol_user_get_range_high_sens(policy, uv);
	CU_ASSERT(sens > 0);

	/*
	 * Asserts inside each draining loop below are intentionally
	 * non-fatal: a CU_ASSERT_*_FATAL() here would longjmp out of the
	 * function on the first failure and skip the corresponding
	 * sepol_cat_set_iter_destroy(), leaking the iterator on top of the
	 * reported assertion failure (see test_range_trans_mls_cat() and
	 * test_sens_level_cat_bits() above for the same pattern).
	 */
	sepol_cat_set_iter_t *cat_iter = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_user_get_range_high_cat(handle, policy, uv,
							    &cat_iter),
			      0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cat_iter);
	int cat_count = 0;
	uint32_t cat_val;
	int rc;
	while (1) {
		rc = sepol_cat_set_iter_next(handle, cat_iter, &cat_val);
		CU_ASSERT_EQUAL(rc, 0);
		if (rc != 0 || cat_val == 0)
			break;
		cat_count++;
	}
	CU_ASSERT(cat_count == 4);
	sepol_cat_set_iter_destroy(cat_iter);

	cat_iter = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_user_get_dflt_level_cat(handle, policy, uv,
							    &cat_iter),
			      0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cat_iter);
	cat_count = 0;
	while (1) {
		rc = sepol_cat_set_iter_next(handle, cat_iter, &cat_val);
		CU_ASSERT_EQUAL(rc, 0);
		if (rc != 0 || cat_val == 0)
			break;
		cat_count++;
	}
	CU_ASSERT_EQUAL(cat_count, 0);
	sepol_cat_set_iter_destroy(cat_iter);

	cat_iter = NULL;
	CU_ASSERT_EQUAL_FATAL(
		sepol_user_get_range_low_cat(handle, policy, uv, &cat_iter), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cat_iter);
	cat_count = 0;
	while (1) {
		rc = sepol_cat_set_iter_next(handle, cat_iter, &cat_val);
		CU_ASSERT_EQUAL(rc, 0);
		if (rc != 0 || cat_val == 0)
			break;
		cat_count++;
	}
	CU_ASSERT_EQUAL(cat_count, 0);
	sepol_cat_set_iter_destroy(cat_iter);

	CU_ASSERT_EQUAL(sepol_user_get_dflt_level_sens(policy, 0), 0);
	CU_ASSERT_EQUAL(sepol_user_get_dflt_level_sens(policy, 9999), 0);
}

static void test_class_perm_value_to_name(void)
{
	uint32_t cv = class_value("CLASS1");
	class_datum_t *cls =
		hashtab_search(policy->p.p_classes.table, "CLASS1");
	CU_ASSERT_PTR_NOT_NULL_FATAL(cls);

	uint32_t pv = perm_value(cls, "PERM1");
	const char *name = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_class_perm_value_to_name(handle, policy, cv,
							     pv, &name),
			      0);
	CU_ASSERT_PTR_NOT_NULL(name);
	if (name)
		CU_ASSERT_STRING_EQUAL(name, "PERM1");

	uint32_t cpv = perm_value(cls, "COMMONPERM1");
	name = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_class_perm_value_to_name(handle, policy, cv,
							     cpv, &name),
			      0);
	CU_ASSERT_PTR_NOT_NULL(name);
	if (name)
		CU_ASSERT_STRING_EQUAL(name, "COMMONPERM1");

	name = NULL;
	CU_ASSERT_EQUAL(sepol_class_perm_value_to_name(handle, policy, cv, 9999,
						       &name),
			0);
	CU_ASSERT_PTR_NULL(name);

	CU_ASSERT_NOT_EQUAL(
		sepol_class_perm_value_to_name(handle, policy, 0, 1, &name), 0);
	CU_ASSERT_PTR_NULL(name);
}

static void test_xen_empty_iters(void)
{
	/* The test policy is SELinux, not Xen. Xen iterators should
	 * reject non-Xen policies with an error. */
	sepol_pirqcon_iter_t *pirq;
	CU_ASSERT(sepol_pirqcon_iter_create(handle, policy, &pirq) != 0);

	sepol_iomemcon_iter_t *iomem;
	CU_ASSERT(sepol_iomemcon_iter_create(handle, policy, &iomem) != 0);

	sepol_ioportcon_iter_t *ioport;
	CU_ASSERT(sepol_ioportcon_iter_create(handle, policy, &ioport) != 0);

	sepol_pcidevicecon_iter_t *pci;
	CU_ASSERT(sepol_pcidevicecon_iter_create(handle, policy, &pci) != 0);

	sepol_devicetreecon_iter_t *dt;
	CU_ASSERT(sepol_devicetreecon_iter_create(handle, policy, &dt) != 0);
}

static void test_type_value_to_name(void)
{
	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_type_value_to_name(handle, policy, 1, &name), 0);
	CU_ASSERT_PTR_NOT_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(sepol_type_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_type_value_to_name(handle, policy, 9999, &name), 0);
	CU_ASSERT_PTR_NULL(name);
}

static void test_class_value_to_name(void)
{
	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_class_value_to_name(handle, policy, 1, &name), 0);
	CU_ASSERT_PTR_NOT_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(sepol_class_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_class_value_to_name(handle, policy, 9999, &name), 0);
	CU_ASSERT_PTR_NULL(name);
}

static void test_role_value_to_name(void)
{
	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_role_value_to_name(handle, policy, 1, &name), 0);
	CU_ASSERT_PTR_NOT_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(sepol_role_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_role_value_to_name(handle, policy, 9999, &name), 0);
	CU_ASSERT_PTR_NULL(name);
}

static void test_user_value_to_name(void)
{
	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_user_value_to_name(handle, policy, 1, &name), 0);
	CU_ASSERT_PTR_NOT_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(sepol_user_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);

	name = NULL;
	CU_ASSERT_NOT_EQUAL(
		sepol_user_value_to_name(handle, policy, 9999, &name), 0);
	CU_ASSERT_PTR_NULL(name);
}

static void test_count_and_exists(void)
{
	unsigned int count = 0;
	int exists = 0;

	CU_ASSERT_EQUAL(sepol_type_count(handle, policy, &count), 0);
	CU_ASSERT(count > 0);

	CU_ASSERT_EQUAL(sepol_role_count(handle, policy, &count), 0);
	CU_ASSERT(count > 0);

	CU_ASSERT_EQUAL(sepol_class_count(handle, policy, &count), 0);
	CU_ASSERT(count > 0);

	CU_ASSERT_EQUAL(sepol_user_count(handle, policy, &count), 0);
	CU_ASSERT(count > 0);

	CU_ASSERT_EQUAL(sepol_bool_count(handle, policy, &count), 0);
	CU_ASSERT(count > 0);

	const char *tname = NULL;
	CU_ASSERT_EQUAL_FATAL(
		sepol_type_value_to_name(handle, policy, 1, &tname), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(tname);

	sepol_type_key_t *tkey = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, tname, &tkey), 0);
	CU_ASSERT_EQUAL(sepol_type_exists(handle, policy, tkey, &exists), 0);
	CU_ASSERT(exists);
	sepol_type_key_free(tkey);

	CU_ASSERT_EQUAL_FATAL(
		sepol_type_key_create(handle, "nonexistent_t", &tkey), 0);
	CU_ASSERT_EQUAL(sepol_type_exists(handle, policy, tkey, &exists), 0);
	CU_ASSERT(!exists);
	sepol_type_key_free(tkey);
}

static void test_query_by_value(void)
{
	sepol_type_t *type_rec = NULL;
	CU_ASSERT_EQUAL(sepol_type_query_by_value(handle, policy, 1, &type_rec),
			0);
	CU_ASSERT_PTR_NOT_NULL(type_rec);
	if (type_rec) {
		CU_ASSERT_PTR_NOT_NULL(sepol_type_get_name(type_rec));
		sepol_type_free(type_rec);
	}

	CU_ASSERT_EQUAL(sepol_type_query_by_value(handle, policy, 0, &type_rec),
			0);
	CU_ASSERT_PTR_NULL(type_rec);

	sepol_role_t *role_rec = NULL;
	CU_ASSERT_EQUAL(sepol_role_query_by_value(handle, policy, 1, &role_rec),
			0);
	CU_ASSERT_PTR_NOT_NULL(role_rec);
	if (role_rec) {
		CU_ASSERT_PTR_NOT_NULL(sepol_role_get_name(role_rec));
		sepol_role_free(role_rec);
	}

	sepol_class_t *class_rec = NULL;
	CU_ASSERT_EQUAL(
		sepol_class_query_by_value(handle, policy, 1, &class_rec), 0);
	CU_ASSERT_PTR_NOT_NULL(class_rec);
	if (class_rec) {
		CU_ASSERT_PTR_NOT_NULL(sepol_class_get_name(class_rec));
		sepol_class_free(class_rec);
	}

	sepol_user_t *user_rec = NULL;
	CU_ASSERT_EQUAL(sepol_user_query_by_value(handle, policy, 1, &user_rec),
			0);
	CU_ASSERT_PTR_NOT_NULL(user_rec);
	if (user_rec) {
		CU_ASSERT_PTR_NOT_NULL(sepol_user_get_name(user_rec));
		sepol_user_free(user_rec);
	}
}

static void test_policydb_getters(void)
{
	unsigned int vers = sepol_policydb_get_vers(policy);
	CU_ASSERT(vers > 0);

	unsigned int unknown = sepol_policydb_get_handle_unknown(policy);
	CU_ASSERT_EQUAL(unknown, SEPOL_DENY_UNKNOWN);

	int platform = sepol_policydb_get_target_platform(policy);
	CU_ASSERT_EQUAL(platform, SEPOL_TARGET_SELINUX);
}

static void test_iter_next_null_output_args(void)
{
	/* _iter_create: NULL policydb must fail without touching *iter
	 * on the fast path, and must clear *iter on later failure paths. */
	sepol_isid_iter_t *isid_iter = (void *)0xdeadbeef;
	CU_ASSERT(sepol_isid_iter_create(handle, NULL, &isid_iter) != 0);
	CU_ASSERT_PTR_NULL(isid_iter);

	/* isid_iter_next */
	CU_ASSERT_EQUAL_FATAL(
		sepol_isid_iter_create(handle, policy, &isid_iter), 0);
	CU_ASSERT(sepol_isid_iter_next(handle, isid_iter, NULL) != 0);
	sepol_isid_iter_destroy(isid_iter);

	/* fsuse_iter_next */
	sepol_fsuse_iter_t *fsuse_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_fsuse_iter_create(handle, policy, &fsuse_iter), 0);
	const char *name;
	uint32_t behavior;
	CU_ASSERT(sepol_fsuse_iter_next(handle, fsuse_iter, NULL, &behavior) !=
		  0);
	CU_ASSERT(sepol_fsuse_iter_next(handle, fsuse_iter, &name, NULL) != 0);
	sepol_fsuse_iter_destroy(fsuse_iter);

	/* genfscon_iter_next */
	sepol_genfscon_iter_t *genfscon_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_genfscon_iter_create(handle, policy, &genfscon_iter), 0);
	const char *fstype, *path;
	uint32_t sclass;
	CU_ASSERT(sepol_genfscon_iter_next(handle, genfscon_iter, NULL, &path,
					   &sclass) != 0);
	CU_ASSERT(sepol_genfscon_iter_next(handle, genfscon_iter, &fstype, NULL,
					   &sclass) != 0);
	CU_ASSERT(sepol_genfscon_iter_next(handle, genfscon_iter, &fstype,
					   &path, NULL) != 0);
	sepol_genfscon_iter_destroy(genfscon_iter);

	/* portcon_iter_next */
	sepol_portcon_iter_t *portcon_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_portcon_iter_create(handle, policy, &portcon_iter), 0);
	uint8_t protocol;
	uint16_t low_port, high_port;
	int has_next;
	CU_ASSERT(sepol_portcon_iter_next(handle, portcon_iter, NULL, &low_port,
					  &high_port, &has_next) != 0);
	CU_ASSERT(sepol_portcon_iter_next(handle, portcon_iter, &protocol, NULL,
					  &high_port, &has_next) != 0);
	CU_ASSERT(sepol_portcon_iter_next(handle, portcon_iter, &protocol,
					  &low_port, NULL, &has_next) != 0);
	CU_ASSERT(sepol_portcon_iter_next(handle, portcon_iter, &protocol,
					  &low_port, &high_port, NULL) != 0);
	sepol_portcon_iter_destroy(portcon_iter);

	/* netifcon_iter_next */
	sepol_netifcon_iter_t *netifcon_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_netifcon_iter_create(handle, policy, &netifcon_iter), 0);
	CU_ASSERT(sepol_netifcon_iter_next(handle, netifcon_iter, NULL) != 0);
	sepol_netifcon_iter_destroy(netifcon_iter);

	/* cat_iter_next / sens_iter_next */
	sepol_cat_iter_t *cat_iter;
	CU_ASSERT_EQUAL_FATAL(sepol_cat_iter_create(handle, policy, &cat_iter),
			      0);
	uint32_t value;
	int isalias;
	CU_ASSERT(sepol_cat_iter_next(handle, cat_iter, NULL, &value,
				      &isalias) != 0);
	CU_ASSERT(sepol_cat_iter_next(handle, cat_iter, &name, NULL,
				      &isalias) != 0);
	CU_ASSERT(sepol_cat_iter_next(handle, cat_iter, &name, &value, NULL) !=
		  0);
	sepol_cat_iter_destroy(cat_iter);

	sepol_sens_iter_t *sens_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_sens_iter_create(handle, policy, &sens_iter), 0);
	uint32_t sens_value;
	CU_ASSERT(sepol_sens_iter_next(handle, sens_iter, NULL, &sens_value,
				       &isalias) != 0);
	CU_ASSERT(sepol_sens_iter_next(handle, sens_iter, &name, NULL,
				       &isalias) != 0);
	CU_ASSERT(sepol_sens_iter_next(handle, sens_iter, &name, &sens_value,
				       NULL) != 0);
	CU_ASSERT_EQUAL_FATAL(sepol_sens_iter_next(handle, sens_iter, &name,
						   &sens_value, &isalias),
			      0);
	if (mls && name) {
		/* cat_set_iter_next */
		sepol_cat_set_iter_t *cat_set_iter = NULL;
		CU_ASSERT_EQUAL_FATAL(sepol_sens_iter_get_level_cat(
					      handle, sens_iter, &cat_set_iter),
				      0);
		CU_ASSERT_PTR_NOT_NULL_FATAL(cat_set_iter);
		CU_ASSERT(sepol_cat_set_iter_next(handle, cat_set_iter, NULL) !=
			  0);
		sepol_cat_set_iter_destroy(cat_set_iter);
	}
	sepol_sens_iter_destroy(sens_iter);

	/* permissive_iter_next */
	sepol_permissive_iter_t *permissive_iter;
	CU_ASSERT_EQUAL_FATAL(sepol_permissive_iter_create(handle, policy,
							   &permissive_iter),
			      0);
	CU_ASSERT(sepol_permissive_iter_next(handle, permissive_iter, NULL) !=
		  0);
	sepol_permissive_iter_destroy(permissive_iter);

	/* polcap_iter_next */
	sepol_polcap_iter_t *polcap_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_polcap_iter_create(handle, policy, &polcap_iter), 0);
	uint32_t cap_num;
	const char *cap_name;
	CU_ASSERT(sepol_polcap_iter_next(handle, polcap_iter, NULL,
					 &cap_name) != 0);
	CU_ASSERT(sepol_polcap_iter_next(handle, polcap_iter, &cap_num, NULL) !=
		  0);
	sepol_polcap_iter_destroy(polcap_iter);

	/* range_trans_iter_next */
	sepol_range_trans_iter_t *rt_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_range_trans_iter_create(handle, policy, &rt_iter), 0);
	uint32_t rt_src, rt_tgt, rt_cls;
	CU_ASSERT(sepol_range_trans_iter_next(handle, rt_iter, NULL, &rt_tgt,
					      &rt_cls) != 0);
	CU_ASSERT(sepol_range_trans_iter_next(handle, rt_iter, &rt_src, NULL,
					      &rt_cls) != 0);
	CU_ASSERT(sepol_range_trans_iter_next(handle, rt_iter, &rt_src, &rt_tgt,
					      NULL) != 0);
	sepol_range_trans_iter_destroy(rt_iter);

	/* role_allow_iter_next / role_trans_iter_next */
	sepol_role_allow_iter_t *ra_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_allow_iter_create(handle, policy, &ra_iter), 0);
	uint32_t role, new_role;
	CU_ASSERT(sepol_role_allow_iter_next(handle, ra_iter, NULL,
					     &new_role) != 0);
	CU_ASSERT(sepol_role_allow_iter_next(handle, ra_iter, &role, NULL) !=
		  0);
	sepol_role_allow_iter_destroy(ra_iter);

	sepol_role_trans_iter_t *rtr_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_trans_iter_create(handle, policy, &rtr_iter), 0);
	uint32_t rtr_type, rtr_tclass;
	CU_ASSERT(sepol_role_trans_iter_next(handle, rtr_iter, NULL, &rtr_type,
					     &rtr_tclass, &new_role) != 0);
	CU_ASSERT(sepol_role_trans_iter_next(handle, rtr_iter, &role, NULL,
					     &rtr_tclass, &new_role) != 0);
	CU_ASSERT(sepol_role_trans_iter_next(handle, rtr_iter, &role, &rtr_type,
					     NULL, &new_role) != 0);
	CU_ASSERT(sepol_role_trans_iter_next(handle, rtr_iter, &role, &rtr_type,
					     &rtr_tclass, NULL) != 0);
	sepol_role_trans_iter_destroy(rtr_iter);

	/* filename_trans_iter_next */
	sepol_filename_trans_iter_t *ft_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_filename_trans_iter_create(handle, policy, &ft_iter), 0);
	uint32_t ft_src, ft_tgt, ft_cls, ft_def;
	const char *ft_name;
	CU_ASSERT(sepol_filename_trans_iter_next(handle, ft_iter, NULL, &ft_tgt,
						 &ft_cls, &ft_name,
						 &ft_def) != 0);
	CU_ASSERT(sepol_filename_trans_iter_next(handle, ft_iter, &ft_src, NULL,
						 &ft_cls, &ft_name,
						 &ft_def) != 0);
	CU_ASSERT(sepol_filename_trans_iter_next(handle, ft_iter, &ft_src,
						 &ft_tgt, NULL, &ft_name,
						 &ft_def) != 0);
	CU_ASSERT(sepol_filename_trans_iter_next(handle, ft_iter, &ft_src,
						 &ft_tgt, &ft_cls, NULL,
						 &ft_def) != 0);
	CU_ASSERT(sepol_filename_trans_iter_next(handle, ft_iter, &ft_src,
						 &ft_tgt, &ft_cls, &ft_name,
						 NULL) != 0);
	sepol_filename_trans_iter_destroy(ft_iter);

	/* common_iter_next / common_perm_iter_next */
	sepol_common_iter_t *common_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_common_iter_create(handle, policy, &common_iter), 0);
	uint32_t common_value;
	CU_ASSERT(sepol_common_iter_next(handle, common_iter, NULL,
					 &common_value) != 0);
	CU_ASSERT(sepol_common_iter_next(handle, common_iter, &name, NULL) !=
		  0);
	CU_ASSERT_EQUAL_FATAL(sepol_common_iter_next(handle, common_iter, &name,
						     &common_value),
			      0);
	if (name) {
		sepol_common_perm_iter_t *cp_iter;
		CU_ASSERT_EQUAL_FATAL(
			sepol_common_perm_iter_create(handle, policy,
						      common_value, &cp_iter),
			0);
		CU_ASSERT(sepol_common_perm_iter_next(handle, cp_iter, NULL) !=
			  0);
		sepol_common_perm_iter_destroy(cp_iter);
	}
	sepol_common_iter_destroy(common_iter);
}

/*
 * All sepol_*_iter_destroy()/sepol_handle_destroy() implementations are
 * thin wrappers around free(), so passing NULL is always safe (free(NULL)
 * is a documented no-op). Genuinely destroying the same live object twice
 * is a double-free and is not something these APIs can guard against,
 * since destroy() only receives the pointer by value and cannot clear the
 * caller's copy; that remains the caller's responsibility, exactly as
 * with free(). This test only verifies the safe, well-defined case: that
 * destroy() tolerates a NULL argument for a representative sample of
 * iterator types plus sepol_handle_t.
 */
static void test_destroy_null_safety(void)
{
	sepol_handle_destroy(NULL);

	sepol_isid_iter_destroy(NULL);
	sepol_fsuse_iter_destroy(NULL);
	sepol_genfscon_iter_destroy(NULL);
	sepol_portcon_iter_destroy(NULL);
	sepol_netifcon_iter_destroy(NULL);
	sepol_nodecon_iter_destroy(NULL);
	sepol_nodecon6_iter_destroy(NULL);
	sepol_ibpkeycon_iter_destroy(NULL);
	sepol_ibendportcon_iter_destroy(NULL);
	sepol_bool_iter_destroy(NULL);
	sepol_role_iter_destroy(NULL);
	sepol_type_iter_destroy(NULL);
	sepol_class_iter_destroy(NULL);
	sepol_user_iter_destroy(NULL);
	sepol_common_iter_destroy(NULL);
	sepol_common_perm_iter_destroy(NULL);
	sepol_cat_iter_destroy(NULL);
	sepol_sens_iter_destroy(NULL);
	sepol_cat_set_iter_destroy(NULL);
	sepol_permissive_iter_destroy(NULL);
	sepol_polcap_iter_destroy(NULL);
	sepol_role_allow_iter_destroy(NULL);
	sepol_role_trans_iter_destroy(NULL);
	sepol_filename_trans_iter_destroy(NULL);
	sepol_range_trans_iter_destroy(NULL);

	/* No assertions: success is simply not crashing. */
}

int tier2_add_tests(CU_pSuite suite)
{
	if (CU_add_test(suite, "role_allow_iter", test_role_allow_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_trans_iter", test_role_trans_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "filename_trans_iter",
			test_filename_trans_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "range_trans_iter", test_range_trans_iter) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "isid_iter", test_isid_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "fsuse_iter", test_fsuse_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "genfscon_iter", test_genfscon_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "polcap_iter", test_polcap_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "common_iter", test_common_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "cat_iter", test_cat_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "sens_iter", test_sens_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "permissive_iter", test_permissive_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "range_trans_mls_cat",
			test_range_trans_mls_cat) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "fsuse_context_values",
			test_fsuse_context_values) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "genfscon_context_values",
			test_genfscon_context_values) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "sens_level_cat_bits",
			test_sens_level_cat_bits) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "common_perm_iter_invalid",
			test_common_perm_iter_invalid) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_allow_no_self", test_role_allow_no_self) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "cat_value_to_name", test_cat_value_to_name) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "sens_value_to_name", test_sens_value_to_name) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "common_value_to_name",
			test_common_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "isid_name", test_isid_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "xen_empty_iters", test_xen_empty_iters) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "portcon_iter", test_portcon_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "netifcon_iter", test_netifcon_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "nodecon_iter", test_nodecon_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "ibpkeycon_iter", test_ibpkeycon_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "ibendportcon_iter", test_ibendportcon_iter) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "bool_iter", test_bool_iter) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "permissive_flags", test_permissive_flags) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "rebuild_attr_map", test_rebuild_attr_map) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "bool_query_by_value",
			test_bool_query_by_value) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_mls_accessors", test_user_mls_accessors) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_perm_value_to_name",
			test_class_perm_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_value_to_name", test_type_value_to_name) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_value_to_name",
			test_class_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_value_to_name", test_role_value_to_name) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_value_to_name", test_user_value_to_name) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "policydb_getters", test_policydb_getters) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "count_and_exists", test_count_and_exists) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "iter_next_null_output_args",
			test_iter_next_null_output_args) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "query_by_value", test_query_by_value) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "destroy_null_safety",
			test_destroy_null_safety) == NULL)
		return CU_get_error();
	return 0;
}

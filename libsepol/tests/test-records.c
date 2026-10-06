#include "test-records.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include <sepol/boolean_record.h>
#include <sepol/booleans.h>
#include <sepol/class_record.h>
#include <sepol/classes.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/policydb.h>
#include <sepol/role_record.h>
#include <sepol/roles.h>
#include <sepol/context.h>
#include <sepol/context_record.h>
#include <sepol/type_record.h>
#include <sepol/types.h>
#include <sepol/user_record.h>
#include <sepol/users.h>

#include "parse_util.h"

extern int mls;

static sepol_handle_t *handle;
static sepol_policydb_t *policy;
static policydb_t basemod;

int records_test_init(void)
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

	if (read_source_policy(&basemod, filename, "test-records"))
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

int records_test_cleanup(void)
{
	sepol_policydb_free(policy);
	policydb_destroy(&basemod);
	sepol_handle_destroy(handle);
	return 0;
}

/*
 * Helpers to look up a symbol's internal numeric value by name, needed
 * to exercise the _query_by_value()/_value_to_name() public API below:
 * there is no public "get value" accessor (by design -- callers are only
 * ever meant to obtain a value from a value-returning API, such as an
 * iterator or another query_by_value() call, not to mint one from a
 * name), so tests reach into the internal, already fully-expanded
 * (POLICY_KERN) `policy` fixture directly to get a known-good value to
 * round-trip through the public API.
 */
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

static void test_class_clone_deep_copy(void)
{
	sepol_class_iter_t *iter;
	CU_ASSERT_EQUAL_FATAL(sepol_class_iter_create(handle, policy, &iter),
			      0);

	sepol_class_t *orig;
	CU_ASSERT_EQUAL_FATAL(sepol_class_iter_next(handle, iter, &orig), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(orig);

	sepol_class_t *clone;
	CU_ASSERT_EQUAL_FATAL(sepol_class_clone(handle, orig, &clone), 0);

	CU_ASSERT_STRING_EQUAL(sepol_class_get_name(orig),
			       sepol_class_get_name(clone));

	const char **orig_perms, **clone_perms;
	uint32_t orig_nperms, clone_nperms;
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_perms(handle, orig, &orig_perms,
						    &orig_nperms),
			      0);
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_perms(handle, clone, &clone_perms,
						    &clone_nperms),
			      0);
	CU_ASSERT_EQUAL(orig_nperms, clone_nperms);
	free(orig_perms);
	free(clone_perms);

	sepol_class_free(clone);
	sepol_class_free(orig);
	sepol_class_iter_destroy(iter);
}

static void test_class_free_no_leak(void)
{
	sepol_class_t *class;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &class), 0);

	CU_ASSERT_EQUAL(sepol_class_set_name(handle, class, "testclass"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_perm(handle, class, "perm1"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_perm(handle, class, "perm2"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_perm(handle, class, "perm3"), 0);

	const char **perms;
	uint32_t nperms;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_get_perms(handle, class, &perms, &nperms), 0);
	CU_ASSERT_EQUAL(nperms, 3);
	free(perms);

	sepol_class_free(class);
}

static void test_type_set_alias_of_null(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	CU_ASSERT_EQUAL(sepol_type_set_alias_of(handle, type, "primary"), 0);
	CU_ASSERT_STRING_EQUAL(sepol_type_get_alias_of(type), "primary");

	CU_ASSERT_EQUAL(sepol_type_set_alias_of(handle, type, NULL), 0);
	CU_ASSERT_PTR_NULL(sepol_type_get_alias_of(type));

	sepol_type_free(type);
}

static void test_type_set_bounds_null(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	CU_ASSERT_EQUAL(sepol_type_set_bounds(handle, type, "parent"), 0);
	CU_ASSERT_STRING_EQUAL(sepol_type_get_bounds(type), "parent");

	CU_ASSERT_EQUAL(sepol_type_set_bounds(handle, type, NULL), 0);
	CU_ASSERT_PTR_NULL(sepol_type_get_bounds(type));

	sepol_type_free(type);
}

static void test_type_get_subtypes_empty(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	const char **subtypes;
	uint32_t nsub;
	CU_ASSERT_EQUAL(sepol_type_get_subtypes(handle, type, &subtypes, &nsub),
			0);
	CU_ASSERT_EQUAL(nsub, 0);
	CU_ASSERT_PTR_NULL(subtypes);

	sepol_type_free(type);
}

static void test_type_del_subtype_no_skip(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	CU_ASSERT_EQUAL(sepol_type_add_subtype(handle, type, "dup"), 0);
	CU_ASSERT_EQUAL(sepol_type_add_subtype(handle, type, "other"), 0);

	CU_ASSERT_EQUAL(sepol_type_del_subtype(handle, type, "dup"), 0);
	CU_ASSERT_FALSE(sepol_type_has_subtype(type, "dup"));
	CU_ASSERT_TRUE(sepol_type_has_subtype(type, "other"));

	const char **subtypes;
	uint32_t nsub;
	CU_ASSERT_EQUAL(sepol_type_get_subtypes(handle, type, &subtypes, &nsub),
			0);
	CU_ASSERT_EQUAL(nsub, 1);
	CU_ASSERT_STRING_EQUAL(subtypes[0], "other");
	free(subtypes);

	sepol_type_free(type);
}

static void test_type_clone(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	CU_ASSERT_EQUAL(sepol_type_set_name(handle, type, "mytype"), 0);
	CU_ASSERT_EQUAL(sepol_type_add_subtype(handle, type, "sub1"), 0);
	CU_ASSERT_EQUAL(sepol_type_add_subtype(handle, type, "sub2"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_alias_of(handle, type, "primary"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_bounds(handle, type, "parent"), 0);

	sepol_type_t *clone;
	CU_ASSERT_EQUAL_FATAL(sepol_type_clone(handle, type, &clone), 0);

	CU_ASSERT_STRING_EQUAL(sepol_type_get_name(type),
			       sepol_type_get_name(clone));
	CU_ASSERT_STRING_EQUAL(sepol_type_get_alias_of(type),
			       sepol_type_get_alias_of(clone));
	CU_ASSERT_STRING_EQUAL(sepol_type_get_bounds(type),
			       sepol_type_get_bounds(clone));

	const char **orig_sub, **clone_sub;
	uint32_t orig_nsub, clone_nsub;
	CU_ASSERT_EQUAL(sepol_type_get_subtypes(handle, type, &orig_sub,
						&orig_nsub),
			0);
	CU_ASSERT_EQUAL(sepol_type_get_subtypes(handle, clone, &clone_sub,
						&clone_nsub),
			0);
	CU_ASSERT_EQUAL(orig_nsub, clone_nsub);
	free(orig_sub);
	free(clone_sub);

	sepol_type_free(clone);
	sepol_type_free(type);
}

static void test_role_clone_with_subroles(void)
{
	sepol_role_t *role;
	CU_ASSERT_EQUAL_FATAL(sepol_role_create(handle, &role), 0);

	CU_ASSERT_EQUAL(sepol_role_set_name(handle, role, "myrole"), 0);
	CU_ASSERT_EQUAL(sepol_role_add_subrole(handle, role, "sub_r1"), 0);
	CU_ASSERT_EQUAL(sepol_role_add_subrole(handle, role, "sub_r2"), 0);

	sepol_role_t *clone;
	CU_ASSERT_EQUAL_FATAL(sepol_role_clone(handle, role, &clone), 0);

	CU_ASSERT_STRING_EQUAL(sepol_role_get_name(role),
			       sepol_role_get_name(clone));

	const char **orig_sub, **clone_sub;
	uint32_t orig_nsub, clone_nsub;
	CU_ASSERT_EQUAL(sepol_role_get_subroles(handle, role, &orig_sub,
						&orig_nsub),
			0);
	CU_ASSERT_EQUAL(sepol_role_get_subroles(handle, clone, &clone_sub,
						&clone_nsub),
			0);
	CU_ASSERT_EQUAL(orig_nsub, clone_nsub);
	CU_ASSERT_EQUAL(orig_nsub, 2);
	free(orig_sub);
	free(clone_sub);

	sepol_role_free(clone);
	sepol_role_free(role);
}

static void test_constraint_clone_deep(void)
{
	sepol_constraint_t *con;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &con), 0);

	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, con, "read"), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, con, "write"), 0);

	sepol_constraint_expr_t *expr;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_create(handle, &expr), 0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_type(handle, expr,
						       SEPOL_CEXPR_TYPE_ATTR),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_attr(handle, expr,
						       SEPOL_CEXPR_ATTR_USER),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_op(handle, expr,
						     SEPOL_CEXPR_OP_EQ),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_insert_expr(handle, con, 0, expr), 0);

	sepol_constraint_t *clone;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_clone(handle, con, &clone), 0);

	CU_ASSERT_TRUE(sepol_constraint_has_perm(clone, "read"));
	CU_ASSERT_TRUE(sepol_constraint_has_perm(clone, "write"));

	const sepol_constraint_expr_t **exprs;
	uint32_t nexprs;
	CU_ASSERT_EQUAL(
		sepol_constraint_get_exprs(handle, clone, &exprs, &nexprs), 0);
	CU_ASSERT_EQUAL(nexprs, 1);
	CU_ASSERT_EQUAL(sepol_constraint_expr_get_type(
				(sepol_constraint_expr_t *)exprs[0]),
			SEPOL_CEXPR_TYPE_ATTR);
	CU_ASSERT_TRUE(sepol_constraint_expr_has_attr(
		(sepol_constraint_expr_t *)exprs[0], SEPOL_CEXPR_ATTR_USER));
	free(exprs);

	sepol_constraint_free(clone);
	sepol_constraint_free(con);
}

/*
 * sepol_class_del_constraint() must match by pointer identity, not by
 * deep value equality: two distinct sepol_constraint_t objects that
 * happen to have identical perms/exprs are legitimate (add_constraint()
 * never deduplicates by value), so deleting one must never also delete
 * or otherwise disturb an unrelated, merely value-equal sibling -- doing
 * so would silently weaken the policy (fewer constraints than the
 * caller asked to keep) and risks a use-after-free/double-free if the
 * caller still holds a pointer to that sibling.
 */
static void test_constraint_del_uses_identity(void)
{
	sepol_class_t *class;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &class), 0);
	CU_ASSERT_EQUAL(sepol_class_set_name(handle, class, "testcls"), 0);

	/* c1 and c2b are distinct objects with identical content ("read") */
	sepol_constraint_t *c1;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &c1), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, c1, "read"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_constraint(handle, class, c1), 0);

	sepol_constraint_t *c2a;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &c2a), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, c2a, "write"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_constraint(handle, class, c2a), 0);

	sepol_constraint_t *c2b;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &c2b), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, c2b, "write"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_constraint(handle, class, c2b), 0);

	const sepol_constraint_t **cons;
	uint32_t ncons;
	CU_ASSERT_EQUAL(
		sepol_class_get_constraints(handle, class, &cons, &ncons), 0);
	CU_ASSERT_EQUAL(ncons, 3);
	free(cons);

	/* A freshly-created, never-added, but value-equal object must not
	 * be found (and must not delete anything) purely on content match.
	 */
	sepol_constraint_t *not_added;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &not_added), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, not_added, "read"),
			0);
	CU_ASSERT_NOT_EQUAL(
		sepol_class_del_constraint(handle, class, not_added), 0);

	CU_ASSERT_EQUAL(
		sepol_class_get_constraints(handle, class, &cons, &ncons), 0);
	CU_ASSERT_EQUAL(ncons, 3);
	free(cons);

	/* Deleting c2a (by identity) must remove exactly c2a, leaving its
	 * value-equal sibling c2b (and unrelated c1) untouched.
	 */
	CU_ASSERT_EQUAL(sepol_class_del_constraint(handle, class, c2a), 0);

	CU_ASSERT_EQUAL(
		sepol_class_get_constraints(handle, class, &cons, &ncons), 0);
	CU_ASSERT_EQUAL(ncons, 2);
	int seen_c1 = 0, seen_c2b = 0;
	for (uint32_t i = 0; i < ncons; i++) {
		if (cons[i] == c1)
			seen_c1 = 1;
		else if (cons[i] == c2b)
			seen_c2b = 1;
	}
	CU_ASSERT_TRUE(seen_c1);
	CU_ASSERT_TRUE(seen_c2b);
	free(cons);

	/* Delete the two remaining constraints (by identity) */
	CU_ASSERT_EQUAL(sepol_class_del_constraint(handle, class, c1), 0);
	CU_ASSERT_EQUAL(sepol_class_del_constraint(handle, class, c2b), 0);

	CU_ASSERT_EQUAL(
		sepol_class_get_constraints(handle, class, &cons, &ncons), 0);
	CU_ASSERT_EQUAL(ncons, 0);
	CU_ASSERT_PTR_NULL(cons);

	sepol_constraint_free(not_added);
	sepol_class_free(class);
}

static void test_constraint_clone_null_args(void)
{
	sepol_constraint_t *con = NULL, *con_clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &con), 0);
	CU_ASSERT(sepol_constraint_clone(handle, NULL, &con_clone) != 0);
	CU_ASSERT_PTR_NULL(con_clone);
	CU_ASSERT(sepol_constraint_clone(handle, con, NULL) != 0);
	sepol_constraint_free(con);

	sepol_constraint_expr_t *expr = NULL, *expr_clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_create(handle, &expr), 0);
	CU_ASSERT(sepol_constraint_expr_clone(handle, NULL, &expr_clone) != 0);
	CU_ASSERT_PTR_NULL(expr_clone);
	CU_ASSERT(sepol_constraint_expr_clone(handle, expr, NULL) != 0);
	sepol_constraint_expr_free(expr);
}

static void test_type_modify_add_and_modify(void)
{
	sepol_policydb_t *p;
	CU_ASSERT_EQUAL_FATAL(sepol_policydb_create(&p), 0);
	/* sepol_type_modify only supports source-format (base/module)
	 * policydbs; a freshly created policydb defaults to POLICY_KERN. */
	p->p.policy_type = POLICY_BASE;

	/* Add a new regular type */
	sepol_type_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, "member_t", &key),
			      0);

	sepol_type_t *data;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &data), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, data, "member_t"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_flavor(handle, data, SEPOL_TYPE_TYPE),
			0);
	CU_ASSERT_EQUAL(sepol_type_set_flag(handle, data,
					    SEPOL_TYPE_FLAGS_PERMISSIVE),
			0);

	CU_ASSERT_EQUAL_FATAL(sepol_type_modify(handle, p, key, data), 0);
	sepol_type_free(data);

	int exists = 0;
	CU_ASSERT_EQUAL(sepol_type_exists(handle, p, key, &exists), 0);
	CU_ASSERT_TRUE(exists);

	sepol_type_t *queried = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_query(handle, p, key, &queried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_type_get_name(queried), "member_t");
	CU_ASSERT_EQUAL(sepol_type_get_flavor(queried), SEPOL_TYPE_TYPE);
	CU_ASSERT_TRUE(
		sepol_type_has_flag(queried, SEPOL_TYPE_FLAGS_PERMISSIVE));
	sepol_type_free(queried);
	sepol_type_key_free(key);

	/* Add an attribute with "member_t" as a member type */
	sepol_type_key_t *akey;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, "myattr_t", &akey),
			      0);

	sepol_type_t *adata;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &adata), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, adata, "myattr_t"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_flavor(handle, adata, SEPOL_TYPE_ATTRIB),
			0);
	CU_ASSERT_EQUAL(sepol_type_add_subtype(handle, adata, "member_t"), 0);

	CU_ASSERT_EQUAL_FATAL(sepol_type_modify(handle, p, akey, adata), 0);
	sepol_type_free(adata);

	sepol_type_t *aqueried = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_query(handle, p, akey, &aqueried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(aqueried);
	CU_ASSERT_EQUAL(sepol_type_get_flavor(aqueried), SEPOL_TYPE_ATTRIB);

	const char **subtypes;
	uint32_t nsub;
	CU_ASSERT_EQUAL(
		sepol_type_get_subtypes(handle, aqueried, &subtypes, &nsub), 0);
	CU_ASSERT_EQUAL(nsub, 1);
	if (nsub == 1)
		CU_ASSERT_STRING_EQUAL(subtypes[0], "member_t");
	free(subtypes);
	sepol_type_free(aqueried);

	/* Modifying the attribute replaces its membership entirely */
	sepol_type_t *adata2;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &adata2), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, adata2, "myattr_t"), 0);
	CU_ASSERT_EQUAL(
		sepol_type_set_flavor(handle, adata2, SEPOL_TYPE_ATTRIB), 0);

	CU_ASSERT_EQUAL_FATAL(sepol_type_modify(handle, p, akey, adata2), 0);
	sepol_type_free(adata2);

	sepol_type_t *aqueried2 = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_query(handle, p, akey, &aqueried2), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(aqueried2);
	CU_ASSERT_EQUAL(sepol_type_get_subtypes(handle, aqueried2, &subtypes,
						&nsub),
			0);
	CU_ASSERT_EQUAL(nsub, 0);
	CU_ASSERT_PTR_NULL(subtypes);
	sepol_type_free(aqueried2);
	sepol_type_key_free(akey);

	/* Aliases are not supported */
	sepol_type_key_t *alkey;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, "alias_t", &alkey),
			      0);
	sepol_type_t *aldata;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &aldata), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, aldata, "alias_t"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_flavor(handle, aldata, SEPOL_TYPE_ALIAS),
			0);
	CU_ASSERT(sepol_type_modify(handle, p, alkey, aldata) != 0);
	sepol_type_free(aldata);
	sepol_type_key_free(alkey);

	sepol_policydb_free(p);
}

static void test_type_modify_rejects_kernel_maps(void)
{
	/* `policy` has already been through expand_module(), which builds
	 * the kernel-format attr_type_map/type_attr_map cross-reference
	 * tables; sepol_type_modify must refuse to mutate it. */
	sepol_type_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, "some_new_t", &key),
			      0);

	sepol_type_t *data;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &data), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, data, "some_new_t"), 0);
	CU_ASSERT_EQUAL(sepol_type_set_flavor(handle, data, SEPOL_TYPE_TYPE),
			0);

	CU_ASSERT(sepol_type_modify(handle, policy, key, data) != 0);

	sepol_type_free(data);
	sepol_type_key_free(key);
}

static int context_check(const char *user, const char *role, const char *type,
			 const char *mls_level)
{
	sepol_context_t *con;
	int ret;

	CU_ASSERT_EQUAL_FATAL(sepol_context_create(handle, &con), 0);
	CU_ASSERT_EQUAL(sepol_context_set_user(handle, con, user), 0);
	CU_ASSERT_EQUAL(sepol_context_set_role(handle, con, role), 0);
	CU_ASSERT_EQUAL(sepol_context_set_type(handle, con, type), 0);
	if (mls_level)
		CU_ASSERT_EQUAL(sepol_context_set_mls(handle, con, mls_level),
				0);

	ret = sepol_context_check(handle, policy, con);
	sepol_context_free(con);
	return ret;
}

static void test_user_modify_preserves_existing_on_validation_failure(void)
{
	sepol_user_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_user_key_create(handle, "USER1", &key), 0);

	sepol_user_t *orig = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_user_query(handle, policy, key, &orig), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(orig);

	const char **orig_roles = NULL;
	unsigned int orig_num_roles = 0;
	CU_ASSERT_EQUAL_FATAL(sepol_user_get_roles(handle, orig, &orig_roles,
						   &orig_num_roles),
			      0);
	CU_ASSERT_EQUAL(orig_num_roles, 1);

	sepol_user_t *broken;
	CU_ASSERT_EQUAL_FATAL(sepol_user_clone(handle, orig, &broken), 0);
	CU_ASSERT_EQUAL(sepol_user_add_role(handle, broken, "NO_SUCH_ROLE"), 0);

	/* Modification must fail, and -- unlike the pre-fix behavior, which
	 * destroyed/reinitialized the user_datum before validating role
	 * names -- must leave the existing user completely untouched. */
	CU_ASSERT(sepol_user_modify(handle, policy, key, broken) != 0);
	sepol_user_free(broken);

	sepol_user_t *after = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_user_query(handle, policy, key, &after), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(after);

	const char **after_roles = NULL;
	unsigned int after_num_roles = 0;
	CU_ASSERT_EQUAL_FATAL(sepol_user_get_roles(handle, after, &after_roles,
						   &after_num_roles),
			      0);
	CU_ASSERT_EQUAL(after_num_roles, orig_num_roles);
	if (after_num_roles == orig_num_roles && orig_num_roles > 0)
		CU_ASSERT_STRING_EQUAL(after_roles[0], orig_roles[0]);

	const char *orig_mlslevel = sepol_user_get_mlslevel(orig);
	const char *after_mlslevel = sepol_user_get_mlslevel(after);
	if (orig_mlslevel) {
		CU_ASSERT_STRING_EQUAL(after_mlslevel, orig_mlslevel);
	} else {
		CU_ASSERT_PTR_NULL(after_mlslevel);
	}

	/* USER1's role cache must still validate exactly as before. */
	CU_ASSERT_EQUAL(context_check("USER1", "ROLE1", "TYPE1", orig_mlslevel),
			0);

	free(orig_roles);
	free(after_roles);
	sepol_user_free(orig);
	sepol_user_free(after);
	sepol_user_key_free(key);
}

static void test_user_modify_rebuilds_role_cache(void)
{
	sepol_user_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_user_key_create(handle, "USER1", &key), 0);

	sepol_user_t *orig = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_user_query(handle, policy, key, &orig), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(orig);

	const char *mls_level = sepol_user_get_mlslevel(orig);

	/* Baseline: USER1 is only authorized for ROLE1/TYPE1 before the
	 * modify below. */
	CU_ASSERT_EQUAL(context_check("USER1", "ROLE1", "TYPE1", mls_level), 0);
	CU_ASSERT(context_check("USER1", "ROLE2", "TYPE2", mls_level) != 0);

	sepol_user_t *modified;
	CU_ASSERT_EQUAL_FATAL(sepol_user_clone(handle, orig, &modified), 0);

	const char *new_roles[] = { "ROLE2" };
	CU_ASSERT_EQUAL(sepol_user_set_roles(handle, modified, new_roles, 1),
			0);

	CU_ASSERT_EQUAL_FATAL(sepol_user_modify(handle, policy, key, modified),
			      0);
	sepol_user_free(modified);

	/*
	 * After modifying an *existing* user, the expanded role cache used
	 * by sepol_context_check()/context_is_valid() must reflect the new
	 * role set -- not the empty cache left behind by
	 * user_datum_init(), and not the stale pre-modify cache.
	 */
	CU_ASSERT_EQUAL(context_check("USER1", "ROLE2", "TYPE2", mls_level), 0);
	CU_ASSERT(context_check("USER1", "ROLE1", "TYPE1", mls_level) != 0);

	/* Restore USER1 to its original role set: this suite's `policy`
	 * fixture is shared across all tests in this file. */
	CU_ASSERT_EQUAL_FATAL(sepol_user_modify(handle, policy, key, orig), 0);
	CU_ASSERT_EQUAL(context_check("USER1", "ROLE1", "TYPE1", mls_level), 0);

	sepol_user_free(orig);
	sepol_user_key_free(key);
}

static void test_user_clone_unnamed(void)
{
	sepol_user_t *user;
	CU_ASSERT_EQUAL_FATAL(sepol_user_create(handle, &user), 0);

	/* A freshly created user has no name yet; cloning it must fail
	 * cleanly instead of calling strdup(NULL). */
	sepol_user_t *cloned = NULL;
	CU_ASSERT(sepol_user_clone(handle, user, &cloned) != 0);
	CU_ASSERT_PTR_NULL(cloned);

	sepol_user_free(user);
}

static void test_bool_clone_unnamed(void)
{
	sepol_bool_t *boolean;
	CU_ASSERT_EQUAL_FATAL(sepol_bool_create(handle, &boolean), 0);

	/* A freshly created boolean has no name yet; cloning it must fail
	 * cleanly instead of calling strdup(NULL). */
	sepol_bool_t *cloned = NULL;
	CU_ASSERT(sepol_bool_clone(handle, boolean, &cloned) != 0);
	CU_ASSERT_PTR_NULL(cloned);

	sepol_bool_free(boolean);
}

static void test_class_exists_query_key_compare(void)
{
	sepol_class_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_class_key_create(handle, "CLASS1", &key),
			      0);

	const char *keyname = NULL;
	sepol_class_key_unpack(key, &keyname);
	CU_ASSERT_STRING_EQUAL(keyname, "CLASS1");

	int exists = 0;
	CU_ASSERT_EQUAL_FATAL(sepol_class_exists(handle, policy, key, &exists),
			      0);
	CU_ASSERT_TRUE(exists);

	sepol_class_t *queried = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_class_query(handle, policy, key, &queried),
			      0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_class_get_name(queried), "CLASS1");
	CU_ASSERT_EQUAL(sepol_class_compare(queried, key), 0);

	sepol_class_key_t *extracted = NULL;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_key_extract(handle, queried, &extracted), 0);
	CU_ASSERT_EQUAL(sepol_class_compare(queried, extracted), 0);
	sepol_class_key_free(extracted);

	sepol_class_t *clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_class_clone(handle, queried, &clone), 0);
	CU_ASSERT_EQUAL(sepol_class_compare2(queried, clone), 0);
	sepol_class_free(clone);

	/* A non-existent key must report exists=0 and query=>NULL, not an
	 * error, and must not compare equal to CLASS1. */
	sepol_class_key_t *missing_key;
	CU_ASSERT_EQUAL_FATAL(sepol_class_key_create(handle, "NO_SUCH_CLASS",
						     &missing_key),
			      0);

	exists = 1;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_exists(handle, policy, missing_key, &exists), 0);
	CU_ASSERT_FALSE(exists);

	sepol_class_t *missing_queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL_FATAL(sepol_class_query(handle, policy, missing_key,
						&missing_queried),
			      0);
	CU_ASSERT_PTR_NULL(missing_queried);

	CU_ASSERT(sepol_class_compare(queried, missing_key) != 0);

	sepol_class_key_free(missing_key);
	sepol_class_key_free(key);
	sepol_class_free(queried);
}

static void test_class_query_by_value_and_value_to_name(void)
{
	uint32_t value = class_value("CLASS1");

	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_class_value_to_name(handle, policy, value, &name),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(name);
	CU_ASSERT_STRING_EQUAL(name, "CLASS1");

	sepol_class_t *queried = NULL;
	CU_ASSERT_EQUAL(
		sepol_class_query_by_value(handle, policy, value, &queried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_class_get_name(queried), "CLASS1");
	sepol_class_free(queried);

	/* Out-of-range values: value_to_name is an error; query_by_value
	 * succeeds and reports "not found" via a NULL response. */
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(sepol_class_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(sepol_class_value_to_name(handle, policy,
						      UINT32_MAX, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);

	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_class_query_by_value(handle, policy, 0, &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);
	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_class_query_by_value(handle, policy, UINT32_MAX,
						   &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);

	/* NULL-argument handling */
	CU_ASSERT_NOT_EQUAL(
		sepol_class_value_to_name(handle, NULL, value, &name), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_class_value_to_name(handle, policy, value, NULL), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_class_query_by_value(handle, NULL, value, &queried), 0);
	CU_ASSERT_PTR_NULL(queried);
	CU_ASSERT_NOT_EQUAL(
		sepol_class_query_by_value(handle, policy, value, NULL), 0);
}

static void test_class_set_default_roundtrip(void)
{
	sepol_class_t *cls;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &cls), 0);
	CU_ASSERT_EQUAL(sepol_class_set_name(handle, cls, "testclass"), 0);

	/* Freshly created class defaults to all-zero defaults. */
	CU_ASSERT_EQUAL(sepol_class_get_default_user(cls), 0);
	CU_ASSERT_EQUAL(sepol_class_get_default_role(cls), 0);
	CU_ASSERT_EQUAL(sepol_class_get_default_type(cls), 0);
	CU_ASSERT_EQUAL(sepol_class_get_default_range(cls), 0);

	CU_ASSERT_EQUAL(sepol_class_set_default_user(
				handle, cls, SEPOL_CLASS_DEFAULT_SOURCE),
			0);
	CU_ASSERT_EQUAL(sepol_class_get_default_user(cls),
			SEPOL_CLASS_DEFAULT_SOURCE);

	CU_ASSERT_EQUAL(sepol_class_set_default_role(
				handle, cls, SEPOL_CLASS_DEFAULT_TARGET),
			0);
	CU_ASSERT_EQUAL(sepol_class_get_default_role(cls),
			SEPOL_CLASS_DEFAULT_TARGET);

	CU_ASSERT_EQUAL(sepol_class_set_default_type(
				handle, cls, SEPOL_CLASS_DEFAULT_SOURCE),
			0);
	CU_ASSERT_EQUAL(sepol_class_get_default_type(cls),
			SEPOL_CLASS_DEFAULT_SOURCE);

	CU_ASSERT_EQUAL(sepol_class_set_default_range(
				handle, cls,
				SEPOL_CLASS_DEFAULT_SOURCE_LOW_HIGH),
			0);
	CU_ASSERT_EQUAL(sepol_class_get_default_range(cls),
			SEPOL_CLASS_DEFAULT_SOURCE_LOW_HIGH);

	sepol_class_free(cls);
}

static void test_class_has_perm_and_del_perm(void)
{
	sepol_class_t *cls;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &cls), 0);
	CU_ASSERT_EQUAL(sepol_class_set_name(handle, cls, "testclass"), 0);

	CU_ASSERT_FALSE(sepol_class_has_perm(cls, "read"));
	CU_ASSERT_EQUAL(sepol_class_add_perm(handle, cls, "read"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_perm(handle, cls, "write"), 0);
	CU_ASSERT_TRUE(sepol_class_has_perm(cls, "read"));
	CU_ASSERT_TRUE(sepol_class_has_perm(cls, "write"));
	CU_ASSERT_FALSE(sepol_class_has_perm(cls, "execute"));

	CU_ASSERT_EQUAL(sepol_class_del_perm(handle, cls, "read"), 0);
	CU_ASSERT_FALSE(sepol_class_has_perm(cls, "read"));
	CU_ASSERT_TRUE(sepol_class_has_perm(cls, "write"));

	const char **perms;
	uint32_t nperms;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_get_perms(handle, cls, &perms, &nperms), 0);
	CU_ASSERT_EQUAL(nperms, 1);
	if (nperms == 1)
		CU_ASSERT_STRING_EQUAL(perms[0], "write");
	free(perms);

	sepol_class_free(cls);
}

static void test_class_validatetrans_roundtrip(void)
{
	sepol_class_t *cls;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &cls), 0);
	CU_ASSERT_EQUAL(sepol_class_set_name(handle, cls, "testclass"), 0);

	const sepol_constraint_t **vtrans;
	uint32_t nvtrans;
	CU_ASSERT_EQUAL(sepol_class_get_validatetrans(handle, cls, &vtrans,
						      &nvtrans),
			0);
	CU_ASSERT_EQUAL(nvtrans, 0);
	CU_ASSERT_PTR_NULL(vtrans);

	sepol_constraint_t *vt;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &vt), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, vt, "transition"), 0);
	CU_ASSERT_EQUAL(sepol_class_add_validatetrans(handle, cls, vt), 0);

	CU_ASSERT_EQUAL(sepol_class_get_validatetrans(handle, cls, &vtrans,
						      &nvtrans),
			0);
	CU_ASSERT_EQUAL(nvtrans, 1);
	CU_ASSERT_PTR_NOT_NULL_FATAL(vtrans);
	CU_ASSERT_TRUE(sepol_constraint_has_perm(vtrans[0], "transition"));
	free(vtrans);

	/*
	 * Like sepol_class_add_constraint()/del_constraint(), add_validatetrans()
	 * takes ownership of `vt` and del_validatetrans() matches by pointer
	 * identity and frees the internally-stored object itself -- `vt` must
	 * not be freed again here.
	 */
	CU_ASSERT_EQUAL(sepol_class_del_validatetrans(handle, cls, vt), 0);
	CU_ASSERT_EQUAL(sepol_class_get_validatetrans(handle, cls, &vtrans,
						      &nvtrans),
			0);
	CU_ASSERT_EQUAL(nvtrans, 0);
	CU_ASSERT_PTR_NULL(vtrans);

	sepol_class_free(cls);
}

static void test_constraint_get_perms_del_perm_remove_expr(void)
{
	sepol_constraint_t *con;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_create(handle, &con), 0);

	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, con, "read"), 0);
	CU_ASSERT_EQUAL(sepol_constraint_add_perm(handle, con, "write"), 0);

	const char **perms;
	uint32_t nperms;
	CU_ASSERT_EQUAL_FATAL(
		sepol_constraint_get_perms(handle, con, &perms, &nperms), 0);
	CU_ASSERT_EQUAL(nperms, 2);
	free(perms);

	CU_ASSERT_EQUAL(sepol_constraint_del_perm(handle, con, "read"), 0);
	CU_ASSERT_FALSE(sepol_constraint_has_perm(con, "read"));
	CU_ASSERT_TRUE(sepol_constraint_has_perm(con, "write"));

	CU_ASSERT_EQUAL_FATAL(
		sepol_constraint_get_perms(handle, con, &perms, &nperms), 0);
	CU_ASSERT_EQUAL(nperms, 1);
	free(perms);

	sepol_constraint_expr_t *e0, *e1;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_create(handle, &e0), 0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_type(handle, e0,
						       SEPOL_CEXPR_TYPE_ATTR),
			0);
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_create(handle, &e1), 0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_type(handle, e1,
						       SEPOL_CEXPR_TYPE_NOT),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_insert_expr(handle, con, 0, e0), 0);
	CU_ASSERT_EQUAL(sepol_constraint_insert_expr(handle, con, 1, e1), 0);

	const sepol_constraint_expr_t **exprs;
	uint32_t nexprs;
	CU_ASSERT_EQUAL_FATAL(
		sepol_constraint_get_exprs(handle, con, &exprs, &nexprs), 0);
	CU_ASSERT_EQUAL(nexprs, 2);
	free(exprs);

	/* Removing index 0 must shift the remaining expr down, not leave a
	 * gap or remove the wrong one. */
	CU_ASSERT_EQUAL(sepol_constraint_remove_expr(handle, con, 0), 0);
	CU_ASSERT_EQUAL_FATAL(
		sepol_constraint_get_exprs(handle, con, &exprs, &nexprs), 0);
	CU_ASSERT_EQUAL_FATAL(nexprs, 1);
	CU_ASSERT_EQUAL(sepol_constraint_expr_get_type(exprs[0]),
			SEPOL_CEXPR_TYPE_NOT);
	free(exprs);

	/* Out-of-range index must fail without side effects. */
	CU_ASSERT(sepol_constraint_remove_expr(handle, con, 5) != 0);
	CU_ASSERT_EQUAL_FATAL(
		sepol_constraint_get_exprs(handle, con, &exprs, &nexprs), 0);
	CU_ASSERT_EQUAL(nexprs, 1);
	free(exprs);

	sepol_constraint_free(con);
}

static void test_constraint_expr_names_and_attr_accessors(void)
{
	sepol_constraint_expr_t *expr;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_create(handle, &expr), 0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_type(handle, expr,
						       SEPOL_CEXPR_TYPE_NAMES),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_op(handle, expr,
						     SEPOL_CEXPR_OP_EQ),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_get_op(expr), SEPOL_CEXPR_OP_EQ);

	CU_ASSERT_FALSE(sepol_constraint_expr_has_name(expr, "TYPE1"));
	CU_ASSERT_EQUAL(sepol_constraint_expr_add_name(handle, expr, "TYPE1"),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_add_name(handle, expr, "TYPE2"),
			0);
	CU_ASSERT_TRUE(sepol_constraint_expr_has_name(expr, "TYPE1"));
	CU_ASSERT_TRUE(sepol_constraint_expr_has_name(expr, "TYPE2"));
	CU_ASSERT_FALSE(sepol_constraint_expr_has_name(expr, "TYPE3"));

	const char **names;
	uint32_t nnames;
	CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_get_names(handle, expr,
							      &names, &nnames),
			      0);
	CU_ASSERT_EQUAL(nnames, 2);
	free(names);

	CU_ASSERT_EQUAL(sepol_constraint_expr_del_name(handle, expr, "TYPE1"),
			0);
	CU_ASSERT_FALSE(sepol_constraint_expr_has_name(expr, "TYPE1"));
	CU_ASSERT_TRUE(sepol_constraint_expr_has_name(expr, "TYPE2"));

	/* Attribute bitmask accessors */
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_attr(handle, expr,
						       SEPOL_CEXPR_ATTR_TYPE),
			0);
	CU_ASSERT_EQUAL(sepol_constraint_expr_set_attr(handle, expr,
						       SEPOL_CEXPR_ATTR_TARGET),
			0);
	CU_ASSERT_TRUE(
		sepol_constraint_expr_has_attr(expr, SEPOL_CEXPR_ATTR_TYPE));
	CU_ASSERT_TRUE(
		sepol_constraint_expr_has_attr(expr, SEPOL_CEXPR_ATTR_TARGET));

	CU_ASSERT_EQUAL(sepol_constraint_expr_unset_attr(
				handle, expr, SEPOL_CEXPR_ATTR_TARGET),
			0);
	CU_ASSERT_TRUE(
		sepol_constraint_expr_has_attr(expr, SEPOL_CEXPR_ATTR_TYPE));
	CU_ASSERT_FALSE(
		sepol_constraint_expr_has_attr(expr, SEPOL_CEXPR_ATTR_TARGET));

	CU_ASSERT_EQUAL(sepol_constraint_expr_clear_attr(handle, expr), 0);
	CU_ASSERT_FALSE(
		sepol_constraint_expr_has_attr(expr, SEPOL_CEXPR_ATTR_TYPE));

	sepol_constraint_expr_free(expr);
}

static void test_role_exists_query_key_compare(void)
{
	sepol_role_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_role_key_create(handle, "ROLE1", &key), 0);

	const char *keyname = NULL;
	sepol_role_key_unpack(key, &keyname);
	CU_ASSERT_STRING_EQUAL(keyname, "ROLE1");

	int exists = 0;
	CU_ASSERT_EQUAL_FATAL(sepol_role_exists(handle, policy, key, &exists),
			      0);
	CU_ASSERT_TRUE(exists);

	sepol_role_t *queried = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_role_query(handle, policy, key, &queried),
			      0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_role_get_name(queried), "ROLE1");
	CU_ASSERT_EQUAL(sepol_role_compare(queried, key), 0);

	sepol_role_key_t *extracted = NULL;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_key_extract(handle, queried, &extracted), 0);
	CU_ASSERT_EQUAL(sepol_role_compare(queried, extracted), 0);
	sepol_role_key_free(extracted);

	sepol_role_t *clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_role_clone(handle, queried, &clone), 0);
	CU_ASSERT_EQUAL(sepol_role_compare2(queried, clone), 0);
	sepol_role_free(clone);

	sepol_role_key_t *missing_key;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_key_create(handle, "NO_SUCH_ROLE", &missing_key), 0);

	exists = 1;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_exists(handle, policy, missing_key, &exists), 0);
	CU_ASSERT_FALSE(exists);

	sepol_role_t *missing_queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL_FATAL(sepol_role_query(handle, policy, missing_key,
					       &missing_queried),
			      0);
	CU_ASSERT_PTR_NULL(missing_queried);

	CU_ASSERT(sepol_role_compare(queried, missing_key) != 0);

	sepol_role_key_free(missing_key);
	sepol_role_key_free(key);
	sepol_role_free(queried);
}

static void test_role_query_by_value_and_value_to_name(void)
{
	uint32_t value = role_value("ROLE1");

	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_role_value_to_name(handle, policy, value, &name),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(name);
	CU_ASSERT_STRING_EQUAL(name, "ROLE1");

	sepol_role_t *queried = NULL;
	CU_ASSERT_EQUAL(
		sepol_role_query_by_value(handle, policy, value, &queried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_role_get_name(queried), "ROLE1");
	sepol_role_free(queried);

	/* Out-of-range values: value_to_name is an error; query_by_value
	 * succeeds and reports "not found" via a NULL response. */
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(sepol_role_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(
		sepol_role_value_to_name(handle, policy, UINT32_MAX, &name), 0);
	CU_ASSERT_PTR_NULL(name);

	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_role_query_by_value(handle, policy, 0, &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);
	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_role_query_by_value(handle, policy, UINT32_MAX,
						  &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);

	/* NULL-argument handling */
	CU_ASSERT_NOT_EQUAL(
		sepol_role_value_to_name(handle, NULL, value, &name), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_role_value_to_name(handle, policy, value, NULL), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_role_query_by_value(handle, NULL, value, &queried), 0);
	CU_ASSERT_PTR_NULL(queried);
	CU_ASSERT_NOT_EQUAL(
		sepol_role_query_by_value(handle, policy, value, NULL), 0);
}

static void test_role_type_membership(void)
{
	sepol_role_t *role;
	CU_ASSERT_EQUAL_FATAL(sepol_role_create(handle, &role), 0);
	CU_ASSERT_EQUAL(sepol_role_set_name(handle, role, "testrole"), 0);

	CU_ASSERT_FALSE(sepol_role_has_type(role, "type_a"));
	CU_ASSERT_EQUAL(sepol_role_add_type(handle, role, "type_a"), 0);
	CU_ASSERT_EQUAL(sepol_role_add_type(handle, role, "type_b"), 0);
	CU_ASSERT_TRUE(sepol_role_has_type(role, "type_a"));
	CU_ASSERT_TRUE(sepol_role_has_type(role, "type_b"));

	const char **types;
	uint32_t ntypes;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_get_types(handle, role, &types, &ntypes), 0);
	CU_ASSERT_EQUAL(ntypes, 2);
	free(types);

	CU_ASSERT_EQUAL(sepol_role_del_type(handle, role, "type_a"), 0);
	CU_ASSERT_FALSE(sepol_role_has_type(role, "type_a"));
	CU_ASSERT_TRUE(sepol_role_has_type(role, "type_b"));

	CU_ASSERT_EQUAL_FATAL(
		sepol_role_get_types(handle, role, &types, &ntypes), 0);
	CU_ASSERT_EQUAL(ntypes, 1);
	if (ntypes == 1)
		CU_ASSERT_STRING_EQUAL(types[0], "type_b");
	free(types);

	sepol_role_free(role);
}

static void test_role_bounds_and_flavor(void)
{
	sepol_role_t *role;
	CU_ASSERT_EQUAL_FATAL(sepol_role_create(handle, &role), 0);
	CU_ASSERT_EQUAL(sepol_role_set_name(handle, role, "testrole"), 0);

	CU_ASSERT_PTR_NULL(sepol_role_get_bounds(role));
	CU_ASSERT_EQUAL(sepol_role_set_bounds(handle, role, "parent_role"), 0);
	CU_ASSERT_STRING_EQUAL(sepol_role_get_bounds(role), "parent_role");
	CU_ASSERT_EQUAL(sepol_role_set_bounds(handle, role, NULL), 0);
	CU_ASSERT_PTR_NULL(sepol_role_get_bounds(role));

	CU_ASSERT_EQUAL(sepol_role_get_flavor(role), SEPOL_ROLE_ROLE);
	CU_ASSERT_EQUAL(sepol_role_set_flavor(handle, role, SEPOL_ROLE_ATTRIB),
			0);
	CU_ASSERT_EQUAL(sepol_role_get_flavor(role), SEPOL_ROLE_ATTRIB);

	sepol_role_free(role);
}

static void test_role_del_subrole(void)
{
	sepol_role_t *role;
	CU_ASSERT_EQUAL_FATAL(sepol_role_create(handle, &role), 0);
	CU_ASSERT_EQUAL(sepol_role_set_name(handle, role, "testattr"), 0);

	CU_ASSERT_EQUAL(sepol_role_add_subrole(handle, role, "sub_a"), 0);
	CU_ASSERT_EQUAL(sepol_role_add_subrole(handle, role, "sub_b"), 0);

	CU_ASSERT_EQUAL(sepol_role_del_subrole(handle, role, "sub_a"), 0);

	const char **subroles;
	uint32_t nsub;
	CU_ASSERT_EQUAL_FATAL(
		sepol_role_get_subroles(handle, role, &subroles, &nsub), 0);
	CU_ASSERT_EQUAL(nsub, 1);
	if (nsub == 1)
		CU_ASSERT_STRING_EQUAL(subroles[0], "sub_b");
	free(subroles);

	sepol_role_free(role);
}

static void test_type_key_unpack_extract_and_compare(void)
{
	sepol_type_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_create(handle, "TYPE1", &key), 0);

	const char *keyname = NULL;
	sepol_type_key_unpack(key, &keyname);
	CU_ASSERT_STRING_EQUAL(keyname, "TYPE1");

	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, type, "TYPE1"), 0);

	CU_ASSERT_EQUAL(sepol_type_compare(type, key), 0);

	sepol_type_key_t *extracted = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_key_extract(handle, type, &extracted),
			      0);
	CU_ASSERT_EQUAL(sepol_type_compare(type, extracted), 0);
	sepol_type_key_free(extracted);

	sepol_type_t *other;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &other), 0);
	CU_ASSERT_EQUAL(sepol_type_set_name(handle, other, "TYPE2"), 0);
	CU_ASSERT(sepol_type_compare(other, key) != 0);
	CU_ASSERT(sepol_type_compare2(type, other) != 0);

	sepol_type_t *clone;
	CU_ASSERT_EQUAL_FATAL(sepol_type_clone(handle, type, &clone), 0);
	CU_ASSERT_EQUAL(sepol_type_compare2(type, clone), 0);

	sepol_type_free(clone);
	sepol_type_free(other);
	sepol_type_free(type);
	sepol_type_key_free(key);
}

static void test_type_query_by_value_and_value_to_name(void)
{
	uint32_t value = type_value("TYPE1");

	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_type_value_to_name(handle, policy, value, &name),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(name);
	CU_ASSERT_STRING_EQUAL(name, "TYPE1");

	sepol_type_t *queried = NULL;
	CU_ASSERT_EQUAL(
		sepol_type_query_by_value(handle, policy, value, &queried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_type_get_name(queried), "TYPE1");
	sepol_type_free(queried);

	/* Out-of-range values: value_to_name is an error; query_by_value
	 * succeeds and reports "not found" via a NULL response. */
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(sepol_type_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(
		sepol_type_value_to_name(handle, policy, UINT32_MAX, &name), 0);
	CU_ASSERT_PTR_NULL(name);

	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_type_query_by_value(handle, policy, 0, &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);
	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_type_query_by_value(handle, policy, UINT32_MAX,
						  &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);

	/* NULL-argument handling */
	CU_ASSERT_NOT_EQUAL(
		sepol_type_value_to_name(handle, NULL, value, &name), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_type_value_to_name(handle, policy, value, NULL), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_type_query_by_value(handle, NULL, value, &queried), 0);
	CU_ASSERT_PTR_NULL(queried);
	CU_ASSERT_NOT_EQUAL(
		sepol_type_query_by_value(handle, policy, value, NULL), 0);
}

static void test_type_unset_flag(void)
{
	sepol_type_t *type;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);

	CU_ASSERT_EQUAL(sepol_type_set_flag(handle, type,
					    SEPOL_TYPE_FLAGS_PERMISSIVE),
			0);
	CU_ASSERT_EQUAL(sepol_type_set_flag(handle, type,
					    SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE),
			0);
	CU_ASSERT_TRUE(sepol_type_has_flag(type, SEPOL_TYPE_FLAGS_PERMISSIVE));
	CU_ASSERT_TRUE(
		sepol_type_has_flag(type, SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE));

	CU_ASSERT_EQUAL(sepol_type_unset_flag(handle, type,
					      SEPOL_TYPE_FLAGS_PERMISSIVE),
			0);
	CU_ASSERT_FALSE(sepol_type_has_flag(type, SEPOL_TYPE_FLAGS_PERMISSIVE));
	CU_ASSERT_TRUE(
		sepol_type_has_flag(type, SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE));

	sepol_type_free(type);
}

static void test_user_exists(void)
{
	sepol_user_key_t *key;
	CU_ASSERT_EQUAL_FATAL(sepol_user_key_create(handle, "USER1", &key), 0);

	int exists = 0;
	CU_ASSERT_EQUAL_FATAL(sepol_user_exists(handle, policy, key, &exists),
			      0);
	CU_ASSERT_TRUE(exists);
	sepol_user_key_free(key);

	sepol_user_key_t *missing_key;
	CU_ASSERT_EQUAL_FATAL(
		sepol_user_key_create(handle, "NO_SUCH_USER", &missing_key), 0);
	exists = 1;
	CU_ASSERT_EQUAL_FATAL(
		sepol_user_exists(handle, policy, missing_key, &exists), 0);
	CU_ASSERT_FALSE(exists);
	sepol_user_key_free(missing_key);
}

static void test_user_query_by_value_and_value_to_name(void)
{
	uint32_t value = user_value("USER1");

	const char *name = NULL;
	CU_ASSERT_EQUAL(sepol_user_value_to_name(handle, policy, value, &name),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(name);
	CU_ASSERT_STRING_EQUAL(name, "USER1");

	sepol_user_t *queried = NULL;
	CU_ASSERT_EQUAL(
		sepol_user_query_by_value(handle, policy, value, &queried), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(queried);
	CU_ASSERT_STRING_EQUAL(sepol_user_get_name(queried), "USER1");
	sepol_user_free(queried);

	/* Out-of-range values: value_to_name is an error; query_by_value
	 * succeeds and reports "not found" via a NULL response. */
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(sepol_user_value_to_name(handle, policy, 0, &name),
			    0);
	CU_ASSERT_PTR_NULL(name);
	name = (void *)0xdeadbeef;
	CU_ASSERT_NOT_EQUAL(
		sepol_user_value_to_name(handle, policy, UINT32_MAX, &name), 0);
	CU_ASSERT_PTR_NULL(name);

	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_user_query_by_value(handle, policy, 0, &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);
	queried = (void *)0xdeadbeef;
	CU_ASSERT_EQUAL(sepol_user_query_by_value(handle, policy, UINT32_MAX,
						  &queried),
			0);
	CU_ASSERT_PTR_NULL(queried);

	/* NULL-argument handling */
	CU_ASSERT_NOT_EQUAL(
		sepol_user_value_to_name(handle, NULL, value, &name), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_user_value_to_name(handle, policy, value, NULL), 0);
	CU_ASSERT_NOT_EQUAL(
		sepol_user_query_by_value(handle, NULL, value, &queried), 0);
	CU_ASSERT_PTR_NULL(queried);
	CU_ASSERT_NOT_EQUAL(
		sepol_user_query_by_value(handle, policy, value, NULL), 0);
}

static void test_context_values_null_args(void)
{
	CU_ASSERT(sepol_values_to_context_string(handle, NULL, 1, 1, 1, NULL,
						 NULL, NULL) != 0);
	CU_ASSERT(sepol_values_to_context_record(handle, NULL, 1, 1, 1, NULL,
						 NULL) != 0);
}

static void test_null_args(void)
{
	/* _iter_create: NULL policydb must fail and clear *iter, even
	 * when the pointer previously held a bogus/stale value. */
	sepol_type_iter_t *titer = (void *)0xdeadbeef;
	CU_ASSERT(sepol_type_iter_create(handle, NULL, &titer) != 0);
	CU_ASSERT_PTR_NULL(titer);
	CU_ASSERT(sepol_type_iter_create(handle, policy, NULL) != 0);

	sepol_role_iter_t *riter = (void *)0xdeadbeef;
	CU_ASSERT(sepol_role_iter_create(handle, NULL, &riter) != 0);
	CU_ASSERT_PTR_NULL(riter);
	CU_ASSERT(sepol_role_iter_create(handle, policy, NULL) != 0);

	sepol_class_iter_t *citer = (void *)0xdeadbeef;
	CU_ASSERT(sepol_class_iter_create(handle, NULL, &citer) != 0);
	CU_ASSERT_PTR_NULL(citer);
	CU_ASSERT(sepol_class_iter_create(handle, policy, NULL) != 0);

	/* _iter_next: any NULL output parameter must be rejected rather
	 * than dereferenced. */
	CU_ASSERT_EQUAL_FATAL(sepol_type_iter_create(handle, policy, &titer),
			      0);
	CU_ASSERT(sepol_type_iter_next(handle, titer, NULL) != 0);
	sepol_type_iter_destroy(titer);

	CU_ASSERT_EQUAL_FATAL(sepol_role_iter_create(handle, policy, &riter),
			      0);
	CU_ASSERT(sepol_role_iter_next(handle, riter, NULL) != 0);
	sepol_role_iter_destroy(riter);

	CU_ASSERT_EQUAL_FATAL(sepol_class_iter_create(handle, policy, &citer),
			      0);
	CU_ASSERT(sepol_class_iter_next(handle, citer, NULL) != 0);
	sepol_class_iter_destroy(citer);
}

static void test_clone_null_args(void)
{
	sepol_type_t *type = NULL, *type_clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_type_create(handle, &type), 0);
	CU_ASSERT(sepol_type_clone(handle, NULL, &type_clone) != 0);
	CU_ASSERT_PTR_NULL(type_clone);
	CU_ASSERT(sepol_type_clone(handle, type, NULL) != 0);
	sepol_type_free(type);

	sepol_role_t *role = NULL, *role_clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_role_create(handle, &role), 0);
	CU_ASSERT(sepol_role_clone(handle, NULL, &role_clone) != 0);
	CU_ASSERT_PTR_NULL(role_clone);
	CU_ASSERT(sepol_role_clone(handle, role, NULL) != 0);
	sepol_role_free(role);

	sepol_class_t *cls = NULL, *class_clone = NULL;
	CU_ASSERT_EQUAL_FATAL(sepol_class_create(handle, &cls), 0);
	CU_ASSERT(sepol_class_clone(handle, NULL, &class_clone) != 0);
	CU_ASSERT_PTR_NULL(class_clone);
	CU_ASSERT(sepol_class_clone(handle, cls, NULL) != 0);
	sepol_class_free(cls);
}

int records_add_tests(CU_pSuite suite)
{
	if (CU_add_test(suite, "class_clone_deep_copy",
			test_class_clone_deep_copy) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_free_no_leak", test_class_free_no_leak) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_set_alias_of_null",
			test_type_set_alias_of_null) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_set_bounds_null",
			test_type_set_bounds_null) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_get_subtypes_empty",
			test_type_get_subtypes_empty) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_del_subtype_no_skip",
			test_type_del_subtype_no_skip) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_clone", test_type_clone) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_clone_with_subroles",
			test_role_clone_with_subroles) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "constraint_clone_deep",
			test_constraint_clone_deep) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "constraint_del_uses_identity",
			test_constraint_del_uses_identity) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "context_values_null_args",
			test_context_values_null_args) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "null_args", test_null_args) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "clone_null_args", test_clone_null_args) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "constraint_clone_null_args",
			test_constraint_clone_null_args) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_modify_add_and_modify",
			test_type_modify_add_and_modify) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_modify_rejects_kernel_maps",
			test_type_modify_rejects_kernel_maps) == NULL)
		return CU_get_error();
	if (CU_add_test(
		    suite,
		    "user_modify_preserves_existing_on_validation_failure",
		    test_user_modify_preserves_existing_on_validation_failure) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_modify_rebuilds_role_cache",
			test_user_modify_rebuilds_role_cache) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_clone_unnamed", test_user_clone_unnamed) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "bool_clone_unnamed", test_bool_clone_unnamed) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_exists_query_key_compare",
			test_class_exists_query_key_compare) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_query_by_value_and_value_to_name",
			test_class_query_by_value_and_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_set_default_roundtrip",
			test_class_set_default_roundtrip) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_has_perm_and_del_perm",
			test_class_has_perm_and_del_perm) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "class_validatetrans_roundtrip",
			test_class_validatetrans_roundtrip) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "constraint_get_perms_del_perm_remove_expr",
			test_constraint_get_perms_del_perm_remove_expr) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "constraint_expr_names_and_attr_accessors",
			test_constraint_expr_names_and_attr_accessors) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_exists_query_key_compare",
			test_role_exists_query_key_compare) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_query_by_value_and_value_to_name",
			test_role_query_by_value_and_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_type_membership",
			test_role_type_membership) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_bounds_and_flavor",
			test_role_bounds_and_flavor) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "role_del_subrole", test_role_del_subrole) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_key_unpack_extract_and_compare",
			test_type_key_unpack_extract_and_compare) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_query_by_value_and_value_to_name",
			test_type_query_by_value_and_value_to_name) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "type_unset_flag", test_type_unset_flag) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_exists", test_user_exists) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "user_query_by_value_and_value_to_name",
			test_user_query_by_value_and_value_to_name) == NULL)
		return CU_get_error();
	return 0;
}

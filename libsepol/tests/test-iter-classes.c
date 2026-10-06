#include "test-iter-classes.h"

#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/class_record.h>
#include <sepol/classes.h>
#include <sepol/policydb/constraint.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "helpers.h"

extern sepol_handle_t *handle;
extern sepol_policydb_t *empty_policy;
extern sepol_policydb_t *iter_policy;
extern int mls;

/*
 * CLASS1's constraints, from policies/test-iter/iter.conf:
 *
 *   constrain CLASS1 { PERM1 } ( t1 == { TYPE1 } );
 *   constrain CLASS1 { PERM1 } ( ( r1 == ROLE1 ) or ( u2 == USER1 ) );
 *   mlsconstrain CLASS1 { PERM1 } ( h1 dom h2 );   -- MLS builds only
 *
 * The middle constraint's expression is a boolean combination (`or`),
 * which is represented as multiple constraint_expr nodes in an
 * unspecified (postfix) order, so it is not practical to assert its
 * exact expression list here. Instead, verify_class1_constraints()
 * below checks the one property shared by every CLASS1 constraint
 * (permissions == {PERM1}) plus the exact expression contents of the
 * single unambiguous, single-expression constraint (`t1 == TYPE1`).
 */

struct expected_class {
	int seen;

	const char *name;
	const char *common;
	uint32_t nperms;
	const char *perms[32];
	char default_user;
	char default_role;
	char default_type;
	char default_range;
};

struct expected_class expected_classes[] = {
	{ 0, "CLASS1", "COMMON1", 2, { "PERM1", "ioctl" }, 0, 0, 0, 0 },
	{ 0, "CLASS01", NULL, 1, { "PERM01" }, 0, 0, 0, 0 },
	{ 0, "CLASS02", NULL, 1, { "PERM02" }, 0, 0, 0, 0 },
	{ 0, "CLASS03", NULL, 1, { "PERM03" }, 0, 0, 0, 0 },
	{ 0, "CLASS04", NULL, 1, { "PERM04" }, 0, 0, 0, 0 },
	{ 0, "CLASS05", NULL, 1, { "PERM05" }, 0, 0, 0, 0 },
	{ 0, "CLASS06", NULL, 1, { "PERM06" }, 0, 0, 0, 0 },
	{ 0, NULL, NULL, 0, { NULL }, 0, 0, 0, 0 },
};

static void verify_class1_constraints(const sepol_constraint_t **constraints,
				      uint32_t nconstraints)
{
	int found_type_names_constraint = 0;

	/* Two plain `constrain` statements always apply; the `mlsconstrain`
	 * only applies to MLS builds. */
	CU_ASSERT_EQUAL(nconstraints, mls ? 3u : 2u);

	for (uint32_t i = 0; i < nconstraints; i++) {
		const char **perms = NULL;
		uint32_t nperms = 0;
		CU_ASSERT_EQUAL_FATAL(
			sepol_constraint_get_perms(handle, constraints[i],
						   &perms, &nperms),
			0);
		CU_ASSERT_EQUAL(nperms, 1);
		if (nperms == 1)
			CU_ASSERT_STRING_EQUAL(perms[0], "PERM1");
		free(perms);

		const sepol_constraint_expr_t **exprs = NULL;
		uint32_t nexprs = 0;
		CU_ASSERT_EQUAL_FATAL(
			sepol_constraint_get_exprs(handle, constraints[i],
						   &exprs, &nexprs),
			0);

		if (nexprs == 1 &&
		    sepol_constraint_expr_get_type(exprs[0]) ==
			    SEPOL_CEXPR_TYPE_NAMES &&
		    sepol_constraint_expr_get_op(exprs[0]) ==
			    SEPOL_CEXPR_OP_EQ &&
		    sepol_constraint_expr_has_attr(exprs[0],
						   SEPOL_CEXPR_ATTR_TYPE)) {
			const char **names = NULL;
			uint32_t nnames = 0;
			CU_ASSERT_EQUAL_FATAL(sepol_constraint_expr_get_names(
						      handle, exprs[0], &names,
						      &nnames),
					      0);
			if (nnames == 1 && names[0] &&
			    !strcmp(names[0], "TYPE1"))
				found_type_names_constraint = 1;
			free(names);
		}
		free(exprs);
	}

	CU_ASSERT_TRUE(found_type_names_constraint);
}

static void unseen(void)
{
	for (struct expected_class *e = expected_classes; e->name; e++) {
		e->seen = 0;
	}
}

static void seen(const sepol_class_t *item)
{
	const char *actual_name = sepol_class_get_name(item);
	const char *actual_common = sepol_class_get_common(item);
	uint32_t nactual_perms;
	const char **actual_perms;
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_perms(handle, item, &actual_perms,
						    &nactual_perms),
			      0);
	uint32_t nactual_constraints;
	const sepol_constraint_t **actual_constraints;
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_constraints(handle, item,
							  &actual_constraints,
							  &nactual_constraints),
			      0);
	char actual_default_user = sepol_class_get_default_user(item);
	char actual_default_role = sepol_class_get_default_role(item);
	char actual_default_type = sepol_class_get_default_type(item);
	char actual_default_range = sepol_class_get_default_range(item);

	struct expected_class *e;
	for (e = expected_classes; e->name; e++) {
		if (strcmp(actual_name, e->name) == 0)
			break;
	}
	CU_ASSERT_PTR_NOT_NULL_FATAL(e->name);
	e->seen = 1;

	if (e->common) {
		CU_ASSERT_STRING_EQUAL(actual_common, e->common);
	} else {
		CU_ASSERT_PTR_NULL(actual_common);
	}

	CU_ASSERT_EQUAL(nactual_perms, e->nperms);
	/* qsort()'s base is declared nonnull; skip the call entirely for
	 * an empty (possibly NULL) array rather than relying on nmemb==0
	 * making the NULL harmless. */
	if (nactual_perms > 0)
		qsort(actual_perms, nactual_perms, sizeof(char *), qstrcmp);
	for (size_t i = 0; i < nactual_perms && i < e->nperms; i++) {
		CU_ASSERT_STRING_EQUAL(actual_perms[i], e->perms[i]);
	}

	if (strcmp(e->name, "CLASS1") == 0)
		verify_class1_constraints(actual_constraints,
					  nactual_constraints);
	else
		CU_ASSERT_EQUAL(nactual_constraints, 0);

	CU_ASSERT_EQUAL(actual_default_user, e->default_user);
	CU_ASSERT_EQUAL(actual_default_role, e->default_role);
	CU_ASSERT_EQUAL(actual_default_type, e->default_type);
	CU_ASSERT_EQUAL(actual_default_range, e->default_range);

	free(actual_perms);
	free(actual_constraints);
}

void test_iter_classes_empty(void)
{
	sepol_class_iter_t *class_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_iter_create(handle, empty_policy, &class_iter), 0);

	sepol_class_t *item;
	CU_ASSERT_EQUAL(sepol_class_iter_next(handle, class_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);
	CU_ASSERT_EQUAL(sepol_class_iter_next(handle, class_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	sepol_class_iter_destroy(class_iter);
}

void test_iter_classes_non_empty(void)
{
	unseen();
	sepol_class_t *item;
	sepol_class_iter_t *class_iter;
	CU_ASSERT_EQUAL_FATAL(
		sepol_class_iter_create(handle, iter_policy, &class_iter), 0);

	while (1) {
		CU_ASSERT_EQUAL(
			sepol_class_iter_next(handle, class_iter, &item), 0);
		if (!item)
			break;
		seen(item);
		sepol_class_free(item);
	}
	CU_ASSERT_EQUAL(sepol_class_iter_next(handle, class_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	for (struct expected_class *e = expected_classes; e->name; e++) {
		CU_ASSERT_TRUE(e->seen);
	}

	sepol_class_iter_destroy(class_iter);
}

#include "test-context-api.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include <sepol/context.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/sidtab.h>
#include <sepol/sid_table.h>

#include "parse_util.h"

extern int mls;

static sepol_handle_t *handle;
static sepol_policydb_t *policy;

int context_api_test_init(void)
{
	char filename[PATH_MAX];

	handle = sepol_handle_create();
	if (!handle)
		return -1;

	if (sepol_policydb_create(&policy)) {
		sepol_handle_destroy(handle);
		handle = NULL;
		return -1;
	}

	policydb_t *p = &policy->p;
	p->policy_type = POLICY_BASE;
	p->policyvers = MOD_POLICYDB_VERSION_MAX;
	p->mls = mls;

	if (snprintf(filename, PATH_MAX, "policies/test-iter/%s%s", "iter.conf",
		     mls ? ".mls" : ".std") < 0)
		goto err;

	if (read_source_policy(p, filename, "test-context-api"))
		goto err;

	return 0;

err:
	sepol_policydb_free(policy);
	policy = NULL;
	sepol_handle_destroy(handle);
	handle = NULL;
	return -1;
}

int context_api_test_cleanup(void)
{
	/*
	 * Tests in this suite install `policy` as the process-global active
	 * policydb via sepol_set_policydb(). Reset it before freeing the
	 * policydb so no dangling global pointer is left behind for other
	 * test suites (or later runs) to dereference.
	 */
	sepol_set_policydb(NULL);
	sepol_policydb_free(policy);
	sepol_handle_destroy(handle);
	return 0;
}

static void test_values_to_context_string(void)
{
	policydb_t *p = &policy->p;
	user_datum_t *u =
		hashtab_search(p->p_users.table, (hashtab_key_t) "USER1");
	role_datum_t *r =
		hashtab_search(p->p_roles.table, (hashtab_key_t) "ROLE1");
	type_datum_t *t =
		hashtab_search(p->p_types.table, (hashtab_key_t) "TYPE1");

	CU_ASSERT_PTR_NOT_NULL_FATAL(u);
	CU_ASSERT_PTR_NOT_NULL_FATAL(r);
	CU_ASSERT_PTR_NOT_NULL_FATAL(t);

	char *str = NULL;
	size_t len = 0;
	const char *mls_part = mls ? "s0" : NULL;

	CU_ASSERT_EQUAL(sepol_values_to_context_string(
				handle, policy, u->s.value, r->s.value,
				t->s.value, mls_part, &str, &len),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(str);

	if (!mls) {
		CU_ASSERT_STRING_EQUAL(str, "USER1:ROLE1:TYPE1");
	} else {
		CU_ASSERT(strncmp(str, "USER1:ROLE1:TYPE1:", 18) == 0);
		CU_ASSERT(strlen(str) > 18);
	}

	free(str);
}

static void test_values_to_context_record(void)
{
	policydb_t *p = &policy->p;
	user_datum_t *u =
		hashtab_search(p->p_users.table, (hashtab_key_t) "USER1");
	role_datum_t *r =
		hashtab_search(p->p_roles.table, (hashtab_key_t) "ROLE1");
	type_datum_t *t =
		hashtab_search(p->p_types.table, (hashtab_key_t) "TYPE1");

	CU_ASSERT_PTR_NOT_NULL_FATAL(u);
	CU_ASSERT_PTR_NOT_NULL_FATAL(r);
	CU_ASSERT_PTR_NOT_NULL_FATAL(t);

	sepol_context_t *rec = NULL;
	const char *mls_part = mls ? "s0" : NULL;

	CU_ASSERT_EQUAL(sepol_values_to_context_record(
				handle, policy, u->s.value, r->s.value,
				t->s.value, mls_part, &rec),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rec);

	CU_ASSERT_STRING_EQUAL(sepol_context_get_user(rec), "USER1");
	CU_ASSERT_STRING_EQUAL(sepol_context_get_role(rec), "ROLE1");
	CU_ASSERT_STRING_EQUAL(sepol_context_get_type(rec), "TYPE1");
	if (mls) {
		CU_ASSERT_PTR_NOT_NULL(sepol_context_get_mls(rec));
		CU_ASSERT(strlen(sepol_context_get_mls(rec)) > 0);
	}

	sepol_context_free(rec);
}

static void test_sid_to_context_record(void)
{
	sidtab_t sidtab;

	memset(&sidtab, 0, sizeof(sidtab));
	CU_ASSERT_EQUAL(policydb_load_isids(&policy->p, &sidtab), 0);

	sepol_set_policydb(&policy->p);
	sepol_set_sidtab(&sidtab);

	const char *ctxstr = mls ? "USER1:ROLE1:TYPE1:s0" : "USER1:ROLE1:TYPE1";
	sepol_security_id_t sid;

	CU_ASSERT_EQUAL_FATAL(
		sepol_context_to_sid(ctxstr, strlen(ctxstr) + 1, &sid), 0);

	sepol_context_t *rec = NULL;
	CU_ASSERT_EQUAL(sepol_sid_to_context_record(handle, sid, &rec), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rec);

	CU_ASSERT_STRING_EQUAL(sepol_context_get_user(rec), "USER1");
	CU_ASSERT_STRING_EQUAL(sepol_context_get_role(rec), "ROLE1");
	CU_ASSERT_STRING_EQUAL(sepol_context_get_type(rec), "TYPE1");

	sepol_context_free(rec);
	sepol_set_sidtab(NULL);
	sepol_sidtab_destroy(&sidtab);
}

static void test_sid_table_opaque(void)
{
	sepol_sid_table_t *st = sepol_sid_table_new();
	sepol_sid_table_t *st2;

	CU_ASSERT_PTR_NOT_NULL_FATAL(st);
	CU_ASSERT_EQUAL(sepol_sid_table_load_isids(st, policy), 0);

	sepol_set_policydb(&policy->p);
	CU_ASSERT_EQUAL(sepol_sid_table_set_opaque(st), 0);

	st2 = sepol_sid_table_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(st2);
	CU_ASSERT_EQUAL(sepol_sid_table_load_isids(st2, policy), 0);
	CU_ASSERT_EQUAL(sepol_sid_table_set_opaque(st2), 0);

	sepol_sid_table_free(st);

	const char *ctxstr = mls ? "USER1:ROLE1:TYPE1:s0" : "USER1:ROLE1:TYPE1";
	sepol_security_id_t sid;

	CU_ASSERT_EQUAL(sepol_context_to_sid(ctxstr, strlen(ctxstr) + 1, &sid),
			0);

	sepol_context_t *rec = NULL;
	CU_ASSERT_EQUAL(sepol_sid_to_context_record(handle, sid, &rec), 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rec);
	sepol_context_free(rec);

	sepol_sid_table_free(st2);
}

/*
 * Look up the numeric SID of a declared initial SID by name directly from
 * the policy's OCON_ISID ocontext list, rather than trying to (re)derive it
 * via sepol_context_to_sid(): that function resolves against whatever
 * sidtab happens to be globally installed at the time, and if the exact
 * context string isn't already present there, it *allocates a brand new,
 * dynamic SID* rather than an error. Since
 * sepol_policydb_sid_to_context_string()/_record() (via
 * policydb_sid_lookup_context()) only ever resolve SIDs against a sidtab
 * rebuilt strictly from the policy's *declared* initial SIDs
 * (policydb_load_isids()), a dynamically-minted SID that happens not to
 * match any declared initial SID's context would never be found there --
 * that's a test-construction bug, not a libsepol bug. Reading the SID
 * number straight out of the policy's own ocontexts list sidesteps that
 * mismatch entirely.
 */
static sepol_security_id_t find_isid(const char *name)
{
	const ocontext_t *c;

	for (c = policy->p.ocontexts[OCON_ISID]; c; c = c->next) {
		if (!strcmp(c->u.name, name))
			return c->sid[0];
	}
	CU_FAIL_FATAL("initial SID not found in test policy");
	return 0;
}

static void test_policydb_sid_to_context_without_globals(void)
{
	/*
	 * Under MLS, resolve the dedicated "isid_mls_cat" initial SID, whose
	 * context carries an actual (non-empty) category set: policydb_sid_
	 * lookup_context() copies the resolved context's MLS range out of a
	 * temporary sidtab that it destroys before returning, and a category
	 * set is the only field of context_struct_t that owns its own heap
	 * allocation (an ebitmap). A context with an empty category set
	 * would not exercise that allocation at all and would silently pass
	 * even if the copy were a shallow one sharing (and thus later
	 * dangling into) the destroyed sidtab's freed ebitmap nodes.
	 */
	const char *ctxstr = mls ? "USER1:ROLE1:TYPE1:s0:c0,c1" :
				   "USER1:ROLE1:TYPE1";
	sepol_security_id_t sid = find_isid(mls ? "isid_mls_cat" : "kernel");
	char *str = NULL;
	size_t len = 0;
	sepol_context_t *rec = NULL;

	CU_ASSERT_EQUAL(sepol_policydb_sid_to_context_string(handle, policy,
							     sid, &str, &len),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(str);
	CU_ASSERT_STRING_EQUAL(str, ctxstr);
	free(str);

	CU_ASSERT_EQUAL(sepol_policydb_sid_to_context_record(handle, policy,
							     sid, &rec),
			0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rec);
	CU_ASSERT_STRING_EQUAL(sepol_context_get_user(rec), "USER1");
	if (mls) {
		CU_ASSERT_PTR_NOT_NULL(sepol_context_get_mls(rec));
		CU_ASSERT_STRING_EQUAL(sepol_context_get_mls(rec), "s0:c0,c1");
	}
	sepol_context_free(rec);
}

int context_api_add_tests(CU_pSuite suite)
{
	if (CU_add_test(suite, "values_to_context_string",
			test_values_to_context_string) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "values_to_context_record",
			test_values_to_context_record) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "sid_to_context_record",
			test_sid_to_context_record) == NULL)
		return CU_get_error();
	if (CU_add_test(suite, "sid_table_opaque", test_sid_table_opaque) ==
	    NULL)
		return CU_get_error();
	if (CU_add_test(suite, "policydb_sid_to_context_without_globals",
			test_policydb_sid_to_context_without_globals) == NULL)
		return CU_get_error();
	return 0;
}

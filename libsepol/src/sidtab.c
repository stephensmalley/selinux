
/* Author : Stephen Smalley, <stephen.smalley.work@gmail.com> */

/* FLASK */

/*
 * Implementation of the SID table type.
 */

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/sidtab.h>
#include <sepol/sid_table.h>

#include "debug.h"
#include "flask.h"
#include "private.h"

extern int sepol_set_sidtab(sidtab_t *s);
extern sidtab_t *sepol_get_sidtab(void);

struct sepol_sid_table {
	sidtab_t tab;
};

#define SIDTAB_HASH(sid) (sid & SIDTAB_HASH_MASK)

#define INIT_SIDTAB_LOCK(s)
#define SIDTAB_LOCK(s)
#define SIDTAB_UNLOCK(s)

int sepol_sidtab_init(sidtab_t *s)
{
	s->htable = calloc(SIDTAB_SIZE, sizeof(sidtab_ptr_t));
	if (!s->htable)
		return -ENOMEM;
	s->nel = 0;
	s->next_sid = 1;
	s->shutdown = 0;
	INIT_SIDTAB_LOCK(s);
	return 0;
}

int sepol_sidtab_insert(sidtab_t *s, sepol_security_id_t sid,
			context_struct_t *context)
{
	int hvalue;
	sidtab_node_t *prev, *cur, *newnode;

	if (!s || !s->htable)
		return -ENOMEM;

	hvalue = SIDTAB_HASH(sid);
	prev = NULL;
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && sid == cur->sid) {
		errno = EEXIST;
		return -EEXIST;
	}

	newnode = (sidtab_node_t *)malloc(sizeof(sidtab_node_t));
	if (newnode == NULL)
		return -ENOMEM;
	newnode->sid = sid;
	if (context_cpy(&newnode->context, context)) {
		free(newnode);
		return -ENOMEM;
	}

	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = s->htable[hvalue];
		s->htable[hvalue] = newnode;
	}

	s->nel++;
	if (sid >= s->next_sid)
		s->next_sid = sid + 1;
	return 0;
}

context_struct_t *sepol_sidtab_search(sidtab_t *s, sepol_security_id_t sid)
{
	int hvalue;
	sidtab_node_t *cur;

	if (!s || !s->htable)
		return NULL;

	hvalue = SIDTAB_HASH(sid);
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid)
		cur = cur->next;

	if (cur == NULL || sid != cur->sid) {
		/* Remap invalid SIDs to the unlabeled SID. */
		sid = SECINITSID_UNLABELED;
		hvalue = SIDTAB_HASH(sid);
		cur = s->htable[hvalue];
		while (cur != NULL && sid > cur->sid)
			cur = cur->next;
		if (!cur || sid != cur->sid)
			return NULL;
	}

	return &cur->context;
}

int sepol_sidtab_map(sidtab_t *s,
		     int (*apply)(sepol_security_id_t sid,
				  context_struct_t *context, void *args),
		     void *args)
{
	int i, ret;
	sidtab_node_t *cur;

	if (!s || !s->htable)
		return 0;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			ret = apply(cur->sid, &cur->context, args);
			if (ret)
				return ret;
			cur = cur->next;
		}
	}
	return 0;
}

void sepol_sidtab_map_remove_on_error(sidtab_t *s,
				      int (*apply)(sepol_security_id_t sid,
						   context_struct_t *context,
						   void *args),
				      void *args)
{
	int i, ret;
	sidtab_node_t *last, *cur, *temp;

	if (!s || !s->htable)
		return;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		last = NULL;
		cur = s->htable[i];
		while (cur != NULL) {
			ret = apply(cur->sid, &cur->context, args);
			if (ret) {
				if (last) {
					last->next = cur->next;
				} else {
					s->htable[i] = cur->next;
				}

				temp = cur;
				cur = cur->next;
				context_destroy(&temp->context);
				free(temp);
				s->nel--;
			} else {
				last = cur;
				cur = cur->next;
			}
		}
	}

	return;
}

static inline sepol_security_id_t
sepol_sidtab_search_context(sidtab_t *s, context_struct_t *context)
{
	int i;
	sidtab_node_t *cur;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			if (context_cmp(&cur->context, context))
				return cur->sid;
			cur = cur->next;
		}
	}
	return 0;
}

int sepol_sidtab_context_to_sid(sidtab_t *s, context_struct_t *context,
				sepol_security_id_t *out_sid)
{
	sepol_security_id_t sid;
	int ret = 0;

	*out_sid = SEPOL_SECSID_NULL;

	sid = sepol_sidtab_search_context(s, context);
	if (!sid) {
		SIDTAB_LOCK(s);
		/* Rescan now that we hold the lock. */
		sid = sepol_sidtab_search_context(s, context);
		if (sid)
			goto unlock_out;
		/* No SID exists for the context.  Allocate a new one. */
		if (s->next_sid == UINT_MAX || s->shutdown) {
			ret = -ENOMEM;
			goto unlock_out;
		}
		sid = s->next_sid++;
		ret = sepol_sidtab_insert(s, sid, context);
		if (ret)
			s->next_sid--;
unlock_out:
		SIDTAB_UNLOCK(s);
	}

	if (ret)
		return ret;

	*out_sid = sid;
	return 0;
}

void sepol_sidtab_hash_eval(sidtab_t *h, char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	sidtab_node_t *cur;

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	printf("%s:  %d entries and %d/%d buckets used, longest chain length %d\n",
	       tag, h->nel, slots_used, SIDTAB_SIZE, max_chain_len);
}

void sepol_sidtab_destroy(sidtab_t *s)
{
	int i;
	sidtab_ptr_t cur, temp;

	if (!s || !s->htable)
		return;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			context_destroy(&temp->context);
			free(temp);
		}
		s->htable[i] = NULL;
	}
	free(s->htable);
	s->htable = NULL;
	s->nel = 0;
	s->next_sid = 1;
}

void sepol_sidtab_set(sidtab_t *dst, sidtab_t *src)
{
	SIDTAB_LOCK(src);
	dst->htable = src->htable;
	dst->nel = src->nel;
	dst->next_sid = src->next_sid;
	dst->shutdown = 0;
	SIDTAB_UNLOCK(src);
}

void sepol_sidtab_shutdown(sidtab_t *s)
{
	SIDTAB_LOCK(s);
	s->shutdown = 1;
	SIDTAB_UNLOCK(s);
}

sepol_sid_table_t *sepol_sid_table_new(void)
{
	sepol_sid_table_t *st;

	st = calloc(1, sizeof(*st));
	if (!st)
		return NULL;
	if (sepol_sidtab_init(&st->tab) < 0) {
		free(st);
		return NULL;
	}
	return st;
}

void sepol_sid_table_free(sepol_sid_table_t *tab)
{
	if (!tab)
		return;
	/*
	 * Compare against the actual, currently-installed sidtab rather
	 * than tracking "did we last install this via
	 * sepol_sid_table_set_opaque()" in a separate variable: the latter
	 * can desynchronize from reality if sepol_set_sidtab() is later
	 * called directly (it is a separate public API), which would
	 * otherwise cause this function to incorrectly clear an unrelated,
	 * still-active global sidtab.
	 */
	if (sepol_get_sidtab() == &tab->tab)
		sepol_set_sidtab(NULL);
	sepol_sidtab_destroy(&tab->tab);
	free(tab);
}

int sepol_sid_table_load_isids(sepol_sid_table_t *tab,
			       sepol_policydb_t *policydb)
{
	sidtab_t tmp;
	int rc;

	if (!tab || !policydb)
		return STATUS_ERR;

	/*
	 * Build the reloaded table into a local temporary first. Destroying
	 * the caller's existing table before knowing whether the reload
	 * even succeeds (policydb_load_isids() can fail on OOM or on a
	 * malformed policydb with duplicate initial SIDs) would permanently
	 * blank out a previously-valid SID table on failure, breaking every
	 * subsequent sepol_sidtab_search() lookup with no way to recover.
	 */
	rc = policydb_load_isids(&policydb->p, &tmp);
	if (rc) {
		sepol_sidtab_destroy(&tmp);
		return STATUS_ERR;
	}

	sepol_sidtab_destroy(&tab->tab);
	sepol_sidtab_set(&tab->tab, &tmp);
	return 0;
}

int sepol_sid_table_set_opaque(sepol_sid_table_t *tab)
{
	if (!tab)
		return STATUS_ERR;
	return sepol_set_sidtab(&tab->tab);
}

/* FLASK */

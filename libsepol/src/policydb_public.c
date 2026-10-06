#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>
#include "policydb_internal.h"
#include "sepol/policydb.h"

/* Policy file interfaces. */

int sepol_policy_file_create(sepol_policy_file_t **pf)
{
	*pf = calloc(1, sizeof(sepol_policy_file_t));
	if (!(*pf))
		return -1;
	return 0;
}

void sepol_policy_file_set_mem(sepol_policy_file_t *spf, char *data, size_t len)
{
	struct policy_file *pf = &spf->pf;
	if (!len) {
		pf->type = PF_LEN;
		return;
	}
	pf->type = PF_USE_MEMORY;
	pf->data = data;
	pf->len = len;
	pf->size = len;
	return;
}

void sepol_policy_file_set_fp(sepol_policy_file_t *spf, FILE *fp)
{
	struct policy_file *pf = &spf->pf;
	pf->type = PF_USE_STDIO;
	pf->fp = fp;
	return;
}

int sepol_policy_file_get_len(sepol_policy_file_t *spf, size_t *len)
{
	struct policy_file *pf = &spf->pf;
	if (pf->type != PF_LEN)
		return -1;
	*len = pf->len;
	return 0;
}

void sepol_policy_file_set_handle(sepol_policy_file_t *pf,
				  sepol_handle_t *handle)
{
	pf->pf.handle = handle;
}

void sepol_policy_file_free(sepol_policy_file_t *pf)
{
	free(pf);
}

/* Policydb interfaces. */

int sepol_policydb_create(sepol_policydb_t **sp)
{
	policydb_t *p;
	*sp = malloc(sizeof(sepol_policydb_t));
	if (!(*sp))
		return -1;
	p = &(*sp)->p;
	if (policydb_init(p)) {
		free(*sp);
		*sp = NULL;
		return -1;
	}
	return 0;
}

void sepol_policydb_free(sepol_policydb_t *p)
{
	if (!p)
		return;
	policydb_destroy(&p->p);
	free(p);
}

int sepol_policy_kern_vers_min(void)
{
	return POLICYDB_VERSION_MIN;
}

int sepol_policy_kern_vers_max(void)
{
	return POLICYDB_VERSION_MAX;
}

int sepol_policydb_set_typevers(sepol_policydb_t *sp, unsigned int type)
{
	struct policydb *p = &sp->p;
	switch (type) {
	case POLICY_KERN:
		p->policyvers = POLICYDB_VERSION_MAX;
		break;
	case POLICY_BASE:
	case POLICY_MOD:
		p->policyvers = MOD_POLICYDB_VERSION_MAX;
		break;
	default:
		return -1;
	}
	p->policy_type = type;
	return 0;
}

int sepol_policydb_set_vers(sepol_policydb_t *sp, unsigned int vers)
{
	struct policydb *p = &sp->p;
	switch (p->policy_type) {
	case POLICY_KERN:
		if (vers < POLICYDB_VERSION_MIN || vers > POLICYDB_VERSION_MAX)
			return -1;
		break;
	case POLICY_BASE:
	case POLICY_MOD:
		if (vers < MOD_POLICYDB_VERSION_MIN ||
		    vers > MOD_POLICYDB_VERSION_MAX)
			return -1;
		break;
	default:
		return -1;
	}
	p->policyvers = vers;
	return 0;
}

unsigned int sepol_policydb_get_vers(const sepol_policydb_t *sp)
{
	return sp ? sp->p.policyvers : 0;
}

int sepol_policydb_set_handle_unknown(sepol_policydb_t *sp,
				      unsigned int handle_unknown)
{
	struct policydb *p = &sp->p;

	switch (handle_unknown) {
	case SEPOL_DENY_UNKNOWN:
	case SEPOL_REJECT_UNKNOWN:
	case SEPOL_ALLOW_UNKNOWN:
		break;
	default:
		return -1;
	}

	p->handle_unknown = handle_unknown;
	return 0;
}

unsigned int sepol_policydb_get_handle_unknown(const sepol_policydb_t *sp)
{
	return sp ? sp->p.handle_unknown : 0;
}

int sepol_policydb_set_target_platform(sepol_policydb_t *sp,
				       int target_platform)
{
	struct policydb *p = &sp->p;

	switch (target_platform) {
	case SEPOL_TARGET_SELINUX:
	case SEPOL_TARGET_XEN:
		break;
	default:
		return -1;
	}

	p->target_platform = target_platform;
	return 0;
}

int sepol_policydb_get_target_platform(const sepol_policydb_t *sp)
{
	return sp ? sp->p.target_platform : SEPOL_TARGET_SELINUX;
}

int sepol_policydb_optimize(sepol_policydb_t *p)
{
	return policydb_optimize(&p->p);
}

int sepol_policydb_read(sepol_policydb_t *p, sepol_policy_file_t *pf)
{
	return policydb_read(&p->p, &pf->pf, 0);
}

int sepol_policydb_write(sepol_policydb_t *p, sepol_policy_file_t *pf)
{
	return policydb_write(&p->p, &pf->pf);
}

int sepol_policydb_from_image(sepol_handle_t *handle, void *data, size_t len,
			      sepol_policydb_t *p)
{
	return policydb_from_image(handle, data, len, &p->p);
}

int sepol_policydb_to_image(sepol_handle_t *handle, sepol_policydb_t *p,
			    void **newdata, size_t *newlen)
{
	return policydb_to_image(handle, &p->p, newdata, newlen);
}

int sepol_policydb_mls_enabled(const sepol_policydb_t *p)
{
	if (!p)
		return 0;
	return p->p.mls;
}

/* 
 * Enable compatibility mode for SELinux network checks iff
 * the packet class is not defined in the policy.
 */
#define PACKET_CLASS_NAME "packet"
int sepol_policydb_compat_net(const sepol_policydb_t *p)
{
	if (!p)
		return 0;
	return (hashtab_search(p->p.p_classes.table, PACKET_CLASS_NAME) ==
		NULL);
}

int sepol_policydb_set_permissive_flags(sepol_handle_t *handle
					__attribute__((unused)),
					sepol_policydb_t *p)
{
	if (!p)
		return -1;
	policydb_t *pdb = &p->p;
	ebitmap_node_t *node;
	unsigned int bit;

	ebitmap_for_each_positive_bit(&pdb->permissive_map, node, bit) {
		if (bit < 1 || bit > pdb->p_types.nprim)
			continue;
		if (!pdb->type_val_to_struct[bit - 1])
			continue;
		pdb->type_val_to_struct[bit - 1]->flags |=
			TYPE_FLAGS_PERMISSIVE;
	}

	return 0;
}

int sepol_policydb_rebuild_attr_map(sepol_handle_t *handle, sepol_policydb_t *p)
{
	if (!p)
		return -1;
	policydb_t *pdb = &p->p;
	uint32_t nprim = pdb->p_types.nprim;
	uint32_t i;
	ebitmap_node_t *node;
	unsigned int bit;
	int rc = 0;

	if (!pdb->attr_type_map)
		return 0;

	/*
	 * Pass 1: pre-allocate synthetic names for unnamed attributes
	 * before touching any ebitmaps.  Name installation is additive
	 * (NULL -> non-NULL) and harmless, so early return on OOM here
	 * leaves the policy in a consistent state.
	 *
	 * The synthetic name is inserted into p_types.table as the real
	 * hashtab key for the attribute, and p_type_val_to_name[i] is set
	 * to alias that same key -- exactly like every ordinarily-named
	 * type/attribute (see type_datum insertion in policydb.c). This
	 * way the name is freed exactly once, by the normal symtab
	 * teardown in policydb_destroy(), instead of leaking (writing a
	 * separately-owned allocation directly into p_type_val_to_name[]
	 * would never be freed, since that array only ever holds borrowed
	 * pointers into the hashtab).
	 */
	for (i = 0; i < nprim; i++) {
		type_datum_t *datum = pdb->type_val_to_struct[i];
		if (!datum || datum->flavor != TYPE_ATTRIB)
			continue;
		if (pdb->p_type_val_to_name[i])
			continue;

		char *synth = malloc(16);
		if (!synth) {
			ERR(handle, "out of memory");
			return -1;
		}
		snprintf(synth, 16, "@ttr%010u", i + 1);
		int hrc = hashtab_insert(pdb->p_types.table, synth,
					 (hashtab_datum_t)datum);
		if (hrc < 0) {
			free(synth);
			if (hrc == SEPOL_EEXIST)
				ERR(handle,
				    "synthetic attribute name already exists");
			else
				ERR(handle, "out of memory");
			return -1;
		}
		pdb->p_type_val_to_name[i] = synth;
	}

	/*
	 * Pass 2: clear every existing reverse-mapping entry first, so this
	 * rebuild recomputes type_attr_map[] from scratch based solely on
	 * the *current* attr_type_map[] contents, rather than monotonically
	 * unioning in new bits on top of whatever a previous rebuild (or the
	 * initial policy load) left behind. Without this, removing a type
	 * from an attribute (or removing an attribute's last member) would
	 * leave a stale bit in type_attr_map[] -- and since services.c's AV
	 * computation reads type_attr_map[] directly to resolve a type's
	 * attribute membership, a stale bit there is a real policy
	 * correctness/security issue, not just an API bookkeeping nit.
	 */
	for (i = 0; i < nprim; i++)
		ebitmap_destroy(&pdb->type_attr_map[i]);

	/*
	 * Pass 3: restore the mandatory "type/attribute is a member of
	 * itself" bit that Pass 2 above just destroyed for every entry.
	 * This mirrors policydb_read()'s "add the type itself as the
	 * degenerate case" step, which unconditionally sets this bit for
	 * every valid type_val_to_struct[i] (type *or* attribute) when a
	 * kernel policy is first loaded (see policydb.c). It is not
	 * optional bookkeeping: services.c's AV-decision hot path reads
	 * type_attr_map[] directly to expand a context's type value into
	 * every {type,attribute} value that can appear as an avtab key's
	 * source/target, so without this bit any allow rule written
	 * against a literal type (rather than through an attribute) would
	 * silently stop matching after this rebuild -- and a type that is
	 * not a member of any attribute at all would lose *all* direct AV
	 * matches for it. Must run before Pass 4 below, so a type that is
	 * also an attribute member still ends up with both bits set.
	 */
	for (i = 0; i < nprim; i++) {
		if (!pdb->type_val_to_struct[i])
			continue;
		if (ebitmap_set_bit(&pdb->type_attr_map[i], i, 1) < 0) {
			ERR(handle,
			    "out of memory restoring self-membership bit");
			rc = -1;
		}
	}

	/*
	 * Pass 4: copy (never move) the forward maps from attr_type_map
	 * into datum->types and build reverse mappings. attr_type_map[i]
	 * must remain intact afterwards: type_datum_to_record() reads
	 * directly from p->attr_type_map/p->type_attr_map for a
	 * POLICY_KERN policydb (the only policy_type for which this
	 * function's early "!attr_type_map" guard lets it run at all),
	 * so destructively moving the bitmap out of attr_type_map here
	 * would silently zero out every subsequent
	 * sepol_type_query()/sepol_type_query_by_value() result for
	 * this attribute. Likewise, the reverse (type -> its attributes)
	 * mapping consulted by type_datum_to_record() for a regular
	 * type in POLICY_KERN mode is p->type_attr_map[], not that
	 * type's own type_datum->types field (which is dead data for
	 * POLICY_KERN) -- so the reverse map must be written into
	 * type_attr_map[bit], not type_val_to_struct[bit]->types. If
	 * ebitmap_cpy/ebitmap_set_bit fails (OOM), log the error but
	 * continue to leave the policy in the most complete state
	 * possible rather than returning mid-loop with some attributes
	 * migrated and others not.
	 *
	 * datum->types is always reset first (even when attr_type_map[i]
	 * is now empty) so an attribute that lost its last member ends up
	 * with an accurately-empty membership set instead of retaining
	 * stale entries from before the removal.
	 */
	for (i = 0; i < nprim; i++) {
		type_datum_t *datum = pdb->type_val_to_struct[i];
		if (!datum || datum->flavor != TYPE_ATTRIB)
			continue;

		ebitmap_destroy(&datum->types);

		if (ebitmap_length(&pdb->attr_type_map[i]) == 0)
			continue;

		if (ebitmap_cpy(&datum->types, &pdb->attr_type_map[i]) < 0) {
			ERR(handle, "out of memory copying attribute map");
			rc = -1;
			continue;
		}

		ebitmap_for_each_positive_bit(&datum->types, node, bit) {
			if (bit >= nprim)
				continue;
			if (!pdb->type_val_to_struct[bit])
				continue;
			if (ebitmap_set_bit(&pdb->type_attr_map[bit], i, 1) <
			    0) {
				ERR(handle,
				    "out of memory building reverse attr map");
				rc = -1;
			}
		}
	}

	return rc;
}

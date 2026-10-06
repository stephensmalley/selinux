#include <sepol/polcap.h>

#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/polcaps.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"

struct sepol_polcap_iter {
	const ebitmap_t *caps;
	ebitmap_node_t *node;
	uint32_t bit;
	uint32_t highbit;
};

int sepol_polcap_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			     sepol_polcap_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_polcap_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->caps = &p->p.policycaps;
	tmp->bit = ebitmap_start(tmp->caps, &tmp->node);
	tmp->highbit = ebitmap_length(tmp->caps);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_polcap_iter_destroy(sepol_polcap_iter_t *iter)
{
	free(iter);
}

int sepol_polcap_iter_next(sepol_handle_t *handle __attribute__((unused)),
			   sepol_polcap_iter_t *iter, uint32_t *cap_num,
			   const char **cap_name)
{
	if (!iter || !cap_num || !cap_name)
		return STATUS_ERR;

	if (!ebitmap_find_next_set_bit(&iter->node, &iter->bit,
				       iter->highbit)) {
		*cap_num = 0;
		*cap_name = NULL;
		return STATUS_SUCCESS;
	}

	*cap_num = iter->bit;
	*cap_name = sepol_polcap_getname(iter->bit);

	iter->bit = ebitmap_next(&iter->node, iter->bit);

	return STATUS_SUCCESS;
}

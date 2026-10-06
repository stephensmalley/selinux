#include <sepol/permissive.h>

#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"

struct sepol_permissive_iter {
	const ebitmap_t *map;
	ebitmap_node_t *node;
	uint32_t bit;
	uint32_t highbit;
};

int sepol_permissive_iter_create(sepol_handle_t *handle,
				 const sepol_policydb_t *p,
				 sepol_permissive_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_permissive_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->map = &p->p.permissive_map;
	tmp->bit = ebitmap_start(tmp->map, &tmp->node);
	tmp->highbit = ebitmap_length(tmp->map);

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_permissive_iter_destroy(sepol_permissive_iter_t *iter)
{
	free(iter);
}

int sepol_permissive_iter_next(sepol_handle_t *handle __attribute__((unused)),
			       sepol_permissive_iter_t *iter,
			       uint32_t *type_value)
{
	if (!iter || !type_value)
		return STATUS_ERR;

	if (!ebitmap_find_next_set_bit(&iter->node, &iter->bit,
				       iter->highbit)) {
		*type_value = 0;
		return STATUS_SUCCESS;
	}

	*type_value = iter->bit;

	iter->bit = ebitmap_next(&iter->node, iter->bit);

	return STATUS_SUCCESS;
}

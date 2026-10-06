#include <sepol/cat_set.h>

#include <sepol/policydb/ebitmap.h>
#include <stdlib.h>

#include "cat_set_internal.h"
#include "debug.h"

struct sepol_cat_set_iter {
	ebitmap_node_t *node;
	uint32_t bit;
	uint32_t highbit;
};

int cat_set_iter_create_from_ebitmap(const ebitmap_t *map,
				     sepol_cat_set_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!map) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_cat_set_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->bit = ebitmap_start(map, &tmp->node);
	tmp->highbit = ebitmap_length(map);

	*iter = tmp;
	return STATUS_SUCCESS;
}

int sepol_cat_set_iter_next(sepol_handle_t *handle __attribute__((unused)),
			    sepol_cat_set_iter_t *iter, uint32_t *cat_value)
{
	if (!iter || !cat_value)
		return STATUS_ERR;

	if (!ebitmap_find_next_set_bit(&iter->node, &iter->bit,
				       iter->highbit)) {
		*cat_value = 0;
		return STATUS_SUCCESS;
	}

	*cat_value = iter->bit + 1;

	iter->bit = ebitmap_next(&iter->node, iter->bit);

	return STATUS_SUCCESS;
}

void sepol_cat_set_iter_destroy(sepol_cat_set_iter_t *iter)
{
	free(iter);
}

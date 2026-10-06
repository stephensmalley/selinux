#ifndef _SEPOL_CAT_SET_INTERNAL_H_
#define _SEPOL_CAT_SET_INTERNAL_H_

#include <sepol/cat_set.h>
#include <sepol/policydb/ebitmap.h>

int cat_set_iter_create_from_ebitmap(const ebitmap_t *map,
				     sepol_cat_set_iter_t **iter);

#endif

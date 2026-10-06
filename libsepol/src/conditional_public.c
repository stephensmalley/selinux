#include <sepol/conditional.h>
#include <sepol/constants.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "av_rule_internal.h"
#include "debug.h"

/* --- Conditional block iterator --- */

struct sepol_cond_iter {
	const cond_node_t *cur;
	const cond_node_t *next;
};

int sepol_cond_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_cond_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_cond_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->cur = NULL;
	tmp->next = p->p.cond_list;
	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_cond_iter_destroy(sepol_cond_iter_t *iter)
{
	free(iter);
}

int sepol_cond_iter_next(sepol_handle_t *handle __attribute__((unused)),
			 sepol_cond_iter_t *iter, int *has_next)
{
	if (!iter || !has_next)
		return STATUS_ERR;

	iter->cur = iter->next;
	if (!iter->cur) {
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->next = iter->cur->next;
	*has_next = 1;
	return STATUS_SUCCESS;
}

/* --- Conditional expression sub-iterator --- */

struct sepol_cond_expr_iter {
	const cond_expr_t *expr;
};

int sepol_cond_expr_iter_create(sepol_handle_t *handle,
				const sepol_cond_iter_t *cond_iter,
				sepol_cond_expr_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!cond_iter) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (!cond_iter->cur) {
		ERR(handle, "no current conditional block");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_cond_expr_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->expr = cond_iter->cur->expr;
	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_cond_expr_iter_destroy(sepol_cond_expr_iter_t *iter)
{
	free(iter);
}

int sepol_cond_expr_iter_next(sepol_handle_t *handle __attribute__((unused)),
			      sepol_cond_expr_iter_t *iter, uint32_t *expr_type,
			      uint32_t *bool_value)
{
	if (!iter || !expr_type || !bool_value)
		return STATUS_ERR;

	if (!iter->expr) {
		*expr_type = 0;
		*bool_value = 0;
		return STATUS_SUCCESS;
	}

	*expr_type = iter->expr->expr_type;
	*bool_value = iter->expr->boolean;

	iter->expr = iter->expr->next;
	return STATUS_SUCCESS;
}

/* --- Conditional rule list sub-iterator --- */

struct sepol_cond_rule_iter {
	const cond_av_list_t *cur;
	const avtab_datum_t *last_datum;
	uint16_t last_specified;
};

int sepol_cond_rule_iter_create(sepol_handle_t *handle,
				const sepol_cond_iter_t *cond_iter,
				int is_true_list, sepol_cond_rule_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!cond_iter) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (!cond_iter->cur) {
		ERR(handle, "no current conditional block");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_cond_rule_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}
	tmp->cur = is_true_list ? cond_iter->cur->true_list :
				  cond_iter->cur->false_list;
	tmp->last_datum = NULL;
	tmp->last_specified = 0;
	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_cond_rule_iter_destroy(sepol_cond_rule_iter_t *iter)
{
	free(iter);
}

int sepol_cond_rule_iter_next(sepol_handle_t *handle __attribute__((unused)),
			      sepol_cond_rule_iter_t *iter, uint32_t *ruletype,
			      uint32_t *source_type, uint32_t *target_type,
			      uint32_t *target_class)
{
	if (!iter || !ruletype || !source_type || !target_type || !target_class)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last_datum = NULL;
		iter->last_specified = 0;
		*ruletype = 0;
		*source_type = 0;
		*target_type = 0;
		*target_class = 0;
		return STATUS_SUCCESS;
	}

	/* Skip entries with NULL node (pruned/disabled rules) */
	while (iter->cur && !iter->cur->node)
		iter->cur = iter->cur->next;

	if (!iter->cur) {
		iter->last_datum = NULL;
		iter->last_specified = 0;
		*ruletype = 0;
		*source_type = 0;
		*target_type = 0;
		*target_class = 0;
		return STATUS_SUCCESS;
	}

	avtab_ptr_t node = iter->cur->node;
	avtab_key_t *key = &node->key;

	iter->last_datum = &node->datum;
	iter->last_specified = key->specified;

	*ruletype = key->specified & ~AVTAB_ENABLED;
	*source_type = key->source_type;
	*target_type = key->target_type;
	*target_class = key->target_class;

	iter->cur = iter->cur->next;
	return STATUS_SUCCESS;
}

uint32_t sepol_cond_rule_iter_get_av_data(const sepol_cond_rule_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_av_data(iter->last_datum, iter->last_specified);
}

uint32_t sepol_cond_rule_iter_get_type_data(const sepol_cond_rule_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_type_data(iter->last_datum);
}

uint8_t sepol_cond_rule_iter_get_xperm_type(const sepol_cond_rule_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_xperm_type(iter->last_datum);
}

uint8_t
sepol_cond_rule_iter_get_xperm_driver(const sepol_cond_rule_iter_t *iter)
{
	if (!iter)
		return 0;
	return avtab_datum_get_xperm_driver(iter->last_datum);
}

int sepol_cond_rule_xperm_iter_create(sepol_handle_t *handle,
				      const sepol_cond_rule_iter_t *iter,
				      sepol_xperm_iter_t **xperm_iter)
{
	if (!xperm_iter)
		return STATUS_ERR;
	if (!iter) {
		*xperm_iter = NULL;
		return STATUS_ERR;
	}

	if (!iter->last_datum || !iter->last_datum->xperms) {
		ERR(handle, "no xperms data on current conditional rule entry");
		*xperm_iter = NULL;
		return STATUS_ERR;
	}

	return sepol_xperm_iter_create_from_datum(
		handle, iter->last_datum->xperms, xperm_iter);
}

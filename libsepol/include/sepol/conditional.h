#ifndef _SEPOL_CONDITIONAL_H_
#define _SEPOL_CONDITIONAL_H_

#include <sepol/av_rule.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SEPOL_COND_BOOL 1
#define SEPOL_COND_NOT 2
#define SEPOL_COND_OR 3
#define SEPOL_COND_AND 4
#define SEPOL_COND_XOR 5
#define SEPOL_COND_EQ 6
#define SEPOL_COND_NEQ 7

/* --- Conditional block iterator --- */

struct sepol_cond_iter;
typedef struct sepol_cond_iter sepol_cond_iter_t;

extern int sepol_cond_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_cond_iter_t **iter);

extern void sepol_cond_iter_destroy(sepol_cond_iter_t *iter);

/*
 * Advance to the next conditional block.
 * Sets *has_next to 0 when done.
 */
extern int sepol_cond_iter_next(sepol_handle_t *handle, sepol_cond_iter_t *iter,
				int *has_next);

/* --- Conditional expression sub-iterator --- */

struct sepol_cond_expr_iter;
typedef struct sepol_cond_expr_iter sepol_cond_expr_iter_t;

extern int sepol_cond_expr_iter_create(sepol_handle_t *handle,
				       const sepol_cond_iter_t *cond_iter,
				       sepol_cond_expr_iter_t **iter);

extern void sepol_cond_expr_iter_destroy(sepol_cond_expr_iter_t *iter);

/*
 * Get the next expression node (reverse polish notation).
 * Sets *expr_type to 0 when done.
 * For SEPOL_COND_BOOL, *bool_value is the 1-based boolean value;
 * for operators it is unused.
 */
extern int sepol_cond_expr_iter_next(sepol_handle_t *handle,
				     sepol_cond_expr_iter_t *iter,
				     uint32_t *expr_type, uint32_t *bool_value);

/* --- Conditional rule list sub-iterator --- */

struct sepol_cond_rule_iter;
typedef struct sepol_cond_rule_iter sepol_cond_rule_iter_t;

/*
 * Create an iterator over the true (is_true_list=1) or false
 * (is_true_list=0) rule list of the current conditional block.
 */
extern int sepol_cond_rule_iter_create(sepol_handle_t *handle,
				       const sepol_cond_iter_t *cond_iter,
				       int is_true_list,
				       sepol_cond_rule_iter_t **iter);

extern void sepol_cond_rule_iter_destroy(sepol_cond_rule_iter_t *iter);

/*
 * Get the next conditional rule. Sets *ruletype to 0 when done.
 */
extern int sepol_cond_rule_iter_next(sepol_handle_t *handle,
				     sepol_cond_rule_iter_t *iter,
				     uint32_t *ruletype, uint32_t *source_type,
				     uint32_t *target_type,
				     uint32_t *target_class);

extern uint32_t
sepol_cond_rule_iter_get_av_data(const sepol_cond_rule_iter_t *iter);

extern uint32_t
sepol_cond_rule_iter_get_type_data(const sepol_cond_rule_iter_t *iter);

extern uint8_t
sepol_cond_rule_iter_get_xperm_type(const sepol_cond_rule_iter_t *iter);

extern uint8_t
sepol_cond_rule_iter_get_xperm_driver(const sepol_cond_rule_iter_t *iter);

/*
 * Create an xperm sub-iterator from the current conditional rule entry.
 * Reuses sepol_xperm_iter_t from av_rule.h.
 */
extern int sepol_cond_rule_xperm_iter_create(sepol_handle_t *handle,
					     const sepol_cond_rule_iter_t *iter,
					     sepol_xperm_iter_t **xperm_iter);

#ifdef __cplusplus
}
#endif

#endif

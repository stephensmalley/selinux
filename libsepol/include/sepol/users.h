#ifndef _SEPOL_USERS_H_
#define _SEPOL_USERS_H_

#include <sepol/cat_set.h>
#include <sepol/policydb.h>
#include <sepol/user_record.h>
#include <sepol/handle.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_user_iter;
typedef struct sepol_user_iter sepol_user_iter_t;

/* Modify the user, or add it, if the key is not found.
 * On failure when adding a new user, the user may still have been inserted
 * into the policydb with an incomplete role set; the policydb remains
 * memory-safe to use and destroy, but should not be relied upon to be
 * fully consistent for that user. */
extern int sepol_user_modify(sepol_handle_t *handle, sepol_policydb_t *policydb,
			     const sepol_user_key_t *key,
			     const sepol_user_t *data);

/* Return the number of users */
extern int sepol_user_count(sepol_handle_t *handle, const sepol_policydb_t *p,
			    unsigned int *response);

/* Check if the specified user exists */
extern int sepol_user_exists(sepol_handle_t *handle,
			     const sepol_policydb_t *policydb,
			     const sepol_user_key_t *key, int *response);

/* Query a user - returns the user or NULL if not found */
extern int sepol_user_query(sepol_handle_t *handle, const sepol_policydb_t *p,
			    const sepol_user_key_t *key,
			    sepol_user_t **response);

/* Resolve a user value to its name.  Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_user_value_to_name(sepol_handle_t *handle,
				    const sepol_policydb_t *p, uint32_t value,
				    const char **name);

/* Query a user by value - returns the user or NULL if not found */
extern int sepol_user_query_by_value(sepol_handle_t *handle,
				     const sepol_policydb_t *p, uint32_t value,
				     sepol_user_t **response);

/* Iterate the users
 * The handler may return:
 * -1 to signal an error condition,
 * 1 to signal successful exit
 * 0 to signal continue */
extern int sepol_user_iterate(sepol_handle_t *handle,
			      const sepol_policydb_t *policydb,
			      int (*fn)(const sepol_user_t *user, void *fn_arg),
			      void *arg);

/*
 * Users iterator. Iteration order follows ascending internal value
 * assignment, which typically -- but is not guaranteed to -- match
 * declaration order; callers should not treat it as a stable guarantee
 * across policydb versions.
 */
extern int sepol_user_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_user_iter_t **iter);
extern void sepol_user_iter_destroy(sepol_user_iter_t *iter);
extern int sepol_user_iter_next(sepol_handle_t *handle, sepol_user_iter_t *iter,
				sepol_user_t **item);

extern uint32_t sepol_user_get_dflt_level_sens(const sepol_policydb_t *p,
					       uint32_t user_value);

/*
 * NOTE on sepol_cat_set_iter_t **cat_iter parameters below: see the
 * ownership contract documented in cat_set.h. The callee always allocates
 * a new, caller-owned iterator that must be freed with
 * sepol_cat_set_iter_destroy().
 */
extern int sepol_user_get_dflt_level_cat(sepol_handle_t *handle,
					 const sepol_policydb_t *p,
					 uint32_t user_value,
					 sepol_cat_set_iter_t **cat_iter);

extern uint32_t sepol_user_get_range_low_sens(const sepol_policydb_t *p,
					      uint32_t user_value);

extern uint32_t sepol_user_get_range_high_sens(const sepol_policydb_t *p,
					       uint32_t user_value);

extern int sepol_user_get_range_low_cat(sepol_handle_t *handle,
					const sepol_policydb_t *p,
					uint32_t user_value,
					sepol_cat_set_iter_t **cat_iter);

extern int sepol_user_get_range_high_cat(sepol_handle_t *handle,
					 const sepol_policydb_t *p,
					 uint32_t user_value,
					 sepol_cat_set_iter_t **cat_iter);

#ifdef __cplusplus
}
#endif

#endif

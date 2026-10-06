#ifndef _SEPOL_AV_RULE_H_
#define _SEPOL_AV_RULE_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Avtab entry iterator --- */

struct sepol_avtab_iter;
typedef struct sepol_avtab_iter sepol_avtab_iter_t;

/*
 * Create an iterator over unconditional TE rules (te_avtab).
 * If 'specified' is 0, all rule types are returned. Otherwise it is a
 * bitmask of AVTAB_* flags (from constants.h) to filter by.
 *
 * Iteration order is unspecified (currently hash-bucket order of the
 * internal avtab) and may change between library versions or policydb
 * loads; callers must not rely on it matching rule declaration order.
 */
extern int sepol_avtab_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   uint32_t specified,
				   sepol_avtab_iter_t **iter);

extern void sepol_avtab_iter_destroy(sepol_avtab_iter_t *iter);

/*
 * Advance to the next entry. When done, sets *ruletype to 0.
 * Values are 1-based; resolve with sepol_*_value_to_name().
 */
extern int sepol_avtab_iter_next(sepol_handle_t *handle,
				 sepol_avtab_iter_t *iter, uint32_t *ruletype,
				 uint32_t *source_type, uint32_t *target_type,
				 uint32_t *target_class);

/* For AV rules: permission bitmask (inverted for AVTAB_AUDITDENY). */
extern uint32_t sepol_avtab_iter_get_av_data(const sepol_avtab_iter_t *iter);

/* For type rules: 1-based default type value. */
extern uint32_t sepol_avtab_iter_get_type_data(const sepol_avtab_iter_t *iter);

/* For xperm rules: kind (AVTAB_XPERMS_IOCTLFUNCTION etc.). */
extern uint8_t sepol_avtab_iter_get_xperm_type(const sepol_avtab_iter_t *iter);

/* For xperm rules: driver/command group. */
extern uint8_t
sepol_avtab_iter_get_xperm_driver(const sepol_avtab_iter_t *iter);

/* --- Permission name sub-iterator --- */

struct sepol_perm_iter;
typedef struct sepol_perm_iter sepol_perm_iter_t;

/*
 * Decode a permission bitmask into individual permission names for
 * the given class. 'target_class' is 1-based.
 */
extern int sepol_perm_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  uint32_t target_class, uint32_t perm_data,
				  sepol_perm_iter_t **iter);

extern void sepol_perm_iter_destroy(sepol_perm_iter_t *iter);

/* Returns the next permission name, or NULL when done.
 * The pointer is borrowed from the policydb and must not be freed.
 * It remains valid only while the sepol_policydb_t is alive. */
extern int sepol_perm_iter_next(sepol_handle_t *handle, sepol_perm_iter_t *iter,
				const char **perm_name);

/* --- Extended permission value sub-iterator --- */

struct sepol_xperm_iter;
typedef struct sepol_xperm_iter sepol_xperm_iter_t;

/*
 * Create an iterator over xperm values (0-255) from the current
 * avtab entry's xperms bitmap.
 */
extern int sepol_xperm_iter_create(sepol_handle_t *handle,
				   const sepol_avtab_iter_t *iter,
				   sepol_xperm_iter_t **xperm_iter);

extern void sepol_xperm_iter_destroy(sepol_xperm_iter_t *xperm_iter);

/* Get the next xperm value. Sets *has_next to 0 when done. */
extern int sepol_xperm_iter_next(sepol_handle_t *handle,
				 sepol_xperm_iter_t *xperm_iter,
				 uint16_t *value, int *has_next);

/*
 * Format an access-vector permission bitmask as a space-separated list of
 * permission names for the given class (1-based). Returns a newly allocated
 * string (caller must free), or NULL on error.
 */
extern char *sepol_policydb_av_to_string(const sepol_policydb_t *policydb,
					 uint32_t class_val, uint32_t av);

/*
 * Format extended permissions (ioctl driver/function or netlink message) as a
 * human-readable string. 'specified' is an AVTAB_XPERMS_* kind,
 * 'driver' is the driver/group byte, and 'perms' is the 8-byte bitmap.
 * Returns a newly allocated string (caller must free), or NULL on error.
 */
extern char *sepol_policydb_extended_perms_to_string(uint8_t specified,
						     uint8_t driver,
						     const uint32_t perms[8]);

#ifdef __cplusplus
}
#endif

#endif

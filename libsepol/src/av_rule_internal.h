#ifndef _SEPOL_AV_RULE_INTERNAL_H_
#define _SEPOL_AV_RULE_INTERNAL_H_

#include <sepol/av_rule.h>
#include <sepol/constants.h>
#include <sepol/policydb/avtab.h>
#include <stdint.h>

struct sepol_xperm_iter {
	uint32_t perms[8];
	uint16_t current_bit;
};

/* Internal helper - not part of the public ABI. */
extern int
sepol_xperm_iter_create_from_datum(sepol_handle_t *handle,
				   const avtab_extended_perms_t *xperms,
				   sepol_xperm_iter_t **xperm_iter);

/*
 * sepol_avtab_iter and sepol_cond_rule_iter both cache the last-visited
 * avtab_datum_t + its "specified" bits so their get_{av,type}_data() and
 * get_xperm_{type,driver}() accessors can be implemented identically here,
 * rather than duplicated verbatim in av_rule.c and conditional_public.c.
 */
static inline uint32_t avtab_datum_get_av_data(const avtab_datum_t *last_datum,
					       uint16_t last_specified)
{
	if (!last_datum)
		return 0;
	if (last_specified & AVTAB_AUDITDENY)
		return ~last_datum->data;
	return last_datum->data;
}

static inline uint32_t
avtab_datum_get_type_data(const avtab_datum_t *last_datum)
{
	if (!last_datum)
		return 0;
	return last_datum->data;
}

static inline uint8_t
avtab_datum_get_xperm_type(const avtab_datum_t *last_datum)
{
	if (!last_datum || !last_datum->xperms)
		return 0;
	return last_datum->xperms->specified;
}

static inline uint8_t
avtab_datum_get_xperm_driver(const avtab_datum_t *last_datum)
{
	if (!last_datum || !last_datum->xperms)
		return 0;
	return last_datum->xperms->driver;
}

#endif

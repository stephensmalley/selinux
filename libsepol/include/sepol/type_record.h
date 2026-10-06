#ifndef _SEPOL_TYPE_RECORD_H_
#define _SEPOL_TYPE_RECORD_H_

#include <sepol/handle.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_type;
typedef struct sepol_type sepol_type_t;
struct sepol_type_key;
typedef struct sepol_type_key sepol_type_key_t;

/* Key */
extern int sepol_type_key_create(sepol_handle_t *handle, const char *name,
				 sepol_type_key_t **key);

extern void sepol_type_key_unpack(const sepol_type_key_t *key,
				  const char **name);

extern int sepol_type_key_extract(sepol_handle_t *handle,
				  const sepol_type_t *type,
				  sepol_type_key_t **key_ptr);

extern void sepol_type_key_free(sepol_type_key_t *key);

extern int sepol_type_compare(const sepol_type_t *type,
			      const sepol_type_key_t *key);

extern int sepol_type_compare2(const sepol_type_t *type,
			       const sepol_type_t *type2);

/* Name */
extern const char *sepol_type_get_name(const sepol_type_t *type);
extern int sepol_type_set_name(sepol_handle_t *handle, sepol_type_t *type,
			       const char *name);

/* Flavor */
#define SEPOL_TYPE_TYPE 0 /* regular type */
#define SEPOL_TYPE_ATTRIB 1 /* attribute */
#define SEPOL_TYPE_ALIAS 2 /* alias */

extern uint32_t sepol_type_get_flavor(const sepol_type_t *type);
extern int sepol_type_set_flavor(sepol_handle_t *handle, sepol_type_t *type,
				 uint32_t flavor);

/* Subtypes/Attributes */
extern int sepol_type_has_subtype(const sepol_type_t *type,
				  const char *subtype);
extern int sepol_type_get_subtypes(sepol_handle_t *handle,
				   const sepol_type_t *type,
				   const char ***subtypes,
				   uint32_t *num_subtypes);
extern int sepol_type_add_subtype(sepol_handle_t *handle, sepol_type_t *type,
				  const char *subtype);
extern int sepol_type_del_subtype(sepol_handle_t *handle, sepol_type_t *type,
				  const char *subtype);

/* Flags */
#define SEPOL_TYPE_FLAGS_PERMISSIVE (1 << 0)
#define SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE (1 << 1)
#define SEPOL_TYPE_FLAGS_EXPAND_ATTR_FALSE (1 << 2)
#define SEPOL_TYPE_FLAGS_EXPAND_ATTR \
	(SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE | SEPOL_TYPE_FLAGS_EXPAND_ATTR_FALSE)
extern int sepol_type_has_flag(const sepol_type_t *type, uint32_t flag);
extern int sepol_type_set_flag(sepol_handle_t *handle, sepol_type_t *type,
			       uint32_t flag);
extern int sepol_type_unset_flag(sepol_handle_t *handle, sepol_type_t *type,
				 uint32_t flag);

/* Primary names of aliases */
extern const char *sepol_type_get_alias_of(const sepol_type_t *type);
extern int sepol_type_set_alias_of(sepol_handle_t *handle, sepol_type_t *type,
				   const char *name);

/* Bounds */
extern const char *sepol_type_get_bounds(const sepol_type_t *type);
extern int sepol_type_set_bounds(sepol_handle_t *handle, sepol_type_t *type,
				 const char *bounds);

/* Create/Clone/Destroy */
extern int sepol_type_create(sepol_handle_t *handle, sepol_type_t **type_ptr);

extern int sepol_type_clone(sepol_handle_t *handle, const sepol_type_t *type,
			    sepol_type_t **type_ptr);

extern void sepol_type_free(sepol_type_t *type);

#ifdef __cplusplus
}
#endif

#endif

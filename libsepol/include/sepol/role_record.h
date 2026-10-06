#ifndef _SEPOL_ROLE_RECORD_H_
#define _SEPOL_ROLE_RECORD_H_

#include <stdint.h>

#include <sepol/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_role;
typedef struct sepol_role sepol_role_t;
struct sepol_role_key;
typedef struct sepol_role_key sepol_role_key_t;

/* Key */
extern int sepol_role_key_create(sepol_handle_t *handle, const char *name,
				 sepol_role_key_t **key);
extern void sepol_role_key_unpack(const sepol_role_key_t *key,
				  const char **name);
extern int sepol_role_key_extract(sepol_handle_t *handle,
				  const sepol_role_t *role,
				  sepol_role_key_t **key);
extern void sepol_role_key_free(sepol_role_key_t *key);

extern int sepol_role_compare(const sepol_role_t *role,
			      const sepol_role_key_t *key);
extern int sepol_role_compare2(const sepol_role_t *role,
			       const sepol_role_t *role2);

/* Role name */
extern const char *sepol_role_get_name(const sepol_role_t *role);
extern int sepol_role_set_name(sepol_handle_t *handle, sepol_role_t *role,
			       const char *name);

/* Authorized types */
extern int sepol_role_has_type(const sepol_role_t *role, const char *type);
extern int sepol_role_get_types(sepol_handle_t *handle,
				const sepol_role_t *role, const char ***types,
				uint32_t *num_types);
extern int sepol_role_add_type(sepol_handle_t *handle, sepol_role_t *role,
			       const char *type);
extern int sepol_role_del_type(sepol_handle_t *handle, sepol_role_t *role,
			       const char *type);

/* Bounds role */
extern const char *sepol_role_get_bounds(const sepol_role_t *role);
extern int sepol_role_set_bounds(sepol_handle_t *handle, sepol_role_t *role,
				 const char *bounds);

/* Flavor */
#define SEPOL_ROLE_ROLE 0
#define SEPOL_ROLE_ATTRIB 1
extern uint32_t sepol_role_get_flavor(const sepol_role_t *role);
extern int sepol_role_set_flavor(sepol_handle_t *handle, sepol_role_t *role,
				 uint32_t flavor);

/* Subroles in attribute */
extern int sepol_role_get_subroles(sepol_handle_t *handle,
				   const sepol_role_t *role,
				   const char ***subroles,
				   uint32_t *num_subroles);
extern int sepol_role_add_subrole(sepol_handle_t *handle, sepol_role_t *role,
				  const char *subrole);
extern int sepol_role_del_subrole(sepol_handle_t *handle, sepol_role_t *role,
				  const char *subrole);

/* Create/Clone/Destroy */
extern int sepol_role_create(sepol_handle_t *handle, sepol_role_t **role_ptr);
extern int sepol_role_clone(sepol_handle_t *handle, const sepol_role_t *role,
			    sepol_role_t **role_ptr);
extern void sepol_role_free(sepol_role_t *role);

#ifdef __cplusplus
}
#endif

#endif

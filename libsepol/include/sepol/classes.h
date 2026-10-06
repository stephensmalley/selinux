#ifndef _SEPOL_CLASSES_H_
#define _SEPOL_CLASSES_H_

#include <sepol/policydb.h>
#include <sepol/class_record.h>
#include <sepol/handle.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_class_iter;
typedef struct sepol_class_iter sepol_class_iter_t;

/* Return the number of classes */
extern int sepol_class_count(sepol_handle_t *handle, const sepol_policydb_t *p,
			     unsigned int *response);

/* Check if the specified class exists */
extern int sepol_class_exists(sepol_handle_t *handle,
			      const sepol_policydb_t *policydb,
			      const sepol_class_key_t *key, int *response);

/* Query a class - returns the class or NULL if not found */
extern int sepol_class_query(sepol_handle_t *handle, const sepol_policydb_t *p,
			     const sepol_class_key_t *key,
			     sepol_class_t **response);

/* Resolve a class value to its name.  Returns non-zero on invalid value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_class_value_to_name(sepol_handle_t *handle,
				     const sepol_policydb_t *p, uint32_t value,
				     const char **name);

/* Query a class by value - returns the class or NULL if not found */
extern int sepol_class_query_by_value(sepol_handle_t *handle,
				      const sepol_policydb_t *p, uint32_t value,
				      sepol_class_t **response);

/* Resolve a permission value to its name within a class.
 * Returns non-zero on invalid class value.
 * The returned pointer is borrowed from the policydb; do not free. */
extern int sepol_class_perm_value_to_name(sepol_handle_t *handle,
					  const sepol_policydb_t *p,
					  uint32_t class_value,
					  uint32_t perm_value,
					  const char **name);

/*
 * Iterating classes. Iteration order is unspecified (currently
 * hash-bucket order of the internal symbol table) and may change between
 * library versions or policydb loads; callers must not rely on it
 * matching declaration order or being stable across calls.
 */
extern int sepol_class_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   sepol_class_iter_t **iter);
extern void sepol_class_iter_destroy(sepol_class_iter_t *iter);
extern int sepol_class_iter_next(sepol_handle_t *handle,
				 sepol_class_iter_t *iter,
				 sepol_class_t **item);

#ifdef __cplusplus
}
#endif

#endif

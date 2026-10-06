#ifndef _SEPOL_CLASS_RECORD_H_
#define _SEPOL_CLASS_RECORD_H_

#include <stdint.h>

#include <sepol/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_class;
typedef struct sepol_class sepol_class_t;
struct sepol_class_key;
typedef struct sepol_class_key sepol_class_key_t;

struct sepol_constraint;
typedef struct sepol_constraint sepol_constraint_t;
struct sepol_constraint_expr;
typedef struct sepol_constraint_expr sepol_constraint_expr_t;

/* Key */
extern int sepol_class_key_create(sepol_handle_t *handle, const char *name,
				  sepol_class_key_t **key);
extern void sepol_class_key_unpack(const sepol_class_key_t *key,
				   const char **name);
extern int sepol_class_key_extract(sepol_handle_t *handle,
				   const sepol_class_t *cls,
				   sepol_class_key_t **key);
extern void sepol_class_key_free(sepol_class_key_t *key);

extern int sepol_class_compare(const sepol_class_t *cls,
			       const sepol_class_key_t *key);
extern int sepol_class_compare2(const sepol_class_t *cls,
				const sepol_class_t *class2);

/* Class name */
extern const char *sepol_class_get_name(const sepol_class_t *cls);
extern int sepol_class_set_name(sepol_handle_t *handle, sepol_class_t *cls,
				const char *name);

/* Common name */
extern const char *sepol_class_get_common(const sepol_class_t *cls);
extern int sepol_class_set_common(sepol_handle_t *handle, sepol_class_t *cls,
				  const char *common);

/* Class-specific permissions */
extern int sepol_class_has_perm(const sepol_class_t *cls, const char *perm);
extern int sepol_class_get_perms(sepol_handle_t *handle,
				 const sepol_class_t *cls, const char ***perms,
				 uint32_t *num_perms);
extern int sepol_class_add_perm(sepol_handle_t *handle, sepol_class_t *cls,
				const char *perm);
extern int sepol_class_del_perm(sepol_handle_t *handle, sepol_class_t *cls,
				const char *perm);

/* Constraints */
extern int sepol_class_get_constraints(sepol_handle_t *handle,
				       const sepol_class_t *cls,
				       const sepol_constraint_t ***constraints,
				       uint32_t *num_constraints);
/*
 * On success, cls takes ownership of constraint: it is stored by
 * reference (not copied) and will be freed when cls is freed or when
 * constraint is removed via sepol_class_del_constraint(). The caller
 * must not free or otherwise reuse constraint after a successful call.
 * On failure, ownership is not transferred and the caller remains
 * responsible for freeing constraint.
 */
extern int sepol_class_add_constraint(sepol_handle_t *handle,
				      sepol_class_t *cls,
				      sepol_constraint_t *constraint);
/*
 * Removes and frees exactly the constraint object passed in, matched by
 * pointer identity (i.e. it must be a value previously passed to
 * sepol_class_add_constraint() on this cls, such as one obtained from
 * sepol_class_get_constraints()), not by comparing field values. Two
 * structurally-identical but distinct constraint objects are never
 * conflated: adding both and deleting one leaves the other untouched.
 * Returns an error, without freeing anything, if constraint is not
 * currently stored in cls.
 */
extern int sepol_class_del_constraint(sepol_handle_t *handle,
				      sepol_class_t *cls,
				      const sepol_constraint_t *constraint);

/* Validate transitions */
extern int
sepol_class_get_validatetrans(sepol_handle_t *handle, const sepol_class_t *cls,
			      const sepol_constraint_t ***validatetrans,
			      uint32_t *num_validatetrans);
/*
 * On success, cls takes ownership of validatetrans: it is stored by
 * reference (not copied) and will be freed when cls is freed or when
 * validatetrans is removed via sepol_class_del_validatetrans(). The
 * caller must not free or otherwise reuse validatetrans after a
 * successful call. On failure, ownership is not transferred and the
 * caller remains responsible for freeing validatetrans.
 */
extern int sepol_class_add_validatetrans(sepol_handle_t *handle,
					 sepol_class_t *cls,
					 sepol_constraint_t *validatetrans);
/*
 * Removes and frees exactly the validatetrans object passed in, matched
 * by pointer identity, not by comparing field values -- see
 * sepol_class_del_constraint()'s documentation for the rationale, which
 * applies identically here. Returns an error, without freeing anything,
 * if validatetrans is not currently stored in cls.
 */
extern int
sepol_class_del_validatetrans(sepol_handle_t *handle, sepol_class_t *cls,
			      const sepol_constraint_t *validatetrans);

/* Defaults */
#define SEPOL_CLASS_DEFAULT_SOURCE 1
#define SEPOL_CLASS_DEFAULT_TARGET 2
extern int sepol_class_get_default_user(const sepol_class_t *cls);
extern int sepol_class_set_default_user(sepol_handle_t *handle,
					sepol_class_t *cls, int default_user);
extern int sepol_class_get_default_role(const sepol_class_t *cls);
extern int sepol_class_set_default_role(sepol_handle_t *handle,
					sepol_class_t *cls, int default_role);
extern int sepol_class_get_default_type(const sepol_class_t *cls);
extern int sepol_class_set_default_type(sepol_handle_t *handle,
					sepol_class_t *cls, int default_type);

#define SEPOL_CLASS_DEFAULT_SOURCE_LOW 1
#define SEPOL_CLASS_DEFAULT_SOURCE_HIGH 2
#define SEPOL_CLASS_DEFAULT_SOURCE_LOW_HIGH 3
#define SEPOL_CLASS_DEFAULT_TARGET_LOW 4
#define SEPOL_CLASS_DEFAULT_TARGET_HIGH 5
#define SEPOL_CLASS_DEFAULT_TARGET_LOW_HIGH 6
#define SEPOL_CLASS_DEFAULT_GLBLUB 7
extern int sepol_class_get_default_range(const sepol_class_t *cls);
extern int sepol_class_set_default_range(sepol_handle_t *handle,
					 sepol_class_t *cls, int default_range);

/* Create/Clone/Destroy */
extern int sepol_class_create(sepol_handle_t *handle,
			      sepol_class_t **class_ptr);
extern int sepol_class_clone(sepol_handle_t *handle, const sepol_class_t *cls,
			     sepol_class_t **class_ptr);
extern void sepol_class_free(sepol_class_t *cls);

/* Constraints */
extern int sepol_constraint_create(sepol_handle_t *handle,
				   sepol_constraint_t **constraint_ptr);
extern int sepol_constraint_clone(sepol_handle_t *handle,
				  const sepol_constraint_t *constraint,
				  sepol_constraint_t **constraint_ptr);
extern void sepol_constraint_free(sepol_constraint_t *constraint);

/* Constrained permissions */
extern int sepol_constraint_has_perm(const sepol_constraint_t *constraint,
				     const char *perm);
extern int sepol_constraint_get_perms(sepol_handle_t *handle,
				      const sepol_constraint_t *constraint,
				      const char ***perms, uint32_t *num_perms);
extern int sepol_constraint_add_perm(sepol_handle_t *handle,
				     sepol_constraint_t *constraint,
				     const char *perm);
extern int sepol_constraint_del_perm(sepol_handle_t *handle,
				     sepol_constraint_t *constraint,
				     const char *perm);

/* Constraint sub expressions */
extern int sepol_constraint_get_exprs(sepol_handle_t *handle,
				      const sepol_constraint_t *constraint,
				      const sepol_constraint_expr_t ***exprs,
				      uint32_t *num_exprs);
extern int sepol_constraint_insert_expr(sepol_handle_t *handle,
					sepol_constraint_t *constraint,
					uint32_t index,
					sepol_constraint_expr_t *expr);
extern int sepol_constraint_remove_expr(sepol_handle_t *handle,
					sepol_constraint_t *constraint,
					uint32_t index);

/* Constraint expressions */
extern int sepol_constraint_expr_create(sepol_handle_t *handle,
					sepol_constraint_expr_t **expr_ptr);
extern int sepol_constraint_expr_clone(sepol_handle_t *handle,
				       const sepol_constraint_expr_t *expr,
				       sepol_constraint_expr_t **expr_ptr);
extern void sepol_constraint_expr_free(sepol_constraint_expr_t *expr);

/* Constraint expr type */
#define SEPOL_CEXPR_TYPE_NOT 1 /* not expr */
#define SEPOL_CEXPR_TYPE_AND 2 /* expr and expr */
#define SEPOL_CEXPR_TYPE_OR 3 /* expr or expr */
#define SEPOL_CEXPR_TYPE_ATTR 4 /* attr op attr */
#define SEPOL_CEXPR_TYPE_NAMES 5 /* attr op names */
extern uint32_t
sepol_constraint_expr_get_type(const sepol_constraint_expr_t *expr);
extern int sepol_constraint_expr_set_type(sepol_handle_t *handle,
					  sepol_constraint_expr_t *expr,
					  uint32_t type);

/* Constraint expr attr */
#define SEPOL_CEXPR_ATTR_USER 1 /* user */
#define SEPOL_CEXPR_ATTR_ROLE 2 /* role */
#define SEPOL_CEXPR_ATTR_TYPE 4 /* type */
#define SEPOL_CEXPR_ATTR_TARGET 8 /* target if set, source otherwise */
#define SEPOL_CEXPR_ATTR_XTARGET \
	16 /* special 3rd target for validatetrans rule */
#define SEPOL_CEXPR_ATTR_L1L2 32 /* low level 1 vs. low level 2 */
#define SEPOL_CEXPR_ATTR_L1H2 64 /* low level 1 vs. high level 2 */
#define SEPOL_CEXPR_ATTR_H1L2 128 /* high level 1 vs. low level 2 */
#define SEPOL_CEXPR_ATTR_H1H2 256 /* high level 1 vs. high level 2 */
#define SEPOL_CEXPR_ATTR_L1H1 512 /* low level 1 vs. high level 1 */
#define SEPOL_CEXPR_ATTR_L2H2 1024 /* low level 2 vs. high level 2 */
extern int sepol_constraint_expr_has_attr(const sepol_constraint_expr_t *expr,
					  uint32_t attr);
extern int sepol_constraint_expr_set_attr(sepol_handle_t *handle,
					  sepol_constraint_expr_t *expr,
					  uint32_t attr);
extern int sepol_constraint_expr_unset_attr(sepol_handle_t *handle,
					    sepol_constraint_expr_t *expr,
					    uint32_t attr);
extern int sepol_constraint_expr_clear_attr(sepol_handle_t *handle,
					    sepol_constraint_expr_t *expr);

/* Constraint expr attr or names operator */
#define SEPOL_CEXPR_OP_EQ 1 /* == or eq */
#define SEPOL_CEXPR_OP_NEQ 2 /* != */
#define SEPOL_CEXPR_OP_DOM 3 /* dom */
#define SEPOL_CEXPR_OP_DOMBY 4 /* domby  */
#define SEPOL_CEXPR_OP_INCOMP 5 /* incomp */
extern uint32_t
sepol_constraint_expr_get_op(const sepol_constraint_expr_t *expr);
extern int sepol_constraint_expr_set_op(sepol_handle_t *handle,
					sepol_constraint_expr_t *expr,
					uint32_t op);

/* Constraint names */
extern int sepol_constraint_expr_has_name(const sepol_constraint_expr_t *expr,
					  const char *name);
extern int sepol_constraint_expr_get_names(sepol_handle_t *handle,
					   const sepol_constraint_expr_t *expr,
					   const char ***names,
					   uint32_t *num_names);
extern int sepol_constraint_expr_add_name(sepol_handle_t *handle,
					  sepol_constraint_expr_t *expr,
					  const char *name);
extern int sepol_constraint_expr_del_name(sepol_handle_t *handle,
					  sepol_constraint_expr_t *expr,
					  const char *name);

#ifdef __cplusplus
}
#endif

#endif

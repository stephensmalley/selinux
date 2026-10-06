
/* Author : Stephen Smalley, <stephen.smalley.work@gmail.com> */

/*
 * Updated: Yuichi Nakamura <ynakam@hitachisoft.jp>
 * 	Tuned number of hash slots for avtab to reduce memory usage
 */

/* Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* FLASK */

/*
 * An access vector table (avtab) is a hash table
 * of access vectors and transition types indexed 
 * by a type pair and a class.  An access vector
 * table is used to represent the type enforcement
 * tables.
 */

#ifndef _SEPOL_POLICYDB_AVTAB_H_
#define _SEPOL_POLICYDB_AVTAB_H_

#include <sys/types.h>
#include <stdint.h>

#include <sepol/constants.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct avtab_key {
	uint16_t source_type;
	uint16_t target_type;
	uint16_t target_class;
	uint16_t specified; /* what fields are specified; see AVTAB_* in sepol/constants.h */
} avtab_key_t;

typedef struct avtab_extended_perms {
	/* extension of the avtab_key specified; see AVTAB_XPERMS_* in sepol/constants.h */
	uint8_t specified;
	uint8_t driver;
	uint32_t perms[8];
} avtab_extended_perms_t;

typedef struct avtab_datum {
	uint32_t data; /* access vector or type */
	avtab_extended_perms_t *xperms;
} avtab_datum_t;

typedef struct avtab_node *avtab_ptr_t;

struct avtab_node {
	avtab_key_t key;
	avtab_datum_t datum;
	avtab_ptr_t next;
	void *parse_context; /* generic context pointer used by parser;
				 * not saved in binary policy */
	unsigned merged; /* flag for avtab_write only;
				   not saved in binary policy */
};

typedef struct avtab {
	avtab_ptr_t *htable;
	uint32_t nel; /* number of elements */
	uint32_t nslot; /* number of hash slots */
	uint32_t mask; /* mask to compute hash func */
} avtab_t;

extern int avtab_init(avtab_t *);
extern int avtab_alloc(avtab_t *, uint32_t);
extern int avtab_insert(avtab_t *h, avtab_key_t *k, avtab_datum_t *d);

extern avtab_datum_t *avtab_search(avtab_t *h, avtab_key_t *k);

extern void avtab_destroy(avtab_t *h);

extern int avtab_map(const avtab_t *h,
		     int (*apply)(avtab_key_t *k, avtab_datum_t *d, void *args),
		     void *args);

extern void avtab_hash_eval(avtab_t *h, char *tag);

struct policy_file;
extern int avtab_read_item(struct policy_file *fp, avtab_t *a,
			   int (*insert)(avtab_t *a, avtab_key_t *k,
					 avtab_datum_t *d, void *p),
			   void *p);

extern int avtab_read(avtab_t *a, struct policy_file *fp);

extern avtab_ptr_t avtab_insert_nonunique(avtab_t *h, avtab_key_t *key,
					  avtab_datum_t *datum);

extern avtab_ptr_t avtab_insert_with_parse_context(avtab_t *h, avtab_key_t *key,
						   avtab_datum_t *datum,
						   void *parse_context);

extern avtab_ptr_t avtab_search_node(avtab_t *h, avtab_key_t *key);

extern avtab_ptr_t avtab_search_node_next(avtab_ptr_t node, int specified);

#ifdef __cplusplus
}
#endif

#endif /* _AVTAB_H_ */

/* FLASK */

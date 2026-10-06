#ifndef _SEPOL_FLASK_H_
#define _SEPOL_FLASK_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char *sepol_security_context_t;
typedef const char *sepol_const_security_context_t;
typedef uint32_t sepol_access_vector_t;
typedef uint16_t sepol_security_class_t;
#define SEPOL_SECCLASS_NULL 0x0000

#define SELINUX_MAGIC 0xf97cff8c
#define SELINUX_MOD_MAGIC 0xf97cff8d

typedef uint32_t sepol_security_id_t;
#define SEPOL_SECSID_NULL 0

struct sepol_av_decision {
	sepol_access_vector_t allowed;
	sepol_access_vector_t decided;
	sepol_access_vector_t auditallow;
	sepol_access_vector_t auditdeny;
	uint32_t seqno;
};

#ifdef __cplusplus
}
#endif

#endif

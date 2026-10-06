#ifndef _SEPOL_H_
#define _SEPOL_H_

#include <stddef.h>
#include <stdio.h>

#include <sepol/av_rule.h>
#include <sepol/boolean_record.h>
#include <sepol/booleans.h>
#include <sepol/cat_set.h>
#include <sepol/class_record.h>
#include <sepol/classes.h>
#include <sepol/common_perm.h>
#include <sepol/conditional.h>
#include <sepol/constants.h>
#include <sepol/context.h>
#include <sepol/context_record.h>
#include <sepol/debug.h>
#include <sepol/filename_trans.h>
#include <sepol/flask.h>
#include <sepol/handle.h>
#include <sepol/ibendport_record.h>
#include <sepol/ibendports.h>
#include <sepol/ibpkey_record.h>
#include <sepol/ibpkeys.h>
#include <sepol/iface_record.h>
#include <sepol/interfaces.h>
#include <sepol/mls_iter.h>
#include <sepol/module.h>
#include <sepol/node_record.h>
#include <sepol/nodes.h>
#include <sepol/ocontext.h>
#include <sepol/permissive.h>
#include <sepol/polcap.h>
#include <sepol/policydb.h>
#include <sepol/port_record.h>
#include <sepol/ports.h>
#include <sepol/range_trans.h>
#include <sepol/role_record.h>
#include <sepol/role_rule.h>
#include <sepol/roles.h>
#include <sepol/sid_table.h>
#include <sepol/type_record.h>
#include <sepol/types.h>
#include <sepol/user_record.h>
#include <sepol/users.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set internal policydb from a file for subsequent service calls. */
extern int sepol_set_policydb_from_file(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif

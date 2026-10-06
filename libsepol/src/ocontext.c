#include <sepol/ocontext.h>

#include <sepol/policydb/context.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "cat_set_internal.h"
#include "debug.h"
#include "initial_sids.h"

/*
 * Macro to stamp out the seven standard context accessor functions for
 * an ocontext iterator.  Each ocontext node carries context[0] (and
 * context[1] for the netifcon message context).  The generated functions
 * return user/role/type values, MLS sensitivity values, and category-set
 * iterators from the context at index CTX_IDX of the most recently
 * yielded ocontext node (iter->last).
 *
 * FN_PREFIX is pasted before _context_user, _context_role, etc.
 * Example: FN_PREFIX = sepol_isid_iter_get
 *      =>  sepol_isid_iter_get_context_user, ...
 */
#define DEFINE_OCON_CONTEXT_GETTERS(FN_PREFIX, ITER_TYPE, CTX_IDX)          \
                                                                            \
	uint32_t FN_PREFIX##_context_user(const ITER_TYPE *iter)            \
	{                                                                   \
		if (!iter || !iter->last)                                   \
			return 0;                                           \
		return iter->last->context[CTX_IDX].user;                   \
	}                                                                   \
                                                                            \
	uint32_t FN_PREFIX##_context_role(const ITER_TYPE *iter)            \
	{                                                                   \
		if (!iter || !iter->last)                                   \
			return 0;                                           \
		return iter->last->context[CTX_IDX].role;                   \
	}                                                                   \
                                                                            \
	uint32_t FN_PREFIX##_context_type(const ITER_TYPE *iter)            \
	{                                                                   \
		if (!iter || !iter->last)                                   \
			return 0;                                           \
		return iter->last->context[CTX_IDX].type;                   \
	}                                                                   \
                                                                            \
	uint32_t FN_PREFIX##_mls_range_low_sens(const ITER_TYPE *iter)      \
	{                                                                   \
		if (!iter || !iter->last)                                   \
			return 0;                                           \
		return iter->last->context[CTX_IDX].range.level[0].sens;    \
	}                                                                   \
                                                                            \
	uint32_t FN_PREFIX##_mls_range_high_sens(const ITER_TYPE *iter)     \
	{                                                                   \
		if (!iter || !iter->last)                                   \
			return 0;                                           \
		return iter->last->context[CTX_IDX].range.level[1].sens;    \
	}                                                                   \
                                                                            \
	int FN_PREFIX##_mls_range_low_cat(const ITER_TYPE *iter,            \
					  sepol_cat_set_iter_t **cat_iter)  \
	{                                                                   \
		if (!cat_iter)                                              \
			return STATUS_ERR;                                  \
		if (!iter || !iter->last) {                                 \
			*cat_iter = NULL;                                   \
			return STATUS_SUCCESS;                              \
		}                                                           \
		return cat_set_iter_create_from_ebitmap(                    \
			&iter->last->context[CTX_IDX].range.level[0].cat,   \
			cat_iter);                                          \
	}                                                                   \
                                                                            \
	int FN_PREFIX##_mls_range_high_cat(const ITER_TYPE *iter,           \
					   sepol_cat_set_iter_t **cat_iter) \
	{                                                                   \
		if (!cat_iter)                                              \
			return STATUS_ERR;                                  \
		if (!iter || !iter->last) {                                 \
			*cat_iter = NULL;                                   \
			return STATUS_SUCCESS;                              \
		}                                                           \
		return cat_set_iter_create_from_ebitmap(                    \
			&iter->last->context[CTX_IDX].range.level[1].cat,   \
			cat_iter);                                          \
	}

/* ---- Initial SID iterator ---- */

struct sepol_isid_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
	int target_platform;
};

int sepol_isid_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_isid_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_isid_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_ISID];
	tmp->last = NULL;
	tmp->target_platform = p->p.target_platform;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_isid_iter_destroy(sepol_isid_iter_t *iter)
{
	free(iter);
}

int sepol_isid_iter_next(sepol_handle_t *handle __attribute__((unused)),
			 sepol_isid_iter_t *iter, uint32_t *sid)
{
	if (!iter || !sid)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*sid = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*sid = iter->cur->sid[0];
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_isid_iter_get, sepol_isid_iter_t, 0)

const char *sepol_isid_iter_get_name(const sepol_isid_iter_t *iter)
{
	uint32_t sid;

	if (!iter || !iter->last)
		return NULL;

	sid = iter->last->sid[0];

	if (iter->target_platform == SEPOL_TARGET_XEN) {
		if (sid < XEN_SID_SZ)
			return xen_sid_to_str[sid];
		return NULL;
	}

	if (sid < SELINUX_SID_SZ)
		return selinux_sid_to_str[sid];
	return NULL;
}

/* ---- fs_use iterator ---- */

struct sepol_fsuse_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_fsuse_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			    sepol_fsuse_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "fsuse requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_fsuse_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_FSUSE];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_fsuse_iter_destroy(sepol_fsuse_iter_t *iter)
{
	free(iter);
}

int sepol_fsuse_iter_next(sepol_handle_t *handle __attribute__((unused)),
			  sepol_fsuse_iter_t *iter, const char **name,
			  uint32_t *behavior)
{
	if (!iter || !name || !behavior)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*name = NULL;
		*behavior = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*name = iter->cur->u.name;
	*behavior = iter->cur->v.behavior;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_fsuse_iter_get, sepol_fsuse_iter_t, 0)

/* ---- genfscon iterator ---- */

struct sepol_genfscon_iter {
	const genfs_t *cur_genfs;
	const ocontext_t *cur_ocon;
	const ocontext_t *last;
};

int sepol_genfscon_iter_create(sepol_handle_t *handle,
			       const sepol_policydb_t *p,
			       sepol_genfscon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_genfscon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur_genfs = p->p.genfs;
	while (tmp->cur_genfs && !tmp->cur_genfs->head)
		tmp->cur_genfs = tmp->cur_genfs->next;
	tmp->cur_ocon = tmp->cur_genfs ? tmp->cur_genfs->head : NULL;
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_genfscon_iter_destroy(sepol_genfscon_iter_t *iter)
{
	free(iter);
}

int sepol_genfscon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			     sepol_genfscon_iter_t *iter, const char **fstype,
			     const char **path, uint32_t *sclass)
{
	if (!iter || !fstype || !path || !sclass)
		return STATUS_ERR;

	if (!iter->cur_ocon) {
		iter->last = NULL;
		*fstype = NULL;
		*path = NULL;
		*sclass = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur_ocon;
	*fstype = iter->cur_genfs->fstype;
	*path = iter->cur_ocon->u.name;
	*sclass = iter->cur_ocon->v.sclass;

	iter->cur_ocon = iter->cur_ocon->next;
	if (!iter->cur_ocon) {
		iter->cur_genfs = iter->cur_genfs->next;
		while (iter->cur_genfs && !iter->cur_genfs->head)
			iter->cur_genfs = iter->cur_genfs->next;
		if (iter->cur_genfs)
			iter->cur_ocon = iter->cur_genfs->head;
	}

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_genfscon_iter_get, sepol_genfscon_iter_t, 0)

/* ---- Xen pirqcon iterator ---- */

struct sepol_pirqcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_pirqcon_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			      sepol_pirqcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform != SEPOL_TARGET_XEN) {
		ERR(handle, "pirqcon requires a Xen policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_pirqcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_XEN_PIRQ];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_pirqcon_iter_destroy(sepol_pirqcon_iter_t *iter)
{
	free(iter);
}

int sepol_pirqcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			    sepol_pirqcon_iter_t *iter, uint32_t *irq,
			    int *has_next)
{
	if (!iter || !irq || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*irq = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*irq = iter->cur->u.pirq;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_pirqcon_iter_get, sepol_pirqcon_iter_t, 0)

/* ---- Xen iomemcon iterator ---- */

struct sepol_iomemcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_iomemcon_iter_create(sepol_handle_t *handle,
			       const sepol_policydb_t *p,
			       sepol_iomemcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform != SEPOL_TARGET_XEN) {
		ERR(handle, "iomemcon requires a Xen policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_iomemcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_XEN_IOMEM];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_iomemcon_iter_destroy(sepol_iomemcon_iter_t *iter)
{
	free(iter);
}

int sepol_iomemcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			     sepol_iomemcon_iter_t *iter, uint64_t *low_iomem,
			     uint64_t *high_iomem, int *has_next)
{
	if (!iter || !low_iomem || !high_iomem || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*low_iomem = 0;
		*high_iomem = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*low_iomem = iter->cur->u.iomem.low_iomem;
	*high_iomem = iter->cur->u.iomem.high_iomem;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_iomemcon_iter_get, sepol_iomemcon_iter_t, 0)

/* ---- Xen ioportcon iterator ---- */

struct sepol_ioportcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_ioportcon_iter_create(sepol_handle_t *handle,
				const sepol_policydb_t *p,
				sepol_ioportcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform != SEPOL_TARGET_XEN) {
		ERR(handle, "ioportcon requires a Xen policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_ioportcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_XEN_IOPORT];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_ioportcon_iter_destroy(sepol_ioportcon_iter_t *iter)
{
	free(iter);
}

int sepol_ioportcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			      sepol_ioportcon_iter_t *iter,
			      uint32_t *low_ioport, uint32_t *high_ioport,
			      int *has_next)
{
	if (!iter || !low_ioport || !high_ioport || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*low_ioport = 0;
		*high_ioport = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*low_ioport = iter->cur->u.ioport.low_ioport;
	*high_ioport = iter->cur->u.ioport.high_ioport;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_ioportcon_iter_get, sepol_ioportcon_iter_t, 0)

/* ---- Xen pcidevicecon iterator ---- */

struct sepol_pcidevicecon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_pcidevicecon_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   sepol_pcidevicecon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform != SEPOL_TARGET_XEN) {
		ERR(handle, "pcidevicecon requires a Xen policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_pcidevicecon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_XEN_PCIDEVICE];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_pcidevicecon_iter_destroy(sepol_pcidevicecon_iter_t *iter)
{
	free(iter);
}

int sepol_pcidevicecon_iter_next(sepol_handle_t *handle __attribute__((unused)),
				 sepol_pcidevicecon_iter_t *iter,
				 uint32_t *device, int *has_next)
{
	if (!iter || !device || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*device = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*device = iter->cur->u.device;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_pcidevicecon_iter_get,
			    sepol_pcidevicecon_iter_t, 0)

/* ---- Xen devicetreecon iterator ---- */

struct sepol_devicetreecon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_devicetreecon_iter_create(sepol_handle_t *handle,
				    const sepol_policydb_t *p,
				    sepol_devicetreecon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform != SEPOL_TARGET_XEN) {
		ERR(handle, "devicetreecon requires a Xen policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_devicetreecon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_XEN_DEVICETREE];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_devicetreecon_iter_destroy(sepol_devicetreecon_iter_t *iter)
{
	free(iter);
}

int sepol_devicetreecon_iter_next(sepol_handle_t *handle
				  __attribute__((unused)),
				  sepol_devicetreecon_iter_t *iter,
				  const char **path)
{
	if (!iter || !path)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*path = NULL;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*path = iter->cur->u.name;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_devicetreecon_iter_get,
			    sepol_devicetreecon_iter_t, 0)

/* ---- portcon iterator ---- */

struct sepol_portcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_portcon_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			      sepol_portcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "portcon requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_portcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_PORT];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_portcon_iter_destroy(sepol_portcon_iter_t *iter)
{
	free(iter);
}

int sepol_portcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			    sepol_portcon_iter_t *iter, uint8_t *protocol,
			    uint16_t *low_port, uint16_t *high_port,
			    int *has_next)
{
	if (!iter || !protocol || !low_port || !high_port || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*protocol = 0;
		*low_port = 0;
		*high_port = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*protocol = iter->cur->u.port.protocol;
	*low_port = iter->cur->u.port.low_port;
	*high_port = iter->cur->u.port.high_port;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_portcon_iter_get, sepol_portcon_iter_t, 0)

/* ---- netifcon iterator ---- */

struct sepol_netifcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_netifcon_iter_create(sepol_handle_t *handle,
			       const sepol_policydb_t *p,
			       sepol_netifcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "netifcon requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_netifcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_NETIF];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_netifcon_iter_destroy(sepol_netifcon_iter_t *iter)
{
	free(iter);
}

int sepol_netifcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			     sepol_netifcon_iter_t *iter, const char **name)
{
	if (!iter || !name)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*name = NULL;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*name = iter->cur->u.name;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_netifcon_iter_get, sepol_netifcon_iter_t, 0)
DEFINE_OCON_CONTEXT_GETTERS(sepol_netifcon_iter_get_msg, sepol_netifcon_iter_t,
			    1)

/* ---- nodecon IPv4 iterator ---- */

struct sepol_nodecon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_nodecon_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			      sepol_nodecon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "nodecon requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_nodecon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_NODE];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_nodecon_iter_destroy(sepol_nodecon_iter_t *iter)
{
	free(iter);
}

int sepol_nodecon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			    sepol_nodecon_iter_t *iter, uint32_t *addr,
			    uint32_t *mask, int *has_next)
{
	if (!iter || !addr || !mask || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*addr = 0;
		*mask = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*addr = iter->cur->u.node.addr;
	*mask = iter->cur->u.node.mask;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_nodecon_iter_get, sepol_nodecon_iter_t, 0)

/* ---- nodecon6 IPv6 iterator ---- */

struct sepol_nodecon6_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_nodecon6_iter_create(sepol_handle_t *handle,
			       const sepol_policydb_t *p,
			       sepol_nodecon6_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "nodecon6 requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_nodecon6_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_NODE6];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_nodecon6_iter_destroy(sepol_nodecon6_iter_t *iter)
{
	free(iter);
}

int sepol_nodecon6_iter_next(sepol_handle_t *handle __attribute__((unused)),
			     sepol_nodecon6_iter_t *iter, const uint32_t **addr,
			     const uint32_t **mask)
{
	if (!iter || !addr || !mask)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*addr = NULL;
		*mask = NULL;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*addr = iter->cur->u.node6.addr;
	*mask = iter->cur->u.node6.mask;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_nodecon6_iter_get, sepol_nodecon6_iter_t, 0)

/* ---- ibpkeycon iterator ---- */

struct sepol_ibpkeycon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_ibpkeycon_iter_create(sepol_handle_t *handle,
				const sepol_policydb_t *p,
				sepol_ibpkeycon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "ibpkeycon requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_ibpkeycon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_IBPKEY];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_ibpkeycon_iter_destroy(sepol_ibpkeycon_iter_t *iter)
{
	free(iter);
}

int sepol_ibpkeycon_iter_next(sepol_handle_t *handle __attribute__((unused)),
			      sepol_ibpkeycon_iter_t *iter,
			      uint64_t *subnet_prefix, uint16_t *low_pkey,
			      uint16_t *high_pkey, int *has_next)
{
	if (!iter || !subnet_prefix || !low_pkey || !high_pkey || !has_next)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*subnet_prefix = 0;
		*low_pkey = 0;
		*high_pkey = 0;
		*has_next = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*subnet_prefix = iter->cur->u.ibpkey.subnet_prefix;
	*low_pkey = iter->cur->u.ibpkey.low_pkey;
	*high_pkey = iter->cur->u.ibpkey.high_pkey;
	iter->cur = iter->cur->next;
	*has_next = 1;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_ibpkeycon_iter_get, sepol_ibpkeycon_iter_t, 0)

/* ---- ibendportcon iterator ---- */

struct sepol_ibendportcon_iter {
	const ocontext_t *cur;
	const ocontext_t *last;
};

int sepol_ibendportcon_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   sepol_ibendportcon_iter_t **iter)
{
	if (!iter)
		return STATUS_ERR;
	if (!handle || !p) {
		*iter = NULL;
		return STATUS_ERR;
	}

	if (p->p.target_platform == SEPOL_TARGET_XEN) {
		ERR(handle, "ibendportcon requires a SELinux policy");
		*iter = NULL;
		return STATUS_ERR;
	}

	sepol_ibendportcon_iter_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		ERR(handle, "out of memory");
		*iter = NULL;
		return STATUS_ERR;
	}

	tmp->cur = p->p.ocontexts[OCON_IBENDPORT];
	tmp->last = NULL;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_ibendportcon_iter_destroy(sepol_ibendportcon_iter_t *iter)
{
	free(iter);
}

int sepol_ibendportcon_iter_next(sepol_handle_t *handle __attribute__((unused)),
				 sepol_ibendportcon_iter_t *iter,
				 const char **dev_name, uint8_t *port)
{
	if (!iter || !dev_name || !port)
		return STATUS_ERR;

	if (!iter->cur) {
		iter->last = NULL;
		*dev_name = NULL;
		*port = 0;
		return STATUS_SUCCESS;
	}

	iter->last = iter->cur;
	*dev_name = iter->cur->u.ibendport.dev_name;
	*port = iter->cur->u.ibendport.port;
	iter->cur = iter->cur->next;

	return STATUS_SUCCESS;
}

DEFINE_OCON_CONTEXT_GETTERS(sepol_ibendportcon_iter_get,
			    sepol_ibendportcon_iter_t, 0)

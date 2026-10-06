#ifndef _SEPOL_OCONTEXT_H_
#define _SEPOL_OCONTEXT_H_

#include <sepol/cat_set.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTE on every sepol_cat_set_iter_t **cat_iter parameter below: see the
 * ownership contract documented in cat_set.h. In short, the callee always
 * allocates a new, caller-owned iterator that must be freed with
 * sepol_cat_set_iter_destroy() -- do not skip destroying it just because
 * the underlying category set turned out to be empty.
 *
 * NOTE on every `const char **`/`const uint32_t **` out-parameter
 * populated by an `_iter_next()` function below (e.g. fsuse's name,
 * genfscon's fstype/path, netifcon's name, ibendportcon's dev_name,
 * devicetreecon's path, nodecon6's addr/mask): the returned pointer is
 * borrowed from the policydb. It remains valid only until the next call
 * on the same iterator (`_iter_next()` or `_destroy()`) and must not be
 * freed by the caller.
 */

/* Initial SID iterator */

typedef struct sepol_isid_iter sepol_isid_iter_t;

extern int sepol_isid_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_isid_iter_t **iter);

extern void sepol_isid_iter_destroy(sepol_isid_iter_t *iter);

extern int sepol_isid_iter_next(sepol_handle_t *handle, sepol_isid_iter_t *iter,
				uint32_t *sid);

extern uint32_t sepol_isid_iter_get_context_user(const sepol_isid_iter_t *iter);
extern uint32_t sepol_isid_iter_get_context_role(const sepol_isid_iter_t *iter);
extern uint32_t sepol_isid_iter_get_context_type(const sepol_isid_iter_t *iter);
extern uint32_t
sepol_isid_iter_get_mls_range_low_sens(const sepol_isid_iter_t *iter);
extern uint32_t
sepol_isid_iter_get_mls_range_high_sens(const sepol_isid_iter_t *iter);
extern int
sepol_isid_iter_get_mls_range_low_cat(const sepol_isid_iter_t *iter,
				      sepol_cat_set_iter_t **cat_iter);
extern int
sepol_isid_iter_get_mls_range_high_cat(const sepol_isid_iter_t *iter,
				       sepol_cat_set_iter_t **cat_iter);

/* Returns the initial SID name.
 * The pointer is borrowed from the policydb; do not free. */
extern const char *sepol_isid_iter_get_name(const sepol_isid_iter_t *iter);

/* fs_use iterator */

typedef struct sepol_fsuse_iter sepol_fsuse_iter_t;

extern int sepol_fsuse_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   sepol_fsuse_iter_t **iter);

extern void sepol_fsuse_iter_destroy(sepol_fsuse_iter_t *iter);

extern int sepol_fsuse_iter_next(sepol_handle_t *handle,
				 sepol_fsuse_iter_t *iter, const char **name,
				 uint32_t *behavior);

extern uint32_t
sepol_fsuse_iter_get_context_user(const sepol_fsuse_iter_t *iter);
extern uint32_t
sepol_fsuse_iter_get_context_role(const sepol_fsuse_iter_t *iter);
extern uint32_t
sepol_fsuse_iter_get_context_type(const sepol_fsuse_iter_t *iter);
extern uint32_t
sepol_fsuse_iter_get_mls_range_low_sens(const sepol_fsuse_iter_t *iter);
extern uint32_t
sepol_fsuse_iter_get_mls_range_high_sens(const sepol_fsuse_iter_t *iter);
extern int
sepol_fsuse_iter_get_mls_range_low_cat(const sepol_fsuse_iter_t *iter,
				       sepol_cat_set_iter_t **cat_iter);
extern int
sepol_fsuse_iter_get_mls_range_high_cat(const sepol_fsuse_iter_t *iter,
					sepol_cat_set_iter_t **cat_iter);

/* genfscon iterator */

typedef struct sepol_genfscon_iter sepol_genfscon_iter_t;

extern int sepol_genfscon_iter_create(sepol_handle_t *handle,
				      const sepol_policydb_t *p,
				      sepol_genfscon_iter_t **iter);

extern void sepol_genfscon_iter_destroy(sepol_genfscon_iter_t *iter);

extern int sepol_genfscon_iter_next(sepol_handle_t *handle,
				    sepol_genfscon_iter_t *iter,
				    const char **fstype, const char **path,
				    uint32_t *sclass);

extern uint32_t
sepol_genfscon_iter_get_context_user(const sepol_genfscon_iter_t *iter);
extern uint32_t
sepol_genfscon_iter_get_context_role(const sepol_genfscon_iter_t *iter);
extern uint32_t
sepol_genfscon_iter_get_context_type(const sepol_genfscon_iter_t *iter);
extern uint32_t
sepol_genfscon_iter_get_mls_range_low_sens(const sepol_genfscon_iter_t *iter);
extern uint32_t
sepol_genfscon_iter_get_mls_range_high_sens(const sepol_genfscon_iter_t *iter);
extern int
sepol_genfscon_iter_get_mls_range_low_cat(const sepol_genfscon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);
extern int
sepol_genfscon_iter_get_mls_range_high_cat(const sepol_genfscon_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);

/* portcon iterator */

typedef struct sepol_portcon_iter sepol_portcon_iter_t;

extern int sepol_portcon_iter_create(sepol_handle_t *handle,
				     const sepol_policydb_t *p,
				     sepol_portcon_iter_t **iter);

extern void sepol_portcon_iter_destroy(sepol_portcon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; the other
 * out-parameters cannot be used to detect end-of-iteration since 0
 * is a valid port value. */
extern int sepol_portcon_iter_next(sepol_handle_t *handle,
				   sepol_portcon_iter_t *iter,
				   uint8_t *protocol, uint16_t *low_port,
				   uint16_t *high_port, int *has_next);

extern uint32_t
sepol_portcon_iter_get_context_user(const sepol_portcon_iter_t *iter);
extern uint32_t
sepol_portcon_iter_get_context_role(const sepol_portcon_iter_t *iter);
extern uint32_t
sepol_portcon_iter_get_context_type(const sepol_portcon_iter_t *iter);
extern uint32_t
sepol_portcon_iter_get_mls_range_low_sens(const sepol_portcon_iter_t *iter);
extern uint32_t
sepol_portcon_iter_get_mls_range_high_sens(const sepol_portcon_iter_t *iter);
extern int
sepol_portcon_iter_get_mls_range_low_cat(const sepol_portcon_iter_t *iter,
					 sepol_cat_set_iter_t **cat_iter);
extern int
sepol_portcon_iter_get_mls_range_high_cat(const sepol_portcon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);

/* netifcon iterator */

typedef struct sepol_netifcon_iter sepol_netifcon_iter_t;

extern int sepol_netifcon_iter_create(sepol_handle_t *handle,
				      const sepol_policydb_t *p,
				      sepol_netifcon_iter_t **iter);

extern void sepol_netifcon_iter_destroy(sepol_netifcon_iter_t *iter);

extern int sepol_netifcon_iter_next(sepol_handle_t *handle,
				    sepol_netifcon_iter_t *iter,
				    const char **name);

extern uint32_t
sepol_netifcon_iter_get_context_user(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_context_role(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_context_type(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_mls_range_low_sens(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_mls_range_high_sens(const sepol_netifcon_iter_t *iter);
extern int
sepol_netifcon_iter_get_mls_range_low_cat(const sepol_netifcon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);
extern int
sepol_netifcon_iter_get_mls_range_high_cat(const sepol_netifcon_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);

extern uint32_t
sepol_netifcon_iter_get_msg_context_user(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_msg_context_role(const sepol_netifcon_iter_t *iter);
extern uint32_t
sepol_netifcon_iter_get_msg_context_type(const sepol_netifcon_iter_t *iter);
extern uint32_t sepol_netifcon_iter_get_msg_mls_range_low_sens(
	const sepol_netifcon_iter_t *iter);
extern uint32_t sepol_netifcon_iter_get_msg_mls_range_high_sens(
	const sepol_netifcon_iter_t *iter);
extern int
sepol_netifcon_iter_get_msg_mls_range_low_cat(const sepol_netifcon_iter_t *iter,
					      sepol_cat_set_iter_t **cat_iter);
extern int sepol_netifcon_iter_get_msg_mls_range_high_cat(
	const sepol_netifcon_iter_t *iter, sepol_cat_set_iter_t **cat_iter);

/* nodecon IPv4 iterator */

typedef struct sepol_nodecon_iter sepol_nodecon_iter_t;

extern int sepol_nodecon_iter_create(sepol_handle_t *handle,
				     const sepol_policydb_t *p,
				     sepol_nodecon_iter_t **iter);

extern void sepol_nodecon_iter_destroy(sepol_nodecon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; addr/mask cannot
 * be used to detect end-of-iteration since 0.0.0.0/0.0.0.0 is a
 * valid nodecon entry. addr and mask are each a single IPv4 address
 * or mask in network byte order (big-endian), as they appear in the
 * policy source (e.g. "nodecon 192.168.1.0 255.255.255.0 ..."). */
extern int sepol_nodecon_iter_next(sepol_handle_t *handle,
				   sepol_nodecon_iter_t *iter, uint32_t *addr,
				   uint32_t *mask, int *has_next);

extern uint32_t
sepol_nodecon_iter_get_context_user(const sepol_nodecon_iter_t *iter);
extern uint32_t
sepol_nodecon_iter_get_context_role(const sepol_nodecon_iter_t *iter);
extern uint32_t
sepol_nodecon_iter_get_context_type(const sepol_nodecon_iter_t *iter);
extern uint32_t
sepol_nodecon_iter_get_mls_range_low_sens(const sepol_nodecon_iter_t *iter);
extern uint32_t
sepol_nodecon_iter_get_mls_range_high_sens(const sepol_nodecon_iter_t *iter);
extern int
sepol_nodecon_iter_get_mls_range_low_cat(const sepol_nodecon_iter_t *iter,
					 sepol_cat_set_iter_t **cat_iter);
extern int
sepol_nodecon_iter_get_mls_range_high_cat(const sepol_nodecon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);

/* nodecon6 IPv6 iterator */

typedef struct sepol_nodecon6_iter sepol_nodecon6_iter_t;

extern int sepol_nodecon6_iter_create(sepol_handle_t *handle,
				      const sepol_policydb_t *p,
				      sepol_nodecon6_iter_t **iter);

extern void sepol_nodecon6_iter_destroy(sepol_nodecon6_iter_t *iter);

/* addr and mask are each set to point at a borrowed, 4-element array
 * of uint32_t (the 128-bit IPv6 address or mask split into four
 * 32-bit words, each in network byte order (big-endian)), matching
 * struct ocontext_t's u.node6.addr / u.node6.mask. The pointers are
 * valid only until the next call on this iterator. */
extern int sepol_nodecon6_iter_next(sepol_handle_t *handle,
				    sepol_nodecon6_iter_t *iter,
				    const uint32_t **addr,
				    const uint32_t **mask);

extern uint32_t
sepol_nodecon6_iter_get_context_user(const sepol_nodecon6_iter_t *iter);
extern uint32_t
sepol_nodecon6_iter_get_context_role(const sepol_nodecon6_iter_t *iter);
extern uint32_t
sepol_nodecon6_iter_get_context_type(const sepol_nodecon6_iter_t *iter);
extern uint32_t
sepol_nodecon6_iter_get_mls_range_low_sens(const sepol_nodecon6_iter_t *iter);
extern uint32_t
sepol_nodecon6_iter_get_mls_range_high_sens(const sepol_nodecon6_iter_t *iter);
extern int
sepol_nodecon6_iter_get_mls_range_low_cat(const sepol_nodecon6_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);
extern int
sepol_nodecon6_iter_get_mls_range_high_cat(const sepol_nodecon6_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);

/* ibpkeycon iterator */

typedef struct sepol_ibpkeycon_iter sepol_ibpkeycon_iter_t;

extern int sepol_ibpkeycon_iter_create(sepol_handle_t *handle,
				       const sepol_policydb_t *p,
				       sepol_ibpkeycon_iter_t **iter);

extern void sepol_ibpkeycon_iter_destroy(sepol_ibpkeycon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; the other
 * out-parameters cannot be used to detect end-of-iteration since 0
 * is a valid pkey value. */
extern int sepol_ibpkeycon_iter_next(sepol_handle_t *handle,
				     sepol_ibpkeycon_iter_t *iter,
				     uint64_t *subnet_prefix,
				     uint16_t *low_pkey, uint16_t *high_pkey,
				     int *has_next);

extern uint32_t
sepol_ibpkeycon_iter_get_context_user(const sepol_ibpkeycon_iter_t *iter);
extern uint32_t
sepol_ibpkeycon_iter_get_context_role(const sepol_ibpkeycon_iter_t *iter);
extern uint32_t
sepol_ibpkeycon_iter_get_context_type(const sepol_ibpkeycon_iter_t *iter);
extern uint32_t
sepol_ibpkeycon_iter_get_mls_range_low_sens(const sepol_ibpkeycon_iter_t *iter);
extern uint32_t sepol_ibpkeycon_iter_get_mls_range_high_sens(
	const sepol_ibpkeycon_iter_t *iter);
extern int
sepol_ibpkeycon_iter_get_mls_range_low_cat(const sepol_ibpkeycon_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);
extern int
sepol_ibpkeycon_iter_get_mls_range_high_cat(const sepol_ibpkeycon_iter_t *iter,
					    sepol_cat_set_iter_t **cat_iter);

/* ibendportcon iterator */

typedef struct sepol_ibendportcon_iter sepol_ibendportcon_iter_t;

extern int sepol_ibendportcon_iter_create(sepol_handle_t *handle,
					  const sepol_policydb_t *p,
					  sepol_ibendportcon_iter_t **iter);

extern void sepol_ibendportcon_iter_destroy(sepol_ibendportcon_iter_t *iter);

extern int sepol_ibendportcon_iter_next(sepol_handle_t *handle,
					sepol_ibendportcon_iter_t *iter,
					const char **dev_name, uint8_t *port);

extern uint32_t
sepol_ibendportcon_iter_get_context_user(const sepol_ibendportcon_iter_t *iter);
extern uint32_t
sepol_ibendportcon_iter_get_context_role(const sepol_ibendportcon_iter_t *iter);
extern uint32_t
sepol_ibendportcon_iter_get_context_type(const sepol_ibendportcon_iter_t *iter);
extern uint32_t sepol_ibendportcon_iter_get_mls_range_low_sens(
	const sepol_ibendportcon_iter_t *iter);
extern uint32_t sepol_ibendportcon_iter_get_mls_range_high_sens(
	const sepol_ibendportcon_iter_t *iter);
extern int sepol_ibendportcon_iter_get_mls_range_low_cat(
	const sepol_ibendportcon_iter_t *iter, sepol_cat_set_iter_t **cat_iter);
extern int sepol_ibendportcon_iter_get_mls_range_high_cat(
	const sepol_ibendportcon_iter_t *iter, sepol_cat_set_iter_t **cat_iter);

/* Xen pirqcon iterator */

typedef struct sepol_pirqcon_iter sepol_pirqcon_iter_t;

extern int sepol_pirqcon_iter_create(sepol_handle_t *handle,
				     const sepol_policydb_t *p,
				     sepol_pirqcon_iter_t **iter);

extern void sepol_pirqcon_iter_destroy(sepol_pirqcon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; irq cannot be
 * used to detect end-of-iteration since 0 is a valid IRQ value. */
extern int sepol_pirqcon_iter_next(sepol_handle_t *handle,
				   sepol_pirqcon_iter_t *iter, uint32_t *irq,
				   int *has_next);

extern uint32_t
sepol_pirqcon_iter_get_context_user(const sepol_pirqcon_iter_t *iter);
extern uint32_t
sepol_pirqcon_iter_get_context_role(const sepol_pirqcon_iter_t *iter);
extern uint32_t
sepol_pirqcon_iter_get_context_type(const sepol_pirqcon_iter_t *iter);
extern uint32_t
sepol_pirqcon_iter_get_mls_range_low_sens(const sepol_pirqcon_iter_t *iter);
extern uint32_t
sepol_pirqcon_iter_get_mls_range_high_sens(const sepol_pirqcon_iter_t *iter);
extern int
sepol_pirqcon_iter_get_mls_range_low_cat(const sepol_pirqcon_iter_t *iter,
					 sepol_cat_set_iter_t **cat_iter);
extern int
sepol_pirqcon_iter_get_mls_range_high_cat(const sepol_pirqcon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);

/* Xen iomemcon iterator */

typedef struct sepol_iomemcon_iter sepol_iomemcon_iter_t;

extern int sepol_iomemcon_iter_create(sepol_handle_t *handle,
				      const sepol_policydb_t *p,
				      sepol_iomemcon_iter_t **iter);

extern void sepol_iomemcon_iter_destroy(sepol_iomemcon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; low_iomem/
 * high_iomem cannot be used to detect end-of-iteration since 0 is a
 * valid address value. */
extern int sepol_iomemcon_iter_next(sepol_handle_t *handle,
				    sepol_iomemcon_iter_t *iter,
				    uint64_t *low_iomem, uint64_t *high_iomem,
				    int *has_next);

extern uint32_t
sepol_iomemcon_iter_get_context_user(const sepol_iomemcon_iter_t *iter);
extern uint32_t
sepol_iomemcon_iter_get_context_role(const sepol_iomemcon_iter_t *iter);
extern uint32_t
sepol_iomemcon_iter_get_context_type(const sepol_iomemcon_iter_t *iter);
extern uint32_t
sepol_iomemcon_iter_get_mls_range_low_sens(const sepol_iomemcon_iter_t *iter);
extern uint32_t
sepol_iomemcon_iter_get_mls_range_high_sens(const sepol_iomemcon_iter_t *iter);
extern int
sepol_iomemcon_iter_get_mls_range_low_cat(const sepol_iomemcon_iter_t *iter,
					  sepol_cat_set_iter_t **cat_iter);
extern int
sepol_iomemcon_iter_get_mls_range_high_cat(const sepol_iomemcon_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);

/* Xen ioportcon iterator */

typedef struct sepol_ioportcon_iter sepol_ioportcon_iter_t;

extern int sepol_ioportcon_iter_create(sepol_handle_t *handle,
				       const sepol_policydb_t *p,
				       sepol_ioportcon_iter_t **iter);

extern void sepol_ioportcon_iter_destroy(sepol_ioportcon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; low_ioport/
 * high_ioport cannot be used to detect end-of-iteration since 0 is
 * a valid address value. */
extern int sepol_ioportcon_iter_next(sepol_handle_t *handle,
				     sepol_ioportcon_iter_t *iter,
				     uint32_t *low_ioport,
				     uint32_t *high_ioport, int *has_next);

extern uint32_t
sepol_ioportcon_iter_get_context_user(const sepol_ioportcon_iter_t *iter);
extern uint32_t
sepol_ioportcon_iter_get_context_role(const sepol_ioportcon_iter_t *iter);
extern uint32_t
sepol_ioportcon_iter_get_context_type(const sepol_ioportcon_iter_t *iter);
extern uint32_t
sepol_ioportcon_iter_get_mls_range_low_sens(const sepol_ioportcon_iter_t *iter);
extern uint32_t sepol_ioportcon_iter_get_mls_range_high_sens(
	const sepol_ioportcon_iter_t *iter);
extern int
sepol_ioportcon_iter_get_mls_range_low_cat(const sepol_ioportcon_iter_t *iter,
					   sepol_cat_set_iter_t **cat_iter);
extern int
sepol_ioportcon_iter_get_mls_range_high_cat(const sepol_ioportcon_iter_t *iter,
					    sepol_cat_set_iter_t **cat_iter);

/* Xen pcidevicecon iterator */

typedef struct sepol_pcidevicecon_iter sepol_pcidevicecon_iter_t;

extern int sepol_pcidevicecon_iter_create(sepol_handle_t *handle,
					  const sepol_policydb_t *p,
					  sepol_pcidevicecon_iter_t **iter);

extern void sepol_pcidevicecon_iter_destroy(sepol_pcidevicecon_iter_t *iter);

/* has_next is set to 0 once iteration is exhausted; device cannot
 * be used to detect end-of-iteration since 0 is a valid device
 * value. */
extern int sepol_pcidevicecon_iter_next(sepol_handle_t *handle,
					sepol_pcidevicecon_iter_t *iter,
					uint32_t *device, int *has_next);

extern uint32_t
sepol_pcidevicecon_iter_get_context_user(const sepol_pcidevicecon_iter_t *iter);
extern uint32_t
sepol_pcidevicecon_iter_get_context_role(const sepol_pcidevicecon_iter_t *iter);
extern uint32_t
sepol_pcidevicecon_iter_get_context_type(const sepol_pcidevicecon_iter_t *iter);
extern uint32_t sepol_pcidevicecon_iter_get_mls_range_low_sens(
	const sepol_pcidevicecon_iter_t *iter);
extern uint32_t sepol_pcidevicecon_iter_get_mls_range_high_sens(
	const sepol_pcidevicecon_iter_t *iter);
extern int sepol_pcidevicecon_iter_get_mls_range_low_cat(
	const sepol_pcidevicecon_iter_t *iter, sepol_cat_set_iter_t **cat_iter);
extern int sepol_pcidevicecon_iter_get_mls_range_high_cat(
	const sepol_pcidevicecon_iter_t *iter, sepol_cat_set_iter_t **cat_iter);

/* Xen devicetreecon iterator */

typedef struct sepol_devicetreecon_iter sepol_devicetreecon_iter_t;

extern int sepol_devicetreecon_iter_create(sepol_handle_t *handle,
					   const sepol_policydb_t *p,
					   sepol_devicetreecon_iter_t **iter);

extern void sepol_devicetreecon_iter_destroy(sepol_devicetreecon_iter_t *iter);

extern int sepol_devicetreecon_iter_next(sepol_handle_t *handle,
					 sepol_devicetreecon_iter_t *iter,
					 const char **path);

extern uint32_t sepol_devicetreecon_iter_get_context_user(
	const sepol_devicetreecon_iter_t *iter);
extern uint32_t sepol_devicetreecon_iter_get_context_role(
	const sepol_devicetreecon_iter_t *iter);
extern uint32_t sepol_devicetreecon_iter_get_context_type(
	const sepol_devicetreecon_iter_t *iter);
extern uint32_t sepol_devicetreecon_iter_get_mls_range_low_sens(
	const sepol_devicetreecon_iter_t *iter);
extern uint32_t sepol_devicetreecon_iter_get_mls_range_high_sens(
	const sepol_devicetreecon_iter_t *iter);
extern int sepol_devicetreecon_iter_get_mls_range_low_cat(
	const sepol_devicetreecon_iter_t *iter,
	sepol_cat_set_iter_t **cat_iter);
extern int sepol_devicetreecon_iter_get_mls_range_high_cat(
	const sepol_devicetreecon_iter_t *iter,
	sepol_cat_set_iter_t **cat_iter);

#ifdef __cplusplus
}
#endif

#endif
